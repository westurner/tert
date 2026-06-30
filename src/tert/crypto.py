#!/usr/bin/env python3
"""
crypto.py - minimal, dependency-free Ed25519 + did:key primitives for tert.

This module implements just enough cryptography for DID-signed provenance:

    - Ed25519 keypair derivation, signing and verification (RFC 8032), using
      only the Python standard library (``hashlib``).
    - ``did:key`` encoding for Ed25519 public keys (multicodec ``0xed01`` +
      base58btc multibase, which always yields a ``z6Mk...`` identifier).

The Ed25519 implementation is the public-domain reference implementation by the
Ed25519 authors (Bernstein et al.). It is intentionally simple rather than fast:
it signs small provenance documents, not bulk data.

Interoperability is verified against OpenSSL (Python tests) and against this same
module's output (Rust ``tert::crypto`` interop tests), so signatures produced
here verify with any conformant Ed25519 implementation.
"""

import hashlib
from typing import List, Tuple

__all__ = [
    "ed25519_publickey",
    "ed25519_sign",
    "ed25519_verify",
    "base58btc_encode",
    "multibase_base58btc",
    "did_key_from_pubkey",
    "pubkey_from_did_key",
    "SEED_BYTES",
    "PUBKEY_BYTES",
    "SIGNATURE_BYTES",
]

SEED_BYTES = 32
PUBKEY_BYTES = 32
SIGNATURE_BYTES = 64

# --- Ed25519 reference implementation (RFC 8032) ---------------------------

_b = 256
_q = 2**255 - 19
_l = 2**252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, _q - 2, _q)


_d = -121665 * _inv(121666) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = 4 * _inv(5) % _q
_Bx = _xrecover(_By)
_B = [_Bx % _q, _By % _q]


def _edwards(P: List[int], Q: List[int]) -> List[int]:
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2) % _q
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2) % _q
    return [x3 % _q, y3 % _q]


def _scalarmult(P: List[int], e: int) -> List[int]:
    if e == 0:
        return [0, 1]
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q


def _encodeint(y: int) -> bytes:
    return y.to_bytes(_b // 8, "little")


def _encodepoint(P: List[int]) -> bytes:
    x, y = P
    val = y | ((x & 1) << (_b - 1))
    return val.to_bytes(_b // 8, "little")


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _Hint(m: bytes) -> int:
    h = _H(m)
    return sum(2**i * _bit(h, i) for i in range(2 * _b))


def _secret_scalar(seed: bytes) -> int:
    h = _H(seed)
    return 2 ** (_b - 2) + sum(2**i * _bit(h, i) for i in range(3, _b - 2))


def ed25519_publickey(seed: bytes) -> bytes:
    """Derive the 32-byte Ed25519 public key from a 32-byte seed."""
    if len(seed) != SEED_BYTES:
        raise ValueError("seed must be %d bytes" % SEED_BYTES)
    a = _secret_scalar(seed)
    A = _scalarmult(_B, a)
    return _encodepoint(A)


def ed25519_sign(seed: bytes, msg: bytes, pubkey: bytes = None) -> bytes:
    """Sign *msg* with the Ed25519 key derived from *seed* (64-byte signature)."""
    if len(seed) != SEED_BYTES:
        raise ValueError("seed must be %d bytes" % SEED_BYTES)
    if pubkey is None:
        pubkey = ed25519_publickey(seed)
    h = _H(seed)
    a = _secret_scalar(seed)
    r = _Hint(h[_b // 8 : _b // 4] + msg)
    R = _scalarmult(_B, r)
    S = (r + _Hint(_encodepoint(R) + pubkey + msg) * a) % _l
    return _encodepoint(R) + _encodeint(S)


def _isoncurve(P: List[int]) -> bool:
    x, y = P
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _q == 0


def _decodeint(s: bytes) -> int:
    return int.from_bytes(s, "little")


def _decodepoint(s: bytes) -> List[int]:
    y = int.from_bytes(s, "little") & ((1 << (_b - 1)) - 1)
    x = _xrecover(y)
    if (x & 1) != _bit(s, _b - 1):
        x = _q - x
    P = [x, y]
    if not _isoncurve(P):
        raise ValueError("decoding point that is not on curve")
    return P


def ed25519_verify(pubkey: bytes, msg: bytes, sig: bytes) -> bool:
    """Verify a 64-byte Ed25519 signature. Returns True iff valid."""
    if len(sig) != SIGNATURE_BYTES or len(pubkey) != PUBKEY_BYTES:
        return False
    try:
        R = _decodepoint(sig[: _b // 8])
        A = _decodepoint(pubkey)
        S = _decodeint(sig[_b // 8 : _b // 4])
        h = _Hint(sig[: _b // 8] + pubkey + msg)
        return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, h))
    except (ValueError, IndexError):
        return False


# --- base58btc / multibase / did:key ---------------------------------------

_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Multicodec prefix for an Ed25519 public key (unsigned varint 0xed01).
_ED25519_MULTICODEC = b"\xed\x01"


def base58btc_encode(data: bytes) -> str:
    """Encode bytes as base58btc (Bitcoin alphabet), without a multibase prefix."""
    n = int.from_bytes(data, "big")
    out = bytearray()
    while n > 0:
        n, rem = divmod(n, 58)
        out.append(_B58_ALPHABET[rem])
    for byte in data:
        if byte == 0:
            out.append(_B58_ALPHABET[0])
        else:
            break
    out.reverse()
    return out.decode("ascii")


def base58btc_decode(text: str) -> bytes:
    """Decode a base58btc string (no multibase prefix) back to bytes."""
    n = 0
    for char in text:
        idx = _B58_ALPHABET.find(char.encode("ascii"))
        if idx < 0:
            raise ValueError("invalid base58 character: %r" % char)
        n = n * 58 + idx
    full = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = 0
    for char in text:
        if char == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + full


def multibase_base58btc(data: bytes) -> str:
    """Encode bytes as multibase base58btc (``z`` prefix)."""
    return "z" + base58btc_encode(data)


def did_key_from_pubkey(pubkey: bytes) -> str:
    """Return the ``did:key`` identifier for an Ed25519 public key."""
    if len(pubkey) != PUBKEY_BYTES:
        raise ValueError("pubkey must be %d bytes" % PUBKEY_BYTES)
    return "did:key:" + multibase_base58btc(_ED25519_MULTICODEC + pubkey)


def pubkey_from_did_key(did: str) -> bytes:
    """Extract the Ed25519 public key from a ``did:key`` identifier."""
    if not did.startswith("did:key:z"):
        raise ValueError("not an Ed25519 did:key: %r" % did)
    raw = base58btc_decode(did[len("did:key:z") :])
    if not raw.startswith(_ED25519_MULTICODEC):
        raise ValueError("did:key is not Ed25519 (bad multicodec)")
    pub = raw[len(_ED25519_MULTICODEC) :]
    if len(pub) != PUBKEY_BYTES:
        raise ValueError("did:key public key has wrong length")
    return pub
