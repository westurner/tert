#!/usr/bin/env python3
"""
pq.py - pure-Python post-quantum and classical primitives backing two Data
Integrity cryptosuites (the Python counterpart of ``tert::pq``).

  * ``mldsa-87-p256``     - a hybrid (composite) signature: ML-DSA-87 (FIPS 204,
    lattice post-quantum) **and** ECDSA-P256. A verifier must accept *both*
    component signatures, so the construction stays secure as long as either
    algorithm is unbroken.

  * ``merkle-tree-certs`` - Merkle Tree Certificates, the design Cloudflare and
    Let's Encrypt are deploying for a post-quantum WebPKI
    (draft-davidben-tls-merkle-tree-certs). Certificates are issued in
    *batches*: the issuer arranges per-credential assertions into a Merkle tree
    and signs only the tree head; each credential carries a signatureless
    *inclusion proof* (the sibling hashes from its leaf to the head). A verifier
    recomputes the tree head from the assertion + proof and checks the single
    batch signature over that head.

Everything here is implemented with the Python standard library only
(``hashlib`` provides SHA-256 and SHAKE-128/256, ``hmac`` provides RFC 6979).
The binary wire formats (hybrid blob, Merkle inclusion proof, tree-head signing
input) are byte-for-byte identical to the Rust implementation in ``src/pq.rs``,
so signatures interoperate across the two languages.
"""

import hmac
import hashlib
import struct
from typing import List, Optional, Tuple

# ===========================================================================
# little binary writer / reader (mirrors src/pq.rs)
# ===========================================================================


def put_u16(out: bytearray, v: int) -> None:
    out.extend(struct.pack(">H", v & 0xFFFF))


def put_bytes(out: bytearray, b: bytes) -> None:
    put_u16(out, len(b))
    out.extend(b)


class Reader:
    __slots__ = ("buf", "pos")

    def __init__(self, buf: bytes) -> None:
        self.buf = buf
        self.pos = 0

    def take(self, n: int) -> Optional[bytes]:
        if self.pos + n > len(self.buf):
            return None
        s = self.buf[self.pos : self.pos + n]
        self.pos += n
        return s

    def u16(self) -> Optional[int]:
        b = self.take(2)
        if b is None:
            return None
        return struct.unpack(">H", b)[0]

    def u32(self) -> Optional[int]:
        b = self.take(4)
        if b is None:
            return None
        return struct.unpack(">I", b)[0]

    def u64(self) -> Optional[int]:
        b = self.take(8)
        if b is None:
            return None
        return struct.unpack(">Q", b)[0]

    def bytes(self) -> Optional[bytes]:
        n = self.u16()
        if n is None:
            return None
        return self.take(n)


# ===========================================================================
# SHAKE extendable-output reader
# ===========================================================================


class Xof:
    """Streaming reader over a SHAKE-128/256 squeeze.

    ``hashlib`` has no incremental squeeze, so each ``read`` re-derives the
    needed prefix. Inputs here are at most a few KB, so this is fine.
    """

    __slots__ = ("_data", "_bits", "_off")

    def __init__(self, data: bytes, bits: int) -> None:
        self._data = bytes(data)
        self._bits = bits
        self._off = 0

    def read(self, k: int) -> bytes:
        h = hashlib.shake_128() if self._bits == 128 else hashlib.shake_256()
        h.update(self._data)
        out = h.digest(self._off + k)[self._off :]
        self._off += k
        return out


def shake256(data: bytes, length: int) -> bytes:
    h = hashlib.shake_256()
    h.update(data)
    return h.digest(length)


# ===========================================================================
# ML-DSA-87 (FIPS 204)
# ===========================================================================

Q = 8380417
N = 256
D = 13
ROOT_OF_UNITY = 1753

# ML-DSA-87 parameter set.
ML_TAU = 60
ML_GAMMA1 = 1 << 19
ML_GAMMA2 = (Q - 1) // 32
ML_K = 8
ML_L = 7
ML_ETA = 2
ML_OMEGA = 75
ML_LAMBDA = 256  # collision strength in bits
ML_C_TILDE_BYTES = ML_LAMBDA // 4  # 64
ML_BETA = ML_TAU * ML_ETA  # 120

MLDSA_PK_LEN = 2592
MLDSA_SK_LEN = 4896
MLDSA_SIG_LEN = 4627


def _bitrev8(x: int) -> int:
    return int("{:08b}".format(x)[::-1], 2)


_ZETAS = [pow(ROOT_OF_UNITY, _bitrev8(i), Q) for i in range(N)]
_F_INV = pow(N, -1, Q)  # 256^-1 mod q


def _ntt(a: List[int]) -> List[int]:
    a = a[:]
    k = 0
    length = 128
    while length >= 1:
        start = 0
        while start < N:
            k += 1
            zeta = _ZETAS[k]
            for j in range(start, start + length):
                t = (zeta * a[j + length]) % Q
                a[j + length] = (a[j] - t) % Q
                a[j] = (a[j] + t) % Q
            start += 2 * length
        length //= 2
    return a


def _intt(a: List[int]) -> List[int]:
    a = a[:]
    k = N
    length = 1
    while length < N:
        start = 0
        while start < N:
            k -= 1
            zeta = (-_ZETAS[k]) % Q
            for j in range(start, start + length):
                t = a[j]
                a[j] = (t + a[j + length]) % Q
                a[j + length] = (zeta * ((t - a[j + length]) % Q)) % Q
            start += 2 * length
        length *= 2
    return [(x * _F_INV) % Q for x in a]


def _poly_add(a: List[int], b: List[int]) -> List[int]:
    return [(x + y) % Q for x, y in zip(a, b)]


def _poly_sub(a: List[int], b: List[int]) -> List[int]:
    return [(x - y) % Q for x, y in zip(a, b)]


def _poly_pointwise(a: List[int], b: List[int]) -> List[int]:
    return [(x * y) % Q for x, y in zip(a, b)]


def _centered(x: int) -> int:
    """Map a coefficient in [0, q) to its signed representative in (-q/2, q/2]."""
    return x - Q if x > Q // 2 else x


def _inf_norm(poly: List[int]) -> int:
    return max(abs(_centered(x)) for x in poly)


# --- bit packing -----------------------------------------------------------


def _bitlen(x: int) -> int:
    return x.bit_length()


def _simple_bit_pack(w: List[int], b: int) -> bytes:
    bl = _bitlen(b)
    bits = 0
    acc = 0
    out = bytearray()
    for coeff in w:
        acc |= (coeff & ((1 << bl) - 1)) << bits
        bits += bl
        while bits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            bits -= 8
    if bits:
        out.append(acc & 0xFF)
    return bytes(out)


def _bit_pack(w: List[int], a: int, b: int) -> bytes:
    # coefficients are in [-a, b]; store (b - coeff)
    return _simple_bit_pack([(b - _centered(c)) for c in w], a + b)


def _simple_bit_unpack(v: bytes, b: int) -> List[int]:
    bl = _bitlen(b)
    mask = (1 << bl) - 1
    coeffs = []
    acc = 0
    bits = 0
    pos = 0
    for _ in range(N):
        while bits < bl:
            acc |= v[pos] << bits
            pos += 1
            bits += 8
        coeffs.append(acc & mask)
        acc >>= bl
        bits -= bl
    return coeffs


def _bit_unpack(v: bytes, a: int, b: int) -> List[int]:
    raw = _simple_bit_unpack(v, a + b)
    return [(b - r) % Q for r in raw]


# --- sampling --------------------------------------------------------------


def _sample_ntt(rho_prime: bytes) -> List[int]:
    xof = Xof(rho_prime, 128)
    coeffs: List[int] = []
    while len(coeffs) < N:
        b = xof.read(3)
        d = b[0] + (b[1] << 8) + ((b[2] & 0x7F) << 16)
        if d < Q:
            coeffs.append(d)
    return coeffs


def _coef_from_halfbyte(b: int) -> Optional[int]:
    # ML-DSA-87 uses eta = 2
    if b < 15:
        return 2 - (b % 5)
    return None


def _sample_bounded(rho_prime: bytes) -> List[int]:
    xof = Xof(rho_prime, 256)
    coeffs: List[int] = []
    while len(coeffs) < N:
        z = xof.read(1)[0]
        z0 = _coef_from_halfbyte(z & 0x0F)
        if z0 is not None:
            coeffs.append(z0 % Q)
            if len(coeffs) == N:
                break
        z1 = _coef_from_halfbyte(z >> 4)
        if z1 is not None:
            coeffs.append(z1 % Q)
    return coeffs


def _sample_in_ball(c_tilde: bytes) -> List[int]:
    xof = Xof(c_tilde, 256)
    sign_bytes = xof.read(8)
    sign_bits = int.from_bytes(sign_bytes, "little")
    c = [0] * N
    for i in range(N - ML_TAU, N):
        while True:
            j = xof.read(1)[0]
            if j <= i:
                break
        c[i] = c[j]
        bit = (sign_bits >> (i - (N - ML_TAU))) & 1
        c[j] = (Q - 1) if bit else 1
    return c


def _expand_a(rho: bytes) -> List[List[List[int]]]:
    a_hat = []
    for r in range(ML_K):
        row = []
        for s in range(ML_L):
            rho_prime = rho + bytes([s, r])
            row.append(_sample_ntt(rho_prime))
        a_hat.append(row)
    return a_hat


def _expand_s(rho_prime: bytes) -> Tuple[List[List[int]], List[List[int]]]:
    s1 = []
    for i in range(ML_L):
        s1.append(_sample_bounded(rho_prime + struct.pack("<H", i)))
    s2 = []
    for i in range(ML_K):
        s2.append(_sample_bounded(rho_prime + struct.pack("<H", i + ML_L)))
    return s1, s2


def _expand_mask(rho_pp: bytes, kappa: int) -> List[List[int]]:
    y = []
    c = 1 + _bitlen(ML_GAMMA1 - 1)  # 20
    blen = 32 * c
    for r in range(ML_L):
        v = Xof(rho_pp + struct.pack("<H", kappa + r), 256).read(blen)
        y.append(_bit_unpack(v, ML_GAMMA1 - 1, ML_GAMMA1))
    return y


# --- rounding --------------------------------------------------------------


def _power2round(r: int) -> Tuple[int, int]:
    r = r % Q
    r0 = r % (1 << D)
    if r0 > (1 << (D - 1)):
        r0 -= 1 << D
    return (r - r0) >> D, r0


def _decompose(r: int) -> Tuple[int, int]:
    alpha = 2 * ML_GAMMA2
    r = r % Q
    r0 = r % alpha
    if r0 > alpha // 2:
        r0 -= alpha
    if r - r0 == Q - 1:
        return 0, r0 - 1
    return (r - r0) // alpha, r0


def _high_bits(r: int) -> int:
    return _decompose(r)[0]


def _low_bits(r: int) -> int:
    return _decompose(r)[1]


def _make_hint(z: int, r: int) -> int:
    return 1 if _high_bits(r) != _high_bits((r + z) % Q) else 0


def _use_hint(h: int, r: int) -> int:
    m = (Q - 1) // (2 * ML_GAMMA2)
    r1, r0 = _decompose(r)
    if h == 1:
        return (r1 + 1) % m if r0 > 0 else (r1 - 1) % m
    return r1


def _w1_encode(w1: List[List[int]]) -> bytes:
    b = (Q - 1) // (2 * ML_GAMMA2) - 1
    out = bytearray()
    for poly in w1:
        out.extend(_simple_bit_pack(poly, b))
    return bytes(out)


# --- key / signature encoding ---------------------------------------------


def _pk_encode(rho: bytes, t1: List[List[int]]) -> bytes:
    out = bytearray(rho)
    for poly in t1:
        out.extend(_simple_bit_pack(poly, (1 << (_bitlen(Q - 1) - D)) - 1))
    return bytes(out)


def _pk_decode(pk: bytes) -> Tuple[bytes, List[List[int]]]:
    rho = pk[:32]
    b = (1 << (_bitlen(Q - 1) - D)) - 1
    bl = _bitlen(b)
    stride = 32 * bl
    t1 = []
    off = 32
    for _ in range(ML_K):
        t1.append(_simple_bit_unpack(pk[off : off + stride], b))
        off += stride
    return rho, t1


def _sk_encode(rho, key, tr, s1, s2, t0) -> bytes:
    out = bytearray(rho)
    out.extend(key)
    out.extend(tr)
    for poly in s1:
        out.extend(_bit_pack(poly, ML_ETA, ML_ETA))
    for poly in s2:
        out.extend(_bit_pack(poly, ML_ETA, ML_ETA))
    for poly in t0:
        out.extend(_bit_pack(poly, (1 << (D - 1)) - 1, 1 << (D - 1)))
    return bytes(out)


def _sk_decode(sk: bytes):
    rho = sk[:32]
    key = sk[32:64]
    tr = sk[64:128]
    off = 128
    eta_bl = _bitlen(2 * ML_ETA)
    eta_stride = 32 * eta_bl
    s1 = []
    for _ in range(ML_L):
        s1.append(_bit_unpack(sk[off : off + eta_stride], ML_ETA, ML_ETA))
        off += eta_stride
    s2 = []
    for _ in range(ML_K):
        s2.append(_bit_unpack(sk[off : off + eta_stride], ML_ETA, ML_ETA))
        off += eta_stride
    t0_bl = _bitlen((1 << (D - 1)) - 1 + (1 << (D - 1)))
    t0_stride = 32 * t0_bl
    t0 = []
    for _ in range(ML_K):
        t0.append(_bit_unpack(sk[off : off + t0_stride], (1 << (D - 1)) - 1, 1 << (D - 1)))
        off += t0_stride
    return rho, key, tr, s1, s2, t0


def _hint_bit_pack(h: List[List[int]]) -> bytes:
    y = bytearray(ML_OMEGA + ML_K)
    index = 0
    for i in range(ML_K):
        for j in range(N):
            if h[i][j] != 0:
                y[index] = j
                index += 1
        y[ML_OMEGA + i] = index
    return bytes(y)


def _hint_bit_unpack(y: bytes) -> Optional[List[List[int]]]:
    h = [[0] * N for _ in range(ML_K)]
    index = 0
    for i in range(ML_K):
        end = y[ML_OMEGA + i]
        if end < index or end > ML_OMEGA:
            return None
        first = index
        while index < end:
            if index > first and y[index - 1] >= y[index]:
                return None
            h[i][y[index]] = 1
            index += 1
    for i in range(index, ML_OMEGA):
        if y[i] != 0:
            return None
    return h


def _sig_encode(c_tilde: bytes, z: List[List[int]], h: List[List[int]]) -> bytes:
    out = bytearray(c_tilde)
    for poly in z:
        out.extend(_bit_pack(poly, ML_GAMMA1 - 1, ML_GAMMA1))
    out.extend(_hint_bit_pack(h))
    return bytes(out)


def _sig_decode(sig: bytes):
    c_tilde = sig[:ML_C_TILDE_BYTES]
    off = ML_C_TILDE_BYTES
    z_bl = _bitlen((ML_GAMMA1 - 1) + ML_GAMMA1)
    z_stride = 32 * z_bl
    z = []
    for _ in range(ML_L):
        z.append(_bit_unpack(sig[off : off + z_stride], ML_GAMMA1 - 1, ML_GAMMA1))
        off += z_stride
    h = _hint_bit_unpack(sig[off : off + ML_OMEGA + ML_K])
    return c_tilde, z, h


# --- keygen / sign / verify ------------------------------------------------


def mldsa87_keygen(xi: bytes) -> Tuple[bytes, bytes]:
    """FIPS 204 ML-DSA.KeyGen from a 32-byte seed (deterministic)."""
    seed = shake256(xi + bytes([ML_K, ML_L]), 128)
    rho, rho_prime, key = seed[:32], seed[32:96], seed[96:128]
    a_hat = _expand_a(rho)
    s1, s2 = _expand_s(rho_prime)
    s1_hat = [_ntt(p) for p in s1]
    # t = A * s1 + s2
    t = []
    for r in range(ML_K):
        acc = [0] * N
        for s in range(ML_L):
            acc = _poly_add(acc, _poly_pointwise(a_hat[r][s], s1_hat[s]))
        t.append(_poly_add(_intt(acc), s2[r]))
    t1 = []
    t0 = []
    for poly in t:
        hi = []
        lo = []
        for coeff in poly:
            a1, a0 = _power2round(coeff)
            hi.append(a1)
            lo.append(a0 % Q)
        t1.append(hi)
        t0.append(lo)
    pk = _pk_encode(rho, t1)
    tr = shake256(pk, 64)
    sk = _sk_encode(rho, key, tr, s1, s2, t0)
    return pk, sk


def _format_message(message: bytes, ctx: bytes) -> bytes:
    # FIPS 204 Sign/Verify wrapper: M' = 0x00 || len(ctx) || ctx || M
    if len(ctx) > 255:
        raise ValueError("ctx too long")
    return bytes([0, len(ctx)]) + ctx + message


def mldsa87_sign(sk: bytes, message: bytes, ctx: bytes = b"") -> bytes:
    """Deterministic ML-DSA.Sign (rnd = 0) so signatures are reproducible."""
    rho, key, tr, s1, s2, t0 = _sk_decode(sk)
    mp = _format_message(message, ctx)
    a_hat = _expand_a(rho)
    s1_hat = [_ntt(p) for p in s1]
    s2_hat = [_ntt(p) for p in s2]
    t0_hat = [_ntt(p) for p in t0]
    mu = shake256(tr + mp, 64)
    rnd = bytes(32)
    rho_pp = shake256(key + rnd + mu, 64)
    kappa = 0
    while True:
        y = _expand_mask(rho_pp, kappa)
        y_hat = [_ntt(p) for p in y]
        w = []
        for r in range(ML_K):
            acc = [0] * N
            for s in range(ML_L):
                acc = _poly_add(acc, _poly_pointwise(a_hat[r][s], y_hat[s]))
            w.append(_intt(acc))
        w1 = [[_high_bits(c) for c in poly] for poly in w]
        c_tilde = shake256(mu + _w1_encode(w1), ML_C_TILDE_BYTES)
        c = _sample_in_ball(c_tilde)
        c_hat = _ntt(c)
        cs1 = [_intt(_poly_pointwise(c_hat, sh)) for sh in s1_hat]
        cs2 = [_intt(_poly_pointwise(c_hat, sh)) for sh in s2_hat]
        z = [_poly_add(y[i], cs1[i]) for i in range(ML_L)]
        kappa += ML_L
        if max(_inf_norm(p) for p in z) >= ML_GAMMA1 - ML_BETA:
            continue
        w_minus_cs2 = [_poly_sub(w[i], cs2[i]) for i in range(ML_K)]
        if max(_inf_norm([_low_bits(c2) for c2 in poly]) for poly in w_minus_cs2) >= ML_GAMMA2 - ML_BETA:
            continue
        ct0 = [_intt(_poly_pointwise(c_hat, th)) for th in t0_hat]
        if max(_inf_norm(p) for p in ct0) >= ML_GAMMA2:
            continue
        h = []
        ones = 0
        for i in range(ML_K):
            row = []
            for j in range(N):
                neg_ct0 = (-ct0[i][j]) % Q
                r_val = (w[i][j] - cs2[i][j] + ct0[i][j]) % Q
                bit = _make_hint(neg_ct0, r_val)
                row.append(bit)
                ones += bit
            h.append(row)
        if ones > ML_OMEGA:
            continue
        return _sig_encode(c_tilde, z, h)


def mldsa87_verify(pk: bytes, message: bytes, sig: bytes, ctx: bytes = b"") -> bool:
    if len(pk) != MLDSA_PK_LEN or len(sig) != MLDSA_SIG_LEN:
        return False
    rho, t1 = _pk_decode(pk)
    c_tilde, z, h = _sig_decode(sig)
    if h is None:
        return False
    if max(_inf_norm(p) for p in z) >= ML_GAMMA1 - ML_BETA:
        return False
    a_hat = _expand_a(rho)
    tr = shake256(pk, 64)
    mp = _format_message(message, ctx)
    mu = shake256(tr + mp, 64)
    c = _sample_in_ball(c_tilde)
    c_hat = _ntt(c)
    z_hat = [_ntt(p) for p in z]
    t1_hat = [_ntt([(coeff << D) % Q for coeff in poly]) for poly in t1]
    w_approx = []
    for r in range(ML_K):
        acc = [0] * N
        for s in range(ML_L):
            acc = _poly_add(acc, _poly_pointwise(a_hat[r][s], z_hat[s]))
        acc = _poly_sub(acc, _poly_pointwise(c_hat, t1_hat[r]))
        w_approx.append(_intt(acc))
    w1 = [[_use_hint(h[i][j], w_approx[i][j]) for j in range(N)] for i in range(ML_K)]
    c_tilde2 = shake256(mu + _w1_encode(w1), ML_C_TILDE_BYTES)
    return c_tilde == c_tilde2


# ===========================================================================
# ECDSA-P256 (NIST P-256 / secp256r1) with RFC 6979 deterministic nonces
# ===========================================================================

_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = _P256_P - 3
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def _p256_inv(x: int, m: int) -> int:
    return pow(x % m, -1, m)


def _p256_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % _P256_P == 0:
        return None
    if x1 == x2 and y1 == y2:
        lam = (3 * x1 * x1 + _P256_A) * _p256_inv(2 * y1, _P256_P) % _P256_P
    else:
        lam = (y2 - y1) * _p256_inv((x2 - x1) % _P256_P, _P256_P) % _P256_P
    x3 = (lam * lam - x1 - x2) % _P256_P
    y3 = (lam * (x1 - x3) - y1) % _P256_P
    return (x3, y3)


def _p256_mul(k: int, point) -> Optional[Tuple[int, int]]:
    result = None
    addend = point
    while k:
        if k & 1:
            result = _p256_add(result, addend)
        addend = _p256_add(addend, addend)
        k >>= 1
    return result


_P256_G = (_P256_GX, _P256_GY)


def p256_scalar_from_seed(seed: bytes) -> int:
    for ctr in range(16):
        h = hashlib.sha256(b"tert-mldsa-87-p256/p256" + seed + bytes([ctr])).digest()
        d = int.from_bytes(h, "big") % _P256_N
        if d != 0:
            return d
    raise ValueError("failed to derive P-256 key")


def p256_public_compressed(d: int) -> bytes:
    point = _p256_mul(d, _P256_G)
    x, y = point
    prefix = 0x02 | (y & 1)
    return bytes([prefix]) + x.to_bytes(32, "big")


def _p256_decompress(data: bytes) -> Optional[Tuple[int, int]]:
    if len(data) != 33 or data[0] not in (0x02, 0x03):
        return None
    x = int.from_bytes(data[1:], "big")
    if x >= _P256_P:
        return None
    rhs = (x * x * x + _P256_A * x + _P256_B) % _P256_P
    y = pow(rhs, (_P256_P + 1) // 4, _P256_P)
    if (y * y) % _P256_P != rhs:
        return None
    if (y & 1) != (data[0] & 1):
        y = _P256_P - y
    return (x, y)


def _rfc6979_k(d: int, h1: bytes) -> int:
    qlen = _P256_N.bit_length()
    hlen = 32
    x = d.to_bytes(32, "big")
    # bits2octets(h1)
    z1 = int.from_bytes(h1, "big")
    z2 = z1 % _P256_N
    bo = z2.to_bytes(32, "big")
    v = b"\x01" * hlen
    k = b"\x00" * hlen
    k = hmac.new(k, v + b"\x00" + x + bo, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + bo, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        t = b""
        while len(t) * 8 < qlen:
            v = hmac.new(k, v, hashlib.sha256).digest()
            t += v
        kk = int.from_bytes(t[:hlen], "big")
        if 1 <= kk < _P256_N:
            return kk
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def p256_sign(d: int, message: bytes) -> bytes:
    """Deterministic ECDSA-P256 signature, returned as raw r||s (64 bytes),
    low-S normalized to match the Rust ``p256`` crate."""
    h = hashlib.sha256(message).digest()
    e = int.from_bytes(h, "big") % _P256_N
    while True:
        k = _rfc6979_k(d, h)
        point = _p256_mul(k, _P256_G)
        r = point[0] % _P256_N
        if r == 0:
            continue
        s = (_p256_inv(k, _P256_N) * (e + r * d)) % _P256_N
        if s == 0:
            continue
        if s > _P256_N // 2:  # low-S
            s = _P256_N - s
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def p256_verify(pub_compressed: bytes, message: bytes, sig: bytes) -> bool:
    if len(sig) != 64:
        return False
    point = _p256_decompress(pub_compressed)
    if point is None:
        return False
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if not (1 <= r < _P256_N and 1 <= s < _P256_N):
        return False
    e = int.from_bytes(hashlib.sha256(message).digest(), "big") % _P256_N
    w = _p256_inv(s, _P256_N)
    u1 = (e * w) % _P256_N
    u2 = (r * w) % _P256_N
    x = _p256_add(_p256_mul(u1, _P256_G), _p256_mul(u2, point))
    if x is None:
        return False
    return (x[0] % _P256_N) == r


# ===========================================================================
# mldsa-87-p256 hybrid blob (wire-compatible with src/pq.rs)
# ===========================================================================

_HYBRID_MAGIC = b"MLP1"


def hybrid_sign(seed: bytes, message: bytes) -> bytes:
    d = p256_scalar_from_seed(seed)
    p256_pk = p256_public_compressed(d)
    p256_sig = p256_sign(d, message)
    xi = hashlib.sha256(b"tert-mldsa-87-p256/ml-dsa-87-xi" + seed).digest()
    mldsa_pk, mldsa_sk = mldsa87_keygen(xi)
    mldsa_sig = mldsa87_sign(mldsa_sk, message)
    out = bytearray(_HYBRID_MAGIC)
    put_bytes(out, p256_pk)
    put_bytes(out, mldsa_pk)
    put_bytes(out, p256_sig)
    put_bytes(out, mldsa_sig)
    return bytes(out)


def hybrid_verify(blob: bytes, message: bytes) -> bool:
    r = Reader(blob)
    if r.take(4) != _HYBRID_MAGIC:
        return False
    p256_pk = r.bytes()
    mldsa_pk = r.bytes()
    p256_sig = r.bytes()
    mldsa_sig = r.bytes()
    if p256_pk is None or mldsa_pk is None or p256_sig is None or mldsa_sig is None:
        return False
    if not p256_verify(p256_pk, message, p256_sig):
        return False
    if len(mldsa_pk) != MLDSA_PK_LEN or len(mldsa_sig) != MLDSA_SIG_LEN:
        return False
    return mldsa87_verify(mldsa_pk, message, mldsa_sig)


# ===========================================================================
# merkle-tree-certs (wire-compatible with src/pq.rs)
# ===========================================================================

_MTC_MAGIC = b"MTC1"
_D_EMPTY = 0
_D_NODE = 1
_D_ASSERTION = 2


def _sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def _u32(v: int) -> bytes:
    return struct.pack(">I", v)


def _u64(v: int) -> bytes:
    return struct.pack(">Q", v)


def hash_empty(issuer: bytes, batch: int) -> bytes:
    return _sha256(bytes([_D_EMPTY]), _u32(len(issuer)), issuer, _u32(batch))


def hash_assertion(issuer: bytes, batch: int, index: int, assertion: bytes) -> bytes:
    return _sha256(
        bytes([_D_ASSERTION]),
        _u32(len(issuer)),
        issuer,
        _u32(batch),
        _u64(index),
        _u32(len(assertion)),
        assertion,
    )


def hash_node(issuer: bytes, batch: int, left: bytes, right: bytes) -> bytes:
    return _sha256(bytes([_D_NODE]), _u32(len(issuer)), issuer, _u32(batch), left, right)


class MerkleTree:
    """Merkle tree over a batch of assertions (RFC 6962-style lone-node
    promotion) with MTC domain separation."""

    def __init__(self, issuer: bytes, batch: int, assertions: List[bytes]) -> None:
        self.issuer = bytes(issuer)
        self.batch = batch
        self.leaves = [
            hash_assertion(self.issuer, batch, i, a) for i, a in enumerate(assertions)
        ]

    def size(self) -> int:
        return len(self.leaves)

    def root(self) -> bytes:
        if not self.leaves:
            return hash_empty(self.issuer, self.batch)
        level = self.leaves
        while len(level) > 1:
            nxt = []
            i = 0
            while i < len(level):
                if i + 1 < len(level):
                    nxt.append(hash_node(self.issuer, self.batch, level[i], level[i + 1]))
                    i += 2
                else:
                    nxt.append(level[i])
                    i += 1
            level = nxt
        return level[0]

    def inclusion_proof(self, index: int) -> Optional[List[Tuple[bool, bytes]]]:
        if index < 0 or index >= len(self.leaves):
            return None
        proof: List[Tuple[bool, bytes]] = []
        level = self.leaves
        idx = index
        while len(level) > 1:
            nxt = []
            i = 0
            while i < len(level):
                if i + 1 < len(level):
                    if i == idx:
                        proof.append((True, level[i + 1]))
                    elif i + 1 == idx:
                        proof.append((False, level[i]))
                    nxt.append(hash_node(self.issuer, self.batch, level[i], level[i + 1]))
                    i += 2
                else:
                    nxt.append(level[i])
                    i += 1
            idx //= 2
            level = nxt
        return proof


def fold_inclusion(
    issuer: bytes, batch: int, index: int, assertion: bytes, proof: List[Tuple[bool, bytes]]
) -> bytes:
    node = hash_assertion(issuer, batch, index, assertion)
    for sibling_on_right, sibling in proof:
        if sibling_on_right:
            node = hash_node(issuer, batch, node, sibling)
        else:
            node = hash_node(issuer, batch, sibling, node)
    return node


def treehead_signing_input(issuer: bytes, batch: int, tree_size: int, root: bytes) -> bytes:
    return (
        b"MerkleTreeCRT:treehead:v1"
        + _u32(len(issuer))
        + issuer
        + _u32(batch)
        + _u64(tree_size)
        + root
    )


def encode_mtc(
    issuer: bytes,
    batch: int,
    tree_size: int,
    index: int,
    root: bytes,
    treehead_sig: bytes,
    proof: List[Tuple[bool, bytes]],
) -> bytes:
    out = bytearray(_MTC_MAGIC)
    put_bytes(out, issuer)
    out.extend(_u32(batch))
    out.extend(_u64(tree_size))
    out.extend(_u64(index))
    out.extend(root)
    put_bytes(out, treehead_sig)
    put_u16(out, len(proof))
    for right, h in proof:
        out.append(1 if right else 0)
        out.extend(h)
    return bytes(out)


class DecodedMtc:
    __slots__ = ("issuer", "batch", "tree_size", "index", "root", "treehead_sig", "proof")

    def __init__(self, issuer, batch, tree_size, index, root, treehead_sig, proof):
        self.issuer = issuer
        self.batch = batch
        self.tree_size = tree_size
        self.index = index
        self.root = root
        self.treehead_sig = treehead_sig
        self.proof = proof


def decode_mtc(blob: bytes) -> Optional[DecodedMtc]:
    r = Reader(blob)
    if r.take(4) != _MTC_MAGIC:
        return None
    issuer = r.bytes()
    if issuer is None:
        return None
    batch = r.u32()
    tree_size = r.u64()
    index = r.u64()
    root = r.take(32)
    treehead_sig = r.bytes()
    if batch is None or tree_size is None or index is None or root is None or treehead_sig is None:
        return None
    n = r.u16()
    if n is None:
        return None
    proof: List[Tuple[bool, bytes]] = []
    for _ in range(n):
        dir_byte = r.take(1)
        h = r.take(32)
        if dir_byte is None or h is None:
            return None
        proof.append((dir_byte[0] == 1, h))
    return DecodedMtc(issuer, batch, tree_size, index, root, treehead_sig, proof)


def mtc_recompute_root(dec: DecodedMtc, assertion: bytes) -> bytes:
    return fold_inclusion(dec.issuer, dec.batch, dec.index, assertion, dec.proof)
