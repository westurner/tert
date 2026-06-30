#!/usr/bin/env python3
"""Tests for tert.pq: pure-Python ML-DSA-87, ECDSA-P256, and Merkle Tree Certs.

Includes cross-language interop checks against the Rust ``vc`` binary when it
has been built (``cargo build --bin vc``); those are skipped otherwise.
"""

import os
import json
import base64
import random
import subprocess

import pytest

from tert import pq
from tert import vc


# ---------------------------------------------------------------------------
# binary reader / writer
# ---------------------------------------------------------------------------


class TestBinary:
    def test_put_and_read_bytes_roundtrip(self):
        out = bytearray()
        pq.put_bytes(out, b"hello")
        pq.put_bytes(out, b"")
        r = pq.Reader(bytes(out))
        assert r.bytes() == b"hello"
        assert r.bytes() == b""
        assert r.bytes() is None

    def test_reader_take_past_end(self):
        r = pq.Reader(b"\x00\x01")
        assert r.take(3) is None
        assert r.u32() is None
        assert r.u64() is None


# ---------------------------------------------------------------------------
# ML-DSA-87 (FIPS 204)
# ---------------------------------------------------------------------------


class TestMldsa:
    def test_ntt_is_negacyclic_convolution(self):
        random.seed(7)
        a = [random.randrange(pq.Q) for _ in range(pq.N)]
        b = [random.randrange(pq.Q) for _ in range(pq.N)]
        n, q = pq.N, pq.Q
        expect = [0] * n
        for i in range(n):
            for j in range(n):
                v = (a[i] * b[j]) % q
                if i + j < n:
                    expect[i + j] = (expect[i + j] + v) % q
                else:
                    expect[i + j - n] = (expect[i + j - n] - v) % q
        expect = [x % q for x in expect]
        got = pq._intt(pq._poly_pointwise(pq._ntt(a), pq._ntt(b)))
        assert got == expect

    def test_simple_bit_pack_roundtrip(self):
        random.seed(1)
        b = 1023
        w = [random.randrange(b + 1) for _ in range(pq.N)]
        assert pq._simple_bit_unpack(pq._simple_bit_pack(w, b), b) == w

    def test_bit_pack_signed_roundtrip(self):
        random.seed(2)
        a = pq.ML_GAMMA1 - 1
        b = pq.ML_GAMMA1
        w = [random.randrange(-a, b + 1) % pq.Q for _ in range(pq.N)]
        packed = pq._bit_pack(w, a, b)
        assert pq._bit_unpack(packed, a, b) == [x % pq.Q for x in w]

    def test_keygen_sizes(self):
        pk, sk = pq.mldsa87_keygen(bytes(range(32)))
        assert len(pk) == pq.MLDSA_PK_LEN
        assert len(sk) == pq.MLDSA_SK_LEN

    def test_sign_verify_roundtrip(self):
        pk, sk = pq.mldsa87_keygen(b"\x02" * 32)
        msg = b"the quick brown fox"
        sig = pq.mldsa87_sign(sk, msg)
        assert len(sig) == pq.MLDSA_SIG_LEN
        assert pq.mldsa87_verify(pk, msg, sig) is True

    def test_sign_is_deterministic(self):
        pk, sk = pq.mldsa87_keygen(b"\x03" * 32)
        assert pq.mldsa87_sign(sk, b"m") == pq.mldsa87_sign(sk, b"m")

    def test_verify_rejects_tampered_message(self):
        pk, sk = pq.mldsa87_keygen(b"\x04" * 32)
        sig = pq.mldsa87_sign(sk, b"hello")
        assert pq.mldsa87_verify(pk, b"hella", sig) is False

    def test_verify_rejects_wrong_key(self):
        pk1, sk1 = pq.mldsa87_keygen(b"\x05" * 32)
        pk2, _ = pq.mldsa87_keygen(b"\x06" * 32)
        sig = pq.mldsa87_sign(sk1, b"hi")
        assert pq.mldsa87_verify(pk2, b"hi", sig) is False

    def test_verify_rejects_bad_lengths(self):
        pk, sk = pq.mldsa87_keygen(b"\x07" * 32)
        sig = pq.mldsa87_sign(sk, b"hi")
        assert pq.mldsa87_verify(pk[:-1], b"hi", sig) is False
        assert pq.mldsa87_verify(pk, b"hi", sig[:-1]) is False

    def test_verify_rejects_tampered_signature(self):
        pk, sk = pq.mldsa87_keygen(b"\x08" * 32)
        sig = bytearray(pq.mldsa87_sign(sk, b"hi"))
        sig[0] ^= 0xFF
        assert pq.mldsa87_verify(pk, b"hi", bytes(sig)) is False


# ---------------------------------------------------------------------------
# ECDSA-P256
# ---------------------------------------------------------------------------


class TestP256:
    def test_sign_verify_roundtrip(self):
        d = pq.p256_scalar_from_seed(b"seed-a")
        pub = pq.p256_public_compressed(d)
        assert len(pub) == 33 and pub[0] in (2, 3)
        sig = pq.p256_sign(d, b"message")
        assert len(sig) == 64
        assert pq.p256_verify(pub, b"message", sig) is True

    def test_low_s_normalized(self):
        d = pq.p256_scalar_from_seed(b"seed-b")
        sig = pq.p256_sign(d, b"x")
        s = int.from_bytes(sig[32:], "big")
        assert s <= pq._P256_N // 2

    def test_verify_rejects_tamper(self):
        d = pq.p256_scalar_from_seed(b"seed-c")
        pub = pq.p256_public_compressed(d)
        sig = pq.p256_sign(d, b"message")
        assert pq.p256_verify(pub, b"messagE", sig) is False

    def test_verify_rejects_bad_inputs(self):
        d = pq.p256_scalar_from_seed(b"seed-d")
        pub = pq.p256_public_compressed(d)
        assert pq.p256_verify(pub, b"m", b"\x00" * 63) is False
        assert pq.p256_verify(b"\x09" * 33, b"m", pq.p256_sign(d, b"m")) is False
        assert pq.p256_verify(pub, b"m", b"\x00" * 64) is False

    def test_decompress_roundtrip(self):
        d = pq.p256_scalar_from_seed(b"seed-e")
        pub = pq.p256_public_compressed(d)
        x, y = pq._p256_decompress(pub)
        assert (y * y - (x * x * x + pq._P256_A * x + pq._P256_B)) % pq._P256_P == 0


# ---------------------------------------------------------------------------
# Merkle tree / MTC
# ---------------------------------------------------------------------------


class TestMerkle:
    def test_single_leaf_root_is_leaf(self):
        issuer = b"did:key:zABC"
        tree = pq.MerkleTree(issuer, 7, [b"cert-0"])
        assert tree.size() == 1
        proof = tree.inclusion_proof(0)
        assert proof == []
        assert pq.fold_inclusion(issuer, 7, 0, b"cert-0", proof) == tree.root()

    def test_empty_tree_uses_hash_empty(self):
        issuer = b"did:key:zABC"
        tree = pq.MerkleTree(issuer, 0, [])
        assert tree.root() == pq.hash_empty(issuer, 0)
        assert tree.inclusion_proof(0) is None

    def test_inclusion_proofs_all_indices(self):
        issuer = b"did:key:zABC"
        certs = [b"cert-%d" % i for i in range(5)]  # non-power-of-two
        tree = pq.MerkleTree(issuer, 3, certs)
        root = tree.root()
        for i, a in enumerate(certs):
            assert pq.fold_inclusion(issuer, 3, i, a, tree.inclusion_proof(i)) == root

    def test_wrong_assertion_fails(self):
        issuer = b"did:key:zABC"
        certs = [b"cert-%d" % i for i in range(4)]
        tree = pq.MerkleTree(issuer, 1, certs)
        proof = tree.inclusion_proof(2)
        assert pq.fold_inclusion(issuer, 1, 2, b"forged", proof) != tree.root()

    def test_mtc_encode_decode_roundtrip(self):
        issuer = b"did:key:zABC"
        certs = [b"cert-%d" % i for i in range(3)]
        tree = pq.MerkleTree(issuer, 9, certs)
        root = tree.root()
        proof = tree.inclusion_proof(1)
        blob = pq.encode_mtc(issuer, 9, 3, 1, root, b"sig-bytes", proof)
        dec = pq.decode_mtc(blob)
        assert dec.issuer == issuer
        assert dec.batch == 9 and dec.tree_size == 3 and dec.index == 1
        assert dec.root == root and dec.treehead_sig == b"sig-bytes"
        assert pq.mtc_recompute_root(dec, certs[1]) == root

    def test_decode_rejects_bad_magic(self):
        assert pq.decode_mtc(b"XXXX") is None


# ---------------------------------------------------------------------------
# hybrid blob
# ---------------------------------------------------------------------------


class TestHybrid:
    def test_sign_verify_roundtrip(self):
        blob = pq.hybrid_sign(b"seed-32-bytes", b"payload")
        assert pq.hybrid_verify(blob, b"payload") is True
        assert pq.hybrid_verify(blob, b"other") is False

    def test_rejects_bad_magic(self):
        assert pq.hybrid_verify(b"XXXX", b"payload") is False

    def test_rejects_tampered_blob(self):
        blob = bytearray(pq.hybrid_sign(b"seed", b"payload"))
        blob[-1] ^= 0xFF
        assert pq.hybrid_verify(bytes(blob), b"payload") is False


# ---------------------------------------------------------------------------
# Cross-language interop with the Rust `vc` binary
# ---------------------------------------------------------------------------

_VCBIN = os.path.join(os.path.dirname(os.path.dirname(__file__)), "target", "debug", "vc")
_FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

SAMPLE = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential"],
    "credentialSubject": {"id": "urn:example:1", "name": "Ada", "n": 7, "u": "caf\u00e9 \u2603"},
}


def _file_backend(keys_dir):
    os.makedirs(keys_dir, exist_ok=True)
    seed = bytes(range(1, 33))
    key_path = os.path.join(keys_dir, "did_ed25519.key")
    with open(key_path, "w") as fh:
        fh.write(base64.b64encode(seed).decode())
    os.chmod(key_path, 0o600)
    return vc.FileKeyBackend.load_or_create(keys_dir)


@pytest.mark.parametrize("fixture", ["vc_mldsa_interop.json", "vc_mtc_interop.json"])
def test_committed_fixture_verifies(fixture):
    """The committed Python-signed fixtures (also verified by the Rust suite)
    must round-trip through Python verification."""
    with open(os.path.join(_FIXTURES, fixture)) as fh:
        signed = json.load(fh)
    assert vc.verify_document(signed) is True


@pytest.mark.skipif(not os.path.exists(_VCBIN), reason="rust vc binary not built")
@pytest.mark.parametrize("suite", ["mldsa-87-p256", "merkle-tree-certs"])
class TestInterop:
    def test_python_sign_rust_verify(self, tmp_path, suite):
        backend = _file_backend(str(tmp_path / "keys"))
        signed = vc.sign_document(SAMPLE, backend, cryptosuite=suite)
        assert vc.verify_document(signed) is True
        path = tmp_path / "py_signed.json"
        path.write_text(json.dumps(signed))
        out = subprocess.run([_VCBIN, "verify", str(path)], capture_output=True, text=True)
        assert out.returncode == 0, out.stderr
        assert "OK" in out.stdout

    def test_rust_sign_python_verify(self, tmp_path, suite):
        keys = str(tmp_path / "keys")
        _file_backend(keys)
        doc_path = tmp_path / "doc.json"
        doc_path.write_text(json.dumps(SAMPLE))
        signed_path = tmp_path / "rust_signed.json"
        out = subprocess.run(
            [_VCBIN, "sign", "--cryptosuite", suite, "--keys-dir", keys,
             "-o", str(signed_path), str(doc_path)],
            capture_output=True, text=True,
        )
        assert out.returncode == 0, out.stderr
        signed = json.loads(signed_path.read_text())
        assert vc.verify_document(signed) is True
