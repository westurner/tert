"""Shared Ed25519 / did:key interop vectors.

The vectors live in ``tests/fixtures/crypto_vectors.json`` and are consumed by
BOTH this Python test and the Rust ``tert::crypto`` interop test, so the two
implementations are checked against one identical data set. The Python values
are independently validated against OpenSSL in test_crypto.py.
"""
import json
import os

import pytest

from tert.crypto import (
    ed25519_publickey,
    ed25519_sign,
    ed25519_verify,
    did_key_from_pubkey,
)

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "crypto_vectors.json")


def load_vectors():
    with open(FIXTURE, "r", encoding="utf-8") as fh:
        return json.load(fh)


VECTORS = load_vectors()

# The canonical vector (seed 0x01..0x20, message "tert interop vector").
CANONICAL = VECTORS[0]


def _ids(vectors):
    return [v["message_utf8"] or "<empty>" for v in vectors]


def test_fixture_present():
    assert len(VECTORS) >= 5


def test_canonical_vector_constants():
    # Pin the canonical vector so an accidental change is caught here.
    assert CANONICAL["seed_hex"] == (
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    )
    assert CANONICAL["did"] == "did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7"
    assert CANONICAL["pubkey_hex"] == (
        "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
    )


@pytest.mark.parametrize("vec", VECTORS, ids=_ids(VECTORS))
def test_pubkey_matches(vec):
    seed = bytes.fromhex(vec["seed_hex"])
    assert ed25519_publickey(seed).hex() == vec["pubkey_hex"]


@pytest.mark.parametrize("vec", VECTORS, ids=_ids(VECTORS))
def test_signature_matches(vec):
    seed = bytes.fromhex(vec["seed_hex"])
    msg = vec["message_utf8"].encode("utf-8")
    assert ed25519_sign(seed, msg).hex() == vec["sig_hex"]


@pytest.mark.parametrize("vec", VECTORS, ids=_ids(VECTORS))
def test_did_matches(vec):
    seed = bytes.fromhex(vec["seed_hex"])
    assert did_key_from_pubkey(ed25519_publickey(seed)) == vec["did"]


@pytest.mark.parametrize("vec", VECTORS, ids=_ids(VECTORS))
def test_vector_verifies(vec):
    pub = bytes.fromhex(vec["pubkey_hex"])
    msg = vec["message_utf8"].encode("utf-8")
    sig = bytes.fromhex(vec["sig_hex"])
    assert ed25519_verify(pub, msg, sig) is True


@pytest.mark.parametrize("vec", VECTORS, ids=_ids(VECTORS))
def test_vector_rejects_wrong_message(vec):
    pub = bytes.fromhex(vec["pubkey_hex"])
    sig = bytes.fromhex(vec["sig_hex"])
    assert ed25519_verify(pub, b"WRONG" + vec["message_utf8"].encode(), sig) is False
