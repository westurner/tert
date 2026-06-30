"""Pytest tests for tert.artifacts."""

import json

import pytest

from tert.artifacts import (
    build_artifact_summary,
    iter_summaries,
    maybe_sign,
    parse_checksum,
    summary_text,
    write_summary,
)
from tert.vc import FileKeyBackend, verify_document

FIXED_SEED = bytes(range(1, 33))


class TestParseChecksum:
    def test_with_algo(self):
        assert parse_checksum("sha256:ABCD") == ("sha256", "abcd")

    def test_bare(self):
        assert parse_checksum("ABCD") == ("sha256", "abcd")


class TestBuildSummary:
    def test_basic_fields(self, tmp_path):
        f = tmp_path / "a.bin"
        f.write_bytes(b"hello")
        doc = build_artifact_summary(str(f), role="input")
        subj = doc["credentialSubject"]
        assert subj["role"] == "input"
        assert subj["filename"] == "a.bin"
        assert subj["size"] == 5
        assert subj["sha256"] == (
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )
        assert doc["type"] == ["VerifiableCredential", "prov:Entity"]

    def test_checksum_match(self, tmp_path):
        f = tmp_path / "a.bin"
        f.write_bytes(b"hello")
        digest = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        doc = build_artifact_summary(str(f), checksum="sha256:" + digest)
        assert doc["credentialSubject"]["checksum_verified"] is True

    def test_checksum_mismatch(self, tmp_path):
        f = tmp_path / "a.bin"
        f.write_bytes(b"hello")
        doc = build_artifact_summary(str(f), checksum="sha256:deadbeef")
        assert doc["credentialSubject"]["checksum_verified"] is False

    def test_unsupported_algo(self, tmp_path):
        f = tmp_path / "a.bin"
        f.write_bytes(b"hello")
        with pytest.raises(ValueError):
            build_artifact_summary(str(f), checksum="md5:abcd")


class TestWriteAndIter:
    def test_write_and_iter_yaml(self, tmp_path):
        pytest.importorskip("yaml")
        f = tmp_path / "a.bin"
        f.write_bytes(b"hello")
        out = tmp_path / "summaries"
        doc = build_artifact_summary(str(f), role="output")
        path = write_summary(doc, str(out), fmt="yaml")
        assert path.endswith("a.bin.output.artifact.yml")
        loaded = iter_summaries(str(out))
        assert len(loaded) == 1
        assert loaded[0][1]["credentialSubject"]["filename"] == "a.bin"

    def test_iter_empty_dir(self, tmp_path):
        assert iter_summaries(str(tmp_path / "missing")) == []


class TestSigning:
    def test_maybe_sign_none(self, tmp_path):
        f = tmp_path / "a.bin"
        f.write_bytes(b"hello")
        doc = build_artifact_summary(str(f))
        assert maybe_sign(doc, None) is doc

    def test_signed_summary_verifies(self, tmp_path):
        f = tmp_path / "a.bin"
        f.write_bytes(b"hello")
        doc = build_artifact_summary(str(f))
        backend = FileKeyBackend(FIXED_SEED)
        signed = maybe_sign(doc, backend)
        assert "proof" in signed
        assert verify_document(signed) is True

    def test_summary_text_json(self, tmp_path):
        f = tmp_path / "a.bin"
        f.write_bytes(b"hello")
        doc = build_artifact_summary(str(f))
        parsed = json.loads(summary_text(doc, "json"))
        assert parsed["credentialSubject"]["filename"] == "a.bin"
