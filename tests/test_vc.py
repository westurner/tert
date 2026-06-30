"""Pytest tests for tert.vc (Verifiable Credential signing)."""
import json

import pytest

from tert.vc import (
    CRYPTOSUITES,
    DEFAULT_CRYPTOSUITE,
    CryptosuiteError,
    FileKeyBackend,
    canonicalize,
    dump_document,
    get_cryptosuite,
    load_document,
    sign_document,
    verify_document,
)

FIXED_SEED = bytes(range(1, 33))


@pytest.fixture
def backend():
    return FileKeyBackend(FIXED_SEED)


SAMPLE_DOC = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential"],
    "credentialSubject": {"id": "urn:example:1", "name": "Ada", "count": 3},
}


class TestCanonicalize:
    def test_sorts_keys_compact(self):
        out = canonicalize({"b": 1, "a": 2})
        assert out == b'{"a":2,"b":1}'

    def test_escapes_non_ascii(self):
        out = canonicalize({"k": "café"})
        # ensure_ascii escapes the é
        assert out == b'{"k":"caf\\u00e9"}'

    def test_nested_deterministic(self):
        a = canonicalize({"x": {"b": 1, "a": 2}, "y": [3, 2, 1]})
        b = canonicalize({"y": [3, 2, 1], "x": {"a": 2, "b": 1}})
        assert a == b


class TestCryptosuites:
    def test_default_is_eddsa(self):
        assert DEFAULT_CRYPTOSUITE == "eddsa-jcs-2022"
        assert get_cryptosuite("eddsa-jcs-2022").available is True

    def test_pq_and_mtc_are_stubs(self):
        assert get_cryptosuite("mldsa-87-p256").available is False
        assert get_cryptosuite("merkle-tree-certs").available is False

    def test_unknown_raises(self):
        with pytest.raises(CryptosuiteError):
            get_cryptosuite("nope")

    def test_registry_contents(self):
        assert set(CRYPTOSUITES) == {"eddsa-jcs-2022", "mldsa-87-p256", "merkle-tree-certs"}


class TestSignVerify:
    def test_sign_and_verify(self, backend):
        signed = sign_document(SAMPLE_DOC, backend)
        assert signed["issuer"] == backend.did()
        assert signed["proof"]["cryptosuite"] == "eddsa-jcs-2022"
        assert signed["proof"]["verificationMethod"].startswith(backend.did() + "#")
        assert verify_document(signed) is True

    def test_verify_detects_tamper(self, backend):
        signed = sign_document(SAMPLE_DOC, backend)
        signed["credentialSubject"]["name"] = "Eve"
        assert verify_document(signed) is False

    def test_verify_unsigned(self):
        assert verify_document(dict(SAMPLE_DOC)) is False

    def test_verify_unknown_cryptosuite(self, backend):
        signed = sign_document(SAMPLE_DOC, backend)
        signed["proof"]["cryptosuite"] = "bogus"
        assert verify_document(signed) is False

    def test_sign_with_pq_stub_raises(self, backend):
        with pytest.raises(CryptosuiteError):
            sign_document(SAMPLE_DOC, backend, cryptosuite="mldsa-87-p256")

    def test_signature_is_deterministic(self, backend):
        s1 = sign_document(SAMPLE_DOC, backend, created="2020-01-01T00:00:00Z")
        s2 = sign_document(SAMPLE_DOC, backend, created="2020-01-01T00:00:00Z")
        assert s1["proof"]["proofValue"] == s2["proof"]["proofValue"]


class TestDocumentIO:
    def test_json_roundtrip(self, tmp_path, backend):
        signed = sign_document(SAMPLE_DOC, backend)
        path = tmp_path / "vc.json"
        path.write_text(dump_document(signed, "json"))
        loaded, fmt = load_document(str(path))
        assert fmt == "json"
        assert verify_document(loaded) is True

    def test_yaml_roundtrip(self, tmp_path, backend):
        pytest.importorskip("yaml")
        signed = sign_document(SAMPLE_DOC, backend)
        path = tmp_path / "vc.yaml"
        path.write_text(dump_document(signed, "yaml"))
        loaded, fmt = load_document(str(path))
        assert fmt == "yaml"
        assert verify_document(loaded) is True

    def test_cross_format_same_signature_verifies(self, tmp_path, backend):
        # A document signed once must verify whether reloaded from JSON or YAML.
        pytest.importorskip("yaml")
        signed = sign_document(SAMPLE_DOC, backend)
        jpath = tmp_path / "vc.json"
        ypath = tmp_path / "vc.yaml"
        jpath.write_text(dump_document(signed, "json"))
        ypath.write_text(dump_document(signed, "yaml"))
        assert verify_document(load_document(str(jpath))[0]) is True
        assert verify_document(load_document(str(ypath))[0]) is True

    def test_toml_roundtrip(self, tmp_path, backend):
        signed = sign_document(SAMPLE_DOC, backend)
        path = tmp_path / "vc.toml"
        path.write_text(dump_document(signed, "toml"))
        loaded, fmt = load_document(str(path))
        assert fmt == "toml"
        assert loaded == signed
        assert verify_document(loaded) is True

    def test_toml_uses_provisional_section(self, tmp_path, backend):
        from tert.vc import TOML_VC_SECTION
        signed = sign_document(SAMPLE_DOC, backend)
        text = dump_document(signed, "toml")
        assert text.startswith("[%s]" % TOML_VC_SECTION)

    def test_toml_quotes_context_key(self, backend):
        signed = sign_document(SAMPLE_DOC, backend)
        text = dump_document(signed, "toml")
        assert '"@context"' in text

    def test_all_three_formats_same_signature(self, tmp_path, backend):
        pytest.importorskip("yaml")
        signed = sign_document(SAMPLE_DOC, backend)
        for ext, fmt in [("json", "json"), ("yaml", "yaml"), ("toml", "toml")]:
            p = tmp_path / ("vc." + ext)
            p.write_text(dump_document(signed, fmt))
            loaded, detected = load_document(str(p))
            assert detected == fmt
            assert verify_document(loaded) is True


class TestCli:
    def test_sign_and_verify_via_cli(self, tmp_path, capsys):
        from tert.vc import main
        keys = tmp_path / "keys"
        doc_path = tmp_path / "doc.json"
        out_path = tmp_path / "signed.json"
        doc_path.write_text(json.dumps(SAMPLE_DOC))
        rc = main(["sign", str(doc_path), "--keys-dir", str(keys), "-o", str(out_path)])
        assert rc == 0
        rc = main(["verify", str(out_path)])
        out = capsys.readouterr().out
        assert rc == 0
        assert "OK" in out

    def test_cryptosuites_listing(self, capsys):
        from tert.vc import main
        rc = main(["cryptosuites", "--json"])
        out = capsys.readouterr().out
        assert rc == 0
        rows = json.loads(out)
        names = {r["name"] for r in rows}
        assert "mldsa-87-p256" in names

    def test_sign_with_stub_cryptosuite_fails(self, tmp_path, capsys):
        from tert.vc import main
        keys = tmp_path / "keys"
        doc_path = tmp_path / "doc.json"
        doc_path.write_text(json.dumps(SAMPLE_DOC))
        rc = main(["sign", str(doc_path), "--keys-dir", str(keys),
                   "--cryptosuite", "mldsa-87-p256"])
        assert rc == 2
