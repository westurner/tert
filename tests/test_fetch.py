"""Pytest tests for tert.fetch."""
import os
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from tert.fetch import (
    CryptoConfig,
    CurlStrategy,
    FetchError,
    FetchResult,
    FileKeyBackend,
    RustStrategy,
    WgetStrategy,
    basename_from_url,
    build_provenance,
    count_pem_certificates,
    detect_tls_backend,
    discover_ca_bundle,
    fetch,
    file_sha256,
    file_size,
    get_strategy,
    main,
    parse_tls_info,
    resolve_strategy_name,
    sign_provenance,
    verify_crypto_config,
    verify_provenance,
    verify_provenance_file,
)


# Two-certificate PEM bundle used across tests.
_TWO_CERT_PEM = (
    "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n"
)


@pytest.fixture
def ca_bundle(tmp_path):
    """Create a fake 2-certificate CA bundle and return its path."""
    p = tmp_path / "ca-bundle.crt"
    p.write_text(_TWO_CERT_PEM)
    return p


class TestFileHelpers:
    def test_file_size(self, tmp_path):
        p = tmp_path / "f"
        p.write_bytes(b"12345")
        assert file_size(str(p)) == 5

    def test_file_size_missing(self, tmp_path):
        assert file_size(str(tmp_path / "nope")) is None

    def test_file_sha256_known(self, tmp_path):
        p = tmp_path / "f"
        p.write_bytes(b"")
        # sha256 of empty input
        assert file_sha256(str(p)) == (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_file_sha256_missing(self, tmp_path):
        assert file_sha256(str(tmp_path / "nope")) is None

    def test_count_pem_certificates(self, ca_bundle):
        assert count_pem_certificates(str(ca_bundle)) == 2

    def test_count_pem_certificates_missing(self, tmp_path):
        assert count_pem_certificates(str(tmp_path / "nope")) is None


class TestBasename:
    @pytest.mark.parametrize("url,expected", [
        ("https://example.com/file.tar.gz", "file.tar.gz"),
        ("https://example.com/a/b/c.bin?x=1#frag", "c.bin"),
        ("https://example.com/", "index.html"),
        ("https://example.com", "example.com"),
    ])
    def test_basename_from_url(self, url, expected):
        assert basename_from_url(url) == expected


class TestDiscoverCaBundle:
    def test_env_var_wins(self, tmp_path):
        env = {"SSL_CERT_FILE": "/custom/ca.pem"}
        path, source = discover_ca_bundle(("SSL_CERT_FILE",), env, candidates=())
        assert path == "/custom/ca.pem"
        assert source == "env:SSL_CERT_FILE"

    def test_env_precedence_order(self, tmp_path):
        env = {"CURL_CA_BUNDLE": "/a.pem", "SSL_CERT_FILE": "/b.pem"}
        path, source = discover_ca_bundle(("CURL_CA_BUNDLE", "SSL_CERT_FILE"), env, candidates=())
        assert path == "/a.pem"
        assert source == "env:CURL_CA_BUNDLE"

    def test_candidate_fallback(self, ca_bundle):
        path, source = discover_ca_bundle((), {}, candidates=(str(ca_bundle),))
        assert path == str(ca_bundle)
        assert source == "candidate"

    def test_none_found(self, tmp_path):
        path, source = discover_ca_bundle((), {}, candidates=(str(tmp_path / "missing"),))
        assert path is None
        assert source == "none"


class TestDetectTlsBackend:
    @pytest.mark.parametrize("text,expected", [
        ("curl 8.15.0 libcurl/8.15.0 OpenSSL/3.5.4 zlib/1.3", "OpenSSL"),
        ("GNU Wget2 2.2.1 +ssl/gnutls +https", "GnuTLS"),
        ("libcurl LibreSSL/3.7", "LibreSSL"),
        ("something BoringSSL based", "BoringSSL"),
        ("no tls here", None),
        (None, None),
    ])
    def test_detect(self, text, expected):
        assert detect_tls_backend(text) == expected


class TestParseTlsInfo:
    def test_curl_connection_line(self):
        text = "* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384\n* more\n"
        assert parse_tls_info(text) == ("TLSv1.3", "TLS_AES_256_GCM_SHA384")

    def test_curl_tls12_ecdhe(self):
        text = "* SSL connection using TLSv1.2 / ECDHE-RSA-AES128-GCM-SHA256\n"
        assert parse_tls_info(text) == ("TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256")

    def test_generic_fallback(self):
        text = "TLS handshake done\nTLSv1.2 negotiated\ncipher: AES_256_GCM\n"
        version, cipher = parse_tls_info(text)
        assert version == "TLSv1.2"
        assert cipher == "AES_256_GCM"

    def test_no_tls(self):
        assert parse_tls_info("plain file download, no encryption") == (None, None)

    def test_empty(self):
        assert parse_tls_info(None) == (None, None)
        assert parse_tls_info("") == (None, None)


class TestVerifyCryptoConfig:
    def test_ok(self, ca_bundle):
        cfg = CryptoConfig(
            strategy="curl",
            tls_backend="OpenSSL",
            ca_bundle_path=str(ca_bundle),
            ca_bundle_exists=True,
            ca_bundle_size=ca_bundle.stat().st_size,
            ca_bundle_cert_count=2,
        )
        ok, problems = verify_crypto_config(cfg)
        assert ok is True
        assert problems == []

    def test_no_backend(self):
        cfg = CryptoConfig(strategy="curl", ca_bundle_path="/x", ca_bundle_exists=True,
                           ca_bundle_size=10, ca_bundle_cert_count=1)
        ok, problems = verify_crypto_config(cfg)
        assert ok is False
        assert any("TLS backend" in p for p in problems)

    def test_no_bundle(self):
        cfg = CryptoConfig(strategy="curl", tls_backend="OpenSSL")
        ok, problems = verify_crypto_config(cfg)
        assert ok is False
        assert any("no CA certificate bundle" in p for p in problems)

    def test_bundle_missing(self):
        cfg = CryptoConfig(strategy="curl", tls_backend="OpenSSL",
                           ca_bundle_path="/x", ca_bundle_exists=False)
        ok, problems = verify_crypto_config(cfg)
        assert ok is False
        assert any("does not exist" in p for p in problems)

    def test_bundle_empty(self):
        cfg = CryptoConfig(strategy="curl", tls_backend="OpenSSL",
                           ca_bundle_path="/x", ca_bundle_exists=True, ca_bundle_size=0)
        ok, problems = verify_crypto_config(cfg)
        assert ok is False
        assert any("empty" in p for p in problems)

    def test_bundle_no_certs(self):
        cfg = CryptoConfig(strategy="curl", tls_backend="OpenSSL",
                           ca_bundle_path="/x", ca_bundle_exists=True,
                           ca_bundle_size=10, ca_bundle_cert_count=0)
        ok, problems = verify_crypto_config(cfg)
        assert ok is False
        assert any("no certificates" in p for p in problems)


class TestStrategySelection:
    def test_get_strategy(self):
        assert isinstance(get_strategy("curl"), CurlStrategy)
        assert isinstance(get_strategy("wget"), WgetStrategy)
        assert isinstance(get_strategy("rust"), RustStrategy)

    def test_get_strategy_unknown(self):
        with pytest.raises(FetchError):
            get_strategy("bogus")

    def test_resolve_auto_prefers_curl(self):
        with patch.object(CurlStrategy, "executable", return_value="/usr/bin/curl"):
            assert resolve_strategy_name("auto") == "curl"

    def test_resolve_auto_falls_back_to_wget(self):
        with patch.object(CurlStrategy, "executable", return_value=None), \
             patch.object(WgetStrategy, "executable", return_value="/usr/bin/wget"):
            assert resolve_strategy_name("auto") == "wget"

    def test_resolve_explicit(self):
        assert resolve_strategy_name("wget") == "wget"


class TestCryptoConfigDiscovery:
    def test_curl_crypto_config(self, ca_bundle):
        env = {"CURL_CA_BUNDLE": str(ca_bundle)}
        strat = CurlStrategy(environ=env, candidates=())
        with patch.object(strat, "executable", return_value="/usr/bin/curl"), \
             patch.object(strat, "version_text",
                          return_value="curl 8.15.0 libcurl/8.15.0 OpenSSL/3.5.4"):
            cfg = strat.crypto_config()
        assert cfg.strategy == "curl"
        assert cfg.available is True
        assert cfg.tls_backend == "OpenSSL"
        assert cfg.ca_bundle_path == str(ca_bundle)
        assert cfg.ca_bundle_source == "env:CURL_CA_BUNDLE"
        assert cfg.ca_bundle_exists is True
        assert cfg.ca_bundle_cert_count == 2
        assert cfg.ca_bundle_sha256 == file_sha256(str(ca_bundle))

    def test_wget_crypto_config(self, ca_bundle):
        strat = WgetStrategy(environ={}, candidates=(str(ca_bundle),))
        with patch.object(strat, "executable", return_value="/usr/bin/wget"), \
             patch.object(strat, "version_text",
                          return_value="GNU Wget2 2.2.1 +ssl/gnutls"):
            cfg = strat.crypto_config()
        assert cfg.tls_backend == "GnuTLS"
        assert cfg.ca_bundle_source == "candidate"

    def test_rust_crypto_config_is_stub(self, ca_bundle):
        strat = RustStrategy(environ={}, candidates=(str(ca_bundle),))
        cfg = strat.crypto_config()
        assert cfg.strategy == "rust"
        assert cfg.available is False
        assert cfg.tls_backend == "rustls"
        assert any("stub" in n for n in cfg.notes)


class TestBuildCommand:
    def test_curl_command_includes_cacert(self, ca_bundle):
        strat = CurlStrategy(environ={}, candidates=())
        cfg = CryptoConfig(strategy="curl", ca_bundle_path=str(ca_bundle),
                           ca_bundle_exists=True)
        cmd = strat.build_command("https://x/y", "/tmp/y.part", cfg)
        assert "curl" == cmd[0]
        assert "--cacert" in cmd
        assert str(ca_bundle) in cmd
        assert cmd[-1] == "https://x/y"

    def test_wget_command_includes_cacert(self, ca_bundle):
        strat = WgetStrategy(environ={}, candidates=())
        cfg = CryptoConfig(strategy="wget", ca_bundle_path=str(ca_bundle),
                           ca_bundle_exists=True)
        cmd = strat.build_command("https://x/y", "/tmp/y.part", cfg)
        assert cmd[0] == "wget"
        assert any(a.startswith("--ca-certificate=") for a in cmd)
        assert cmd[-1] == "https://x/y"


class TestRustStub:
    def test_download_raises(self):
        strat = RustStrategy()
        cfg = CryptoConfig(strategy="rust")
        with pytest.raises(NotImplementedError):
            strat.download("https://x", "/tmp/x", cfg)


class TestDownloadMocked:
    def test_curl_download_success(self, tmp_path, ca_bundle):
        strat = CurlStrategy(environ={}, candidates=())
        cfg = CryptoConfig(strategy="curl", ca_bundle_path=str(ca_bundle),
                           ca_bundle_exists=True)
        dest = str(tmp_path / "out.bin")

        def fake_run(cmd, **kwargs):
            # emulate curl writing the .part file
            part = cmd[cmd.index("-o") + 1]
            Path(part).write_bytes(b"payload")
            return Mock(returncode=0, stdout="", stderr="")

        with patch.object(strat, "executable", return_value="/usr/bin/curl"), \
             patch("subprocess.run", side_effect=fake_run):
            rc = strat.download("https://x/out.bin", dest, cfg)
        assert rc == 0
        assert Path(dest).read_bytes() == b"payload"
        assert not Path(dest + ".part").exists()

    def test_curl_download_failure_cleans_part(self, tmp_path, ca_bundle):
        strat = CurlStrategy(environ={}, candidates=())
        cfg = CryptoConfig(strategy="curl", ca_bundle_path=str(ca_bundle),
                           ca_bundle_exists=True)
        dest = str(tmp_path / "out.bin")

        def fake_run(cmd, **kwargs):
            part = cmd[cmd.index("-o") + 1]
            Path(part).write_bytes(b"partial")
            return Mock(returncode=22, stdout="", stderr="404")

        with patch.object(strat, "executable", return_value="/usr/bin/curl"), \
             patch("subprocess.run", side_effect=fake_run):
            with pytest.raises(FetchError):
                strat.download("https://x/out.bin", dest, cfg)
        assert not Path(dest + ".part").exists()
        assert not Path(dest).exists()


class TestFetchOrchestration:
    def test_refuses_when_crypto_unverified(self, tmp_path):
        # No bundle and no backend -> verification fails -> refuse.
        with pytest.raises(FetchError) as exc:
            fetch(
                "https://x/y",
                str(tmp_path / "y"),
                strategy="rust",
                environ={},
                candidates=(str(tmp_path / "missing"),),
            )
        assert "crypto configuration could not be verified" in str(exc.value)

    def test_crypto_only_no_download(self, ca_bundle):
        env = {"CURL_CA_BUNDLE": str(ca_bundle)}
        strat = get_strategy("curl", environ=env, candidates=())
        with patch.object(CurlStrategy, "executable", return_value="/usr/bin/curl"), \
             patch.object(CurlStrategy, "version_text",
                          return_value="curl 8.15.0 OpenSSL/3.5.4"):
            result = fetch(
                "https://x/y",
                strategy="curl",
                environ=env,
                candidates=(),
                download=False,
            )
        assert isinstance(result, FetchResult)
        assert result.downloaded is False
        assert result.crypto_ok is True

    def test_full_fetch_via_file_url(self, tmp_path, ca_bundle):
        # Use a real curl file:// download if curl is available.
        import shutil
        if shutil.which("curl") is None:
            pytest.skip("curl not available")
        src = tmp_path / "src.txt"
        src.write_text("hello fetch")
        dest = tmp_path / "dst.txt"
        env = {"CURL_CA_BUNDLE": str(ca_bundle)}
        result = fetch(
            src.as_uri(),
            str(dest),
            strategy="curl",
            environ=env,
            candidates=(),
        )
        assert result.downloaded is True
        assert dest.read_text() == "hello fetch"
        assert result.sha256 == file_sha256(str(dest))


class TestCli:
    def test_crypto_only_cli(self, capsys, ca_bundle, monkeypatch):
        monkeypatch.setenv("CURL_CA_BUNDLE", str(ca_bundle))
        with patch.object(CurlStrategy, "executable", return_value="/usr/bin/curl"), \
             patch.object(CurlStrategy, "version_text",
                          return_value="curl 8.15.0 OpenSSL/3.5.4"):
            rc = main(["--crypto-only", "--curl", "--json"])
        out = capsys.readouterr().out
        assert rc == 0
        assert '"tls_backend": "OpenSSL"' in out

    def test_url_required(self):
        with pytest.raises(SystemExit):
            main([])


def _result_for_provenance(tmp_path):
    cfg = CryptoConfig(
        strategy="curl",
        tls_backend="OpenSSL",
        ca_bundle_path="/etc/pki/tls/certs/ca-bundle.crt",
        ca_bundle_exists=True,
        ca_bundle_size=1000,
        ca_bundle_cert_count=3,
        ca_bundle_sha256="abc123",
    )
    return FetchResult(
        url="https://example.com/file.bin",
        dest=str(tmp_path / "file.bin"),
        strategy="curl",
        crypto_config=cfg,
        crypto_ok=True,
        sha256="deadbeef",
        bytes_written=42,
    )


class TestProvenance:
    def test_sign_and_verify_with_file_backend(self, tmp_path):
        backend = FileKeyBackend(bytes(range(1, 33)))
        result = _result_for_provenance(tmp_path)
        prov = sign_provenance(build_provenance(result), backend)
        assert prov["issuer"] == backend.did()
        assert prov["proof"]["proofValue"]
        assert verify_provenance(prov) is True

    def test_verify_detects_tampering(self, tmp_path):
        backend = FileKeyBackend(bytes(range(1, 33)))
        prov = sign_provenance(build_provenance(_result_for_provenance(tmp_path)), backend)
        prov["credentialSubject"]["sha256"] = "tampered"
        assert verify_provenance(prov) is False

    def test_verify_unsigned_is_false(self, tmp_path):
        prov = build_provenance(_result_for_provenance(tmp_path))
        assert verify_provenance(prov) is False

    def test_file_backend_persists_key(self, tmp_path):
        keys = tmp_path / "keys"
        b1 = FileKeyBackend.load_or_create(str(keys))
        b2 = FileKeyBackend.load_or_create(str(keys))
        assert b1.did() == b2.did()
        key_file = keys / "did_ed25519.key"
        assert key_file.exists()
        assert (key_file.stat().st_mode & 0o077) == 0

    def test_fetch_writes_signed_sidecar_via_file_backend(self, tmp_path, ca_bundle):
        import shutil
        if shutil.which("curl") is None:
            pytest.skip("curl not available")
        src = tmp_path / "src.txt"
        src.write_text("payload to sign")
        dest = tmp_path / "out.txt"
        backend = FileKeyBackend(bytes(range(1, 33)))
        env = {"CURL_CA_BUNDLE": str(ca_bundle)}
        result = fetch(
            src.as_uri(),
            str(dest),
            strategy="curl",
            environ=env,
            candidates=(),
            sign=True,
            key_backend=backend,
        )
        assert result.provenance_path is not None
        assert result.signed_by == backend.did()
        assert verify_provenance_file(result.provenance_path) is True


class TestCache:
    def test_cache_helpers(self, tmp_path):
        from tert.fetch import (
            cache_output_path,
            meta_sidecar_path,
            index_path,
            _url_host,
            default_cache_dir,
        )
        cdir = str(tmp_path / "cache")
        out = cache_output_path(cdir, "https://example.com/path/file.tar.gz?x=1")
        assert out.endswith("/cache/example.com/file.tar.gz")
        assert meta_sidecar_path(out).endswith("file.tar.gz.meta.yml")
        assert index_path(cdir).endswith("index.meta.yml")
        assert _url_host("https://user@host.example:443/p") == "host.example"
        env = {"TERT_FETCH_CACHE_DIR": "/custom/cache"}
        assert default_cache_dir(env) == "/custom/cache"

    def test_cache_download_writes_signed_meta_and_index(self, tmp_path, ca_bundle):
        import shutil
        if shutil.which("curl") is None:
            pytest.skip("curl not available")
        from tert.fetch import query_ls, query_show, default_cache_dir
        from tert.vc import verify_document
        import yaml

        src = tmp_path / "artifact.bin"
        src.write_bytes(b"cache me")
        cache_dir = str(tmp_path / "cache")
        backend = FileKeyBackend(bytes(range(1, 33)))
        env = {"CURL_CA_BUNDLE": str(ca_bundle)}
        result = fetch(
            src.as_uri(),
            strategy="curl",
            environ=env,
            candidates=(),
            cache=True,
            cache_dir=cache_dir,
            key_backend=backend,
        )
        # Output cached under cache/<host>/<filename> with a .meta.yml sidecar.
        assert "/cache/" in result.dest
        assert result.provenance_path.endswith(".meta.yml")
        meta_doc = yaml.safe_load(open(result.provenance_path))
        assert verify_document(meta_doc) is True
        assert meta_doc["credentialSubject"]["sha256"] == result.sha256
        # Index lists the metadata; query_show returns it.
        listed = query_ls(cache_dir)
        assert result.provenance_path in listed
        assert query_show(result.dest) is not None
        assert query_show(str(tmp_path / "nope")) is None

    def test_cache_copies_to_dest(self, tmp_path, ca_bundle):
        import shutil
        if shutil.which("curl") is None:
            pytest.skip("curl not available")
        src = tmp_path / "artifact.bin"
        src.write_bytes(b"copy me")
        dest = tmp_path / "out" / "copy.bin"
        cache_dir = str(tmp_path / "cache")
        env = {"CURL_CA_BUNDLE": str(ca_bundle)}
        result = fetch(
            src.as_uri(),
            str(dest),
            strategy="curl",
            environ=env,
            candidates=(),
            cache=True,
            cache_dir=cache_dir,
        )
        assert dest.exists()
        assert dest.read_bytes() == b"copy me"
        assert "/cache/" in result.dest


class TestFetchRunner:
    def test_runner_registers_downloaded_artifact(self, tmp_path):
        import shutil
        if shutil.which("curl") is None:
            pytest.skip("curl not available")
        from tert.run_tests import FetchRunner
        src = tmp_path / "src.txt"
        src.write_text("runner payload")
        out = tmp_path / "report"
        runner = FetchRunner(out)
        rc = runner.run(src.as_uri())
        assert rc == 0
        names = {p.name for p in runner.get_artifacts()}
        assert "src.txt" in names
        assert "build.log" in names
        # The downloaded file landed in the report dir.
        assert (out / "src.txt").exists()

    def test_runner_in_known_runners(self):
        from tert.run_tests import get_runner, FetchRunner
        assert isinstance(get_runner("fetch", Path("/tmp/x")), FetchRunner)

    def test_fetch_records_run_and_artifact_by_default(self, tmp_path):
        import shutil
        if shutil.which("curl") is None:
            pytest.skip("curl not available")
        from tert.fetch import main as fetch_main
        from tert.run_tests import ReplogDB, query_runs, query_artifacts
        src = tmp_path / "logged.txt"
        src.write_text("log this download")
        reports = tmp_path / "reports"
        db = reports / "replog.db"
        dest = tmp_path / "out.txt"
        rc = fetch_main([
            "--reports-dir", str(reports),
            "--replog-db", str(db),
            src.as_uri(),
            str(dest),
        ])
        assert rc == 0
        runs = query_runs(ReplogDB(db))
        assert len(runs) == 1
        assert runs[0]["command"].startswith("fetch ")
        artifacts = {a["filename"] for a in query_artifacts(ReplogDB(db))}
        assert "out.txt" in artifacts

    def test_no_record_skips_replog(self, tmp_path):
        import shutil
        if shutil.which("curl") is None:
            pytest.skip("curl not available")
        from tert.fetch import main as fetch_main
        src = tmp_path / "plain.txt"
        src.write_text("no replog please")
        reports = tmp_path / "reports"
        dest = tmp_path / "out.txt"
        rc = fetch_main([
            "--no-record",
            "--reports-dir", str(reports),
            src.as_uri(),
            str(dest),
        ])
        assert rc == 0
        assert dest.exists()
        # No report directory created when recording is disabled.
        assert not reports.exists()

    def test_json_still_records(self, tmp_path, capsys):
        import shutil
        import json as _json
        if shutil.which("curl") is None:
            pytest.skip("curl not available")
        from tert.fetch import main as fetch_main
        from tert.run_tests import ReplogDB, query_runs
        src = tmp_path / "j.txt"
        src.write_text("json and record")
        reports = tmp_path / "reports"
        db = reports / "replog.db"
        dest = tmp_path / "out.txt"
        rc = fetch_main([
            "--json",
            "--reports-dir", str(reports),
            "--replog-db", str(db),
            src.as_uri(),
            str(dest),
        ])
        out = capsys.readouterr().out
        assert rc == 0
        # --json emitted the FetchResult ...
        payload = _json.loads(out)
        assert payload["downloaded"] is True
        assert payload["dest"].endswith("out.txt")
        # ... and the run was still recorded.
        assert len(query_runs(ReplogDB(db))) == 1



