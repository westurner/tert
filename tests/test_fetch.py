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
    RustStrategy,
    WgetStrategy,
    basename_from_url,
    count_pem_certificates,
    detect_tls_backend,
    discover_ca_bundle,
    fetch,
    file_sha256,
    file_size,
    get_strategy,
    main,
    resolve_strategy_name,
    verify_crypto_config,
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
