#!/usr/bin/env python3
"""
fetch.py - ``tert fetch``: download a URL with a selectable strategy.

Strategies:
    - ``curl``  : download with ``curl`` (default when available)
    - ``wget``  : download with ``wget``
    - ``rust``  : native rustls-based downloader (stub; not yet implemented)

For every strategy, ``tert fetch`` discovers, logs, and verifies the active TLS
crypto configuration that the strategy would use to fetch over HTTPS:

    - the TLS backend (OpenSSL / GnuTLS / rustls / ...)
    - the CA certificate bundle path and where it came from (env / system default)
    - the CA bundle size, certificate count, and sha256 digest

This makes the trust anchors of a download auditable and lets a download be
refused when the crypto configuration cannot be verified.

Usage:
    tert fetch <url> [<dest>]
    tert fetch --curl <url>
    tert fetch --wget <url>
    tert fetch --rust <url>          # stub: prints/verifies config, no download
    tert fetch --crypto-only [--curl|--wget|--rust]
"""

import os
import sys
import json
import shutil
import hashlib
import logging
import argparse
import subprocess
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Sequence, Mapping

logger = logging.getLogger(__name__)
if not logger.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(_handler)


# ---------------------------------------------------------------------------
# CA certificate bundle discovery
# ---------------------------------------------------------------------------

#: Common system CA bundle locations, in priority order.
CA_BUNDLE_CANDIDATES: Sequence[str] = (
    "/etc/pki/tls/certs/ca-bundle.crt",        # Fedora / RHEL (OpenSSL default)
    "/etc/ssl/certs/ca-certificates.crt",      # Debian / Ubuntu / Alpine
    "/etc/ssl/cert.pem",                       # OpenBSD / macOS / OpenSSL
    "/etc/pki/tls/cert.pem",                   # RHEL alternate
    "/etc/ssl/ca-bundle.pem",                  # openSUSE
    "/usr/local/share/certs/ca-root-nss.crt",  # FreeBSD
)

#: Environment variables consulted for an explicit CA bundle, per strategy.
CA_BUNDLE_ENV_VARS: Mapping[str, Sequence[str]] = {
    "curl": ("CURL_CA_BUNDLE", "SSL_CERT_FILE"),
    "wget": ("SSL_CERT_FILE",),
    "rust": ("SSL_CERT_FILE",),
}

_PEM_CERT_MARKER = "-----BEGIN CERTIFICATE-----"


def file_size(path: str) -> Optional[int]:
    """Return the size of *path* in bytes, or None if it cannot be stat'd."""
    try:
        return os.path.getsize(path)
    except OSError:
        return None


def file_sha256(path: str) -> Optional[str]:
    """Return the lowercase hex sha256 of *path*, or None on error."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def count_pem_certificates(path: str) -> Optional[int]:
    """Count ``BEGIN CERTIFICATE`` markers in a PEM bundle, or None on error."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().count(_PEM_CERT_MARKER)
    except OSError:
        return None


def discover_ca_bundle(
    env_vars: Sequence[str],
    environ: Optional[Mapping[str, str]] = None,
    candidates: Sequence[str] = CA_BUNDLE_CANDIDATES,
) -> "tuple[Optional[str], str]":
    """Discover the CA bundle path for a strategy.

    Returns ``(path, source)`` where *source* is one of:
        - ``"env:<NAME>"`` if an environment variable specified the path
        - ``"candidate"``  if a known system path was found to exist
        - ``"none"``       if no bundle could be located

    An env var wins even if the path it points at does not exist, so that a
    misconfigured override is surfaced by verification rather than silently
    falling back to a system default.
    """
    env = environ if environ is not None else os.environ
    for name in env_vars:
        value = env.get(name)
        if value:
            return value, "env:" + name
    for cand in candidates:
        if os.path.isfile(cand):
            return cand, "candidate"
    return None, "none"


# ---------------------------------------------------------------------------
# Crypto configuration
# ---------------------------------------------------------------------------


@dataclass
class CryptoConfig:
    """The TLS crypto configuration a strategy would use for an HTTPS fetch."""

    strategy: str
    available: bool = False
    downloader_path: Optional[str] = None
    downloader_version: Optional[str] = None
    tls_backend: Optional[str] = None
    ca_bundle_path: Optional[str] = None
    ca_bundle_source: Optional[str] = None
    ca_bundle_exists: bool = False
    ca_bundle_size: Optional[int] = None
    ca_bundle_cert_count: Optional[int] = None
    ca_bundle_sha256: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


#: Recognised TLS backend tokens (case-insensitive), longest first so that
#: e.g. ``BoringSSL`` is matched before ``SSL``.
_TLS_BACKENDS = (
    "LibreSSL",
    "BoringSSL",
    "OpenSSL",
    "GnuTLS",
    "wolfSSL",
    "mbedTLS",
    "Schannel",
    "SecureTransport",
    "rustls",
    "NSS",
)


def detect_tls_backend(version_text: Optional[str]) -> Optional[str]:
    """Return the canonical TLS backend name found in a ``--version`` string."""
    if not version_text:
        return None
    lowered = version_text.lower()
    for name in _TLS_BACKENDS:
        if name.lower() in lowered:
            return name
    return None


def verify_crypto_config(cfg: CryptoConfig) -> "tuple[bool, List[str]]":
    """Verify a crypto configuration.

    Returns ``(ok, problems)``. ``ok`` is True only when a TLS backend is known
    and a non-empty CA bundle containing at least one certificate is present.
    """
    problems: List[str] = []
    if cfg.tls_backend is None:
        problems.append("TLS backend could not be determined")
    if not cfg.ca_bundle_path:
        problems.append("no CA certificate bundle configured")
    elif not cfg.ca_bundle_exists:
        problems.append("CA bundle path does not exist: %s" % cfg.ca_bundle_path)
    elif not cfg.ca_bundle_size:
        problems.append("CA bundle is empty: %s" % cfg.ca_bundle_path)
    elif cfg.ca_bundle_cert_count == 0:
        problems.append("CA bundle contains no certificates: %s" % cfg.ca_bundle_path)
    return (not problems), problems


def log_crypto_config(cfg: CryptoConfig, log: Optional[logging.Logger] = None) -> None:
    """Emit the crypto configuration to *log* at INFO level."""
    log = log or logger
    log.info("fetch strategy: %s (available=%s)", cfg.strategy, cfg.available)
    log.info("  downloader: %s", cfg.downloader_path or "<none>")
    if cfg.downloader_version:
        log.info("  version:    %s", cfg.downloader_version)
    log.info("  tls backend: %s", cfg.tls_backend or "<unknown>")
    log.info(
        "  ca bundle:   %s (source=%s)",
        cfg.ca_bundle_path or "<none>",
        cfg.ca_bundle_source or "none",
    )
    if cfg.ca_bundle_exists:
        log.info(
            "  ca bundle:   size=%s bytes, certs=%s, sha256=%s",
            cfg.ca_bundle_size,
            cfg.ca_bundle_cert_count,
            cfg.ca_bundle_sha256,
        )
    for note in cfg.notes:
        log.info("  note: %s", note)


# ---------------------------------------------------------------------------
# Fetch result
# ---------------------------------------------------------------------------


class FetchError(Exception):
    """Raised when a fetch cannot be performed (e.g. crypto verification failed)."""


@dataclass
class FetchResult:
    url: str
    dest: Optional[str]
    strategy: str
    crypto_config: CryptoConfig
    crypto_ok: bool
    crypto_problems: List[str] = field(default_factory=list)
    downloaded: bool = False
    exit_code: int = 0
    sha256: Optional[str] = None
    bytes_written: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["crypto_config"] = self.crypto_config.to_dict()
        return d


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------


def basename_from_url(url: str) -> str:
    """Best-effort output filename derived from a URL."""
    name = url.split("?", 1)[0].split("#", 1)[0]
    name = name.rsplit("/", 1)[-1]
    return name or "index.html"


class FetchStrategy:
    """Base class for download strategies."""

    name = "base"
    env_vars: Sequence[str] = ("SSL_CERT_FILE",)

    def __init__(
        self,
        environ: Optional[Mapping[str, str]] = None,
        candidates: Sequence[str] = CA_BUNDLE_CANDIDATES,
    ) -> None:
        self.environ = environ if environ is not None else os.environ
        self.candidates = candidates

    # -- introspection ------------------------------------------------------

    def executable(self) -> Optional[str]:
        """Return the absolute path to the downloader, or None if unavailable."""
        return None

    def version_text(self, exe: str) -> Optional[str]:
        """Return the raw ``--version`` output of the downloader."""
        try:
            proc = subprocess.run(
                [exe, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return (proc.stdout or "") + (proc.stderr or "")

    def tls_backend(self, version_text: Optional[str]) -> Optional[str]:
        return detect_tls_backend(version_text)

    def crypto_config(self) -> CryptoConfig:
        """Discover the TLS crypto configuration for this strategy."""
        cfg = CryptoConfig(strategy=self.name)
        exe = self.executable()
        cfg.downloader_path = exe
        cfg.available = exe is not None
        version_text = self.version_text(exe) if exe else None
        if version_text:
            cfg.downloader_version = version_text.strip().splitlines()[0]
        cfg.tls_backend = self.tls_backend(version_text)

        path, source = discover_ca_bundle(self.env_vars, self.environ, self.candidates)
        cfg.ca_bundle_path = path
        cfg.ca_bundle_source = source
        if path and os.path.isfile(path):
            cfg.ca_bundle_exists = True
            cfg.ca_bundle_size = file_size(path)
            cfg.ca_bundle_cert_count = count_pem_certificates(path)
            cfg.ca_bundle_sha256 = file_sha256(path)
        return cfg

    # -- download -----------------------------------------------------------

    def download(self, url: str, dest: str, cfg: CryptoConfig) -> int:
        raise NotImplementedError


class CurlStrategy(FetchStrategy):
    name = "curl"
    env_vars = ("CURL_CA_BUNDLE", "SSL_CERT_FILE")

    def executable(self) -> Optional[str]:
        return shutil.which("curl")

    def build_command(self, url: str, part: str, cfg: CryptoConfig) -> List[str]:
        cmd = ["curl", "-fsSL", "--proto", "=https,http,file"]
        if cfg.ca_bundle_path and cfg.ca_bundle_exists:
            cmd += ["--cacert", cfg.ca_bundle_path]
        cmd += ["-o", part, url]
        return cmd

    def download(self, url: str, dest: str, cfg: CryptoConfig) -> int:
        exe = self.executable()
        if not exe:
            raise FetchError("curl is not available")
        part = dest + ".part"
        cmd = self.build_command(url, part, cfg)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True)
        except OSError as exc:
            raise FetchError("curl invocation failed: %s" % exc)
        if proc.returncode != 0:
            _cleanup(part)
            raise FetchError(
                "curl failed (exit %d): %s" % (proc.returncode, (proc.stderr or "").strip())
            )
        os.replace(part, dest)
        return 0


class WgetStrategy(FetchStrategy):
    name = "wget"
    env_vars = ("SSL_CERT_FILE",)

    def executable(self) -> Optional[str]:
        return shutil.which("wget")

    def build_command(self, url: str, part: str, cfg: CryptoConfig) -> List[str]:
        cmd = ["wget", "-q", "-O", part]
        if cfg.ca_bundle_path and cfg.ca_bundle_exists:
            cmd.append("--ca-certificate=" + cfg.ca_bundle_path)
        cmd.append(url)
        return cmd

    def download(self, url: str, dest: str, cfg: CryptoConfig) -> int:
        exe = self.executable()
        if not exe:
            raise FetchError("wget is not available")
        part = dest + ".part"
        cmd = self.build_command(url, part, cfg)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True)
        except OSError as exc:
            raise FetchError("wget invocation failed: %s" % exc)
        if proc.returncode != 0:
            _cleanup(part)
            raise FetchError(
                "wget failed (exit %d): %s" % (proc.returncode, (proc.stderr or "").strip())
            )
        os.replace(part, dest)
        return 0


class RustStrategy(FetchStrategy):
    """Native rustls-based downloader (stub; not yet implemented).

    The crypto configuration is still reported and verifiable so that the
    intended trust anchors can be audited ahead of the implementation.
    """

    name = "rust"
    env_vars = ("SSL_CERT_FILE",)

    def executable(self) -> Optional[str]:
        return None

    def crypto_config(self) -> CryptoConfig:
        cfg = super().crypto_config()
        cfg.tls_backend = "rustls"
        cfg.notes.append("native rust fetch strategy is a stub; not yet implemented")
        cfg.notes.append("planned: rustls with rustls-native-certs over the system CA bundle")
        return cfg

    def download(self, url: str, dest: str, cfg: CryptoConfig) -> int:
        raise NotImplementedError("the rust fetch strategy is not yet implemented (stub)")


_STRATEGIES = {
    "curl": CurlStrategy,
    "wget": WgetStrategy,
    "rust": RustStrategy,
}


def _cleanup(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def get_strategy(
    name: str,
    environ: Optional[Mapping[str, str]] = None,
    candidates: Sequence[str] = CA_BUNDLE_CANDIDATES,
) -> FetchStrategy:
    """Instantiate a strategy by name (``curl`` / ``wget`` / ``rust``)."""
    try:
        cls = _STRATEGIES[name]
    except KeyError:
        raise FetchError("unknown fetch strategy: %s" % name)
    return cls(environ=environ, candidates=candidates)


def resolve_strategy_name(
    requested: str,
    environ: Optional[Mapping[str, str]] = None,
    candidates: Sequence[str] = CA_BUNDLE_CANDIDATES,
) -> str:
    """Resolve ``"auto"`` to the first available real downloader."""
    if requested != "auto":
        return requested
    for name in ("curl", "wget"):
        if get_strategy(name, environ, candidates).executable():
            return name
    return "curl"


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def fetch(
    url: str,
    dest: Optional[str] = None,
    strategy: str = "auto",
    *,
    verify: bool = True,
    overwrite: bool = False,
    environ: Optional[Mapping[str, str]] = None,
    candidates: Sequence[str] = CA_BUNDLE_CANDIDATES,
    download: bool = True,
    log: Optional[logging.Logger] = None,
) -> FetchResult:
    """Fetch *url* with the selected strategy after verifying its crypto config.

    When *verify* is True and the crypto configuration cannot be verified, the
    download is refused and :class:`FetchError` is raised.
    """
    log = log or logger
    name = resolve_strategy_name(strategy, environ, candidates)
    strat = get_strategy(name, environ, candidates)

    cfg = strat.crypto_config()
    log_crypto_config(cfg, log)
    crypto_ok, problems = verify_crypto_config(cfg)
    for problem in problems:
        log.warning("crypto verify: %s", problem)

    result = FetchResult(
        url=url,
        dest=dest,
        strategy=name,
        crypto_config=cfg,
        crypto_ok=crypto_ok,
        crypto_problems=problems,
    )

    if not download:
        return result

    if verify and not crypto_ok:
        raise FetchError(
            "refusing to fetch %s: crypto configuration could not be verified (%s)"
            % (url, "; ".join(problems))
        )

    target = dest or basename_from_url(url)
    result.dest = target
    if os.path.exists(target) and not overwrite:
        raise FetchError("destination exists (use --overwrite): %s" % target)

    parent = os.path.dirname(os.path.abspath(target))
    os.makedirs(parent, exist_ok=True)

    result.exit_code = strat.download(url, target, cfg)
    result.downloaded = True
    result.bytes_written = file_size(target)
    result.sha256 = file_sha256(target)
    log.info("saved %s (%s bytes, sha256=%s)", target, result.bytes_written, result.sha256)
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tert fetch",
        description="Download a URL with a selectable strategy, verifying the "
        "TLS crypto configuration and CA certificate bundle.",
    )
    parser.add_argument("url", nargs="?", help="URL to fetch")
    parser.add_argument("dest", nargs="?", help="Destination path")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--curl", action="store_const", dest="strategy", const="curl",
                       help="Use the curl strategy")
    group.add_argument("--wget", action="store_const", dest="strategy", const="wget",
                       help="Use the wget strategy")
    group.add_argument("--rust", action="store_const", dest="strategy", const="rust",
                       help="Use the rust strategy (stub; not yet implemented)")
    parser.add_argument("--strategy", dest="strategy",
                        choices=["auto", "curl", "wget", "rust"],
                        help="Explicit strategy (default: auto)")
    parser.add_argument("--crypto-only", action="store_true",
                        help="Only discover, log and verify the crypto config")
    parser.add_argument("--no-verify-crypto", action="store_true",
                        help="Do not refuse the download if crypto cannot be verified")
    parser.add_argument("--overwrite", action="store_true",
                        help="Overwrite an existing destination")
    parser.add_argument("--json", action="store_true",
                        help="Emit the result as JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    logger.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    strategy = args.strategy or "auto"

    if args.crypto_only:
        name = resolve_strategy_name(strategy)
        cfg = get_strategy(name).crypto_config()
        log_crypto_config(cfg)
        ok, problems = verify_crypto_config(cfg)
        if args.json:
            print(json.dumps({"crypto_config": cfg.to_dict(), "ok": ok,
                              "problems": problems}, indent=2))
        else:
            print("crypto verify: %s" % ("OK" if ok else "FAILED"))
            for problem in problems:
                print("  - %s" % problem)
        return 0 if ok else 1

    if not args.url:
        parser.error("a URL is required (or use --crypto-only)")

    try:
        result = fetch(
            args.url,
            args.dest,
            strategy=strategy,
            verify=not args.no_verify_crypto,
            overwrite=args.overwrite,
        )
    except NotImplementedError as exc:
        logger.error("%s", exc)
        return 2
    except FetchError as exc:
        logger.error("%s", exc)
        return 1

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
