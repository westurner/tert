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
import re
import subprocess
from datetime import datetime, timezone
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


# curl -v prints e.g. "* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384".
_TLS_CONN_RE = re.compile(r"SSL connection using (\S+)\s*/\s*([A-Za-z0-9_\-]+)")
# Fallbacks for other downloaders / formats.
_TLS_VERSION_RE = re.compile(r"\b(TLSv1\.[0-3]|TLSv1|TLS1\.[0-3]|SSLv3)\b")
_TLS_CIPHER_RE = re.compile(
    r"(?:cipher|Cipher|ciphersuite)[\s:=]+[\"']?([A-Za-z0-9_]+(?:[-_][A-Za-z0-9]+)*)"
)


def parse_tls_info(text: Optional[str]) -> "tuple[Optional[str], Optional[str]]":
    """Extract ``(tls_version, tls_cipher)`` from downloader verbose output.

    Recognises curl's ``SSL connection using <version> / <cipher>`` line and
    falls back to generic TLS-version / cipher patterns (e.g. wget/GnuTLS debug
    output). Returns ``(None, None)`` for non-TLS transfers such as ``file://``.
    """
    if not text:
        return None, None
    match = _TLS_CONN_RE.search(text)
    if match:
        return match.group(1), match.group(2)
    version = None
    cipher = None
    version_match = _TLS_VERSION_RE.search(text)
    if version_match:
        version = version_match.group(1)
    cipher_match = _TLS_CIPHER_RE.search(text)
    if cipher_match:
        cipher = cipher_match.group(1)
    return version, cipher


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
    provenance_path: Optional[str] = None
    signed_by: Optional[str] = None
    tls_version: Optional[str] = None
    tls_cipher: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["crypto_config"] = self.crypto_config.to_dict()
        return d


# ---------------------------------------------------------------------------
# Key backends and DID-signed provenance
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Key backends and document signing live in ``tert.vc``; re-exported here for
# backwards compatibility with existing imports from ``tert.fetch``.
from .vc import (  # noqa: E402
    KeyBackend,
    AgentKeyBackend,
    FileKeyBackend,
    resolve_key_backend,
    sign_document,
    verify_document,
    DEFAULT_CRYPTOSUITE,
)


def build_provenance(result: FetchResult) -> Dict[str, Any]:
    """Build an unsigned YAML-LD/JSON provenance document for a fetch result."""
    cfg = result.crypto_config
    return {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/prov",
        ],
        "type": ["VerifiableCredential", "prov:Entity"],
        "issuanceDate": _utc_now_iso(),
        "credentialSubject": {
            "type": "prov:Entity",
            "url": result.url,
            "dest": result.dest,
            "sha256": result.sha256,
            "bytes": result.bytes_written,
            "strategy": result.strategy,
            "tls_backend": cfg.tls_backend,
            "tls_version": result.tls_version,
            "tls_cipher": result.tls_cipher,
            "ca_bundle_path": cfg.ca_bundle_path,
            "ca_bundle_sha256": cfg.ca_bundle_sha256,
            "ca_bundle_cert_count": cfg.ca_bundle_cert_count,
        },
    }


def sign_provenance(
    prov: Dict[str, Any],
    backend: KeyBackend,
    cryptosuite: str = DEFAULT_CRYPTOSUITE,
) -> Dict[str, Any]:
    """Return a copy of *prov* with a DID DataIntegrityProof."""
    return sign_document(prov, backend, cryptosuite=cryptosuite)


def verify_provenance(prov: Dict[str, Any]) -> bool:
    """Verify the DID proof on a provenance document."""
    return verify_document(prov)


def verify_provenance_file(path: str) -> bool:
    """Load a provenance sidecar JSON file and verify its DID proof."""
    with open(path, "r", encoding="utf-8") as fh:
        return verify_provenance(json.load(fh))


def provenance_sidecar_path(dest: str) -> str:
    return dest + ".prov.json"


# ---------------------------------------------------------------------------
# Central cache + signed YAML-LD metadata + index (modeled on scripts/fetchc)
# ---------------------------------------------------------------------------


def default_cache_dir(environ: Optional[Mapping[str, str]] = None) -> str:
    """Central tert fetch cache directory (honors TERT_FETCH_CACHE_DIR / XDG)."""
    env = environ if environ is not None else os.environ
    explicit = env.get("TERT_FETCH_CACHE_DIR")
    if explicit:
        return explicit
    base = env.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "tert", "fetch")


def _url_host(url: str) -> str:
    """Best-effort host segment of a URL for cache namespacing."""
    rest = url.split("://", 1)[-1]
    host = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    host = host.split("@")[-1].split(":", 1)[0]
    return host or "local"


def cache_output_path(cache_dir: str, url: str) -> str:
    """Compute the cache path ``<cache_dir>/cache/<host>/<filename>`` for a URL."""
    return os.path.join(cache_dir, "cache", _url_host(url), basename_from_url(url))


def meta_sidecar_path(outpath: str) -> str:
    """Sidecar metadata path (``<outpath>.meta.yml``), as in fetchc."""
    return outpath + ".meta.yml"


def index_path(cache_dir: str) -> str:
    return os.path.join(cache_dir, "index.meta.yml")


def write_meta(outpath: str, prov: Dict[str, Any]) -> str:
    """Write the YAML-LD metadata document next to *outpath* and return its path."""
    meta = meta_sidecar_path(outpath)
    os.makedirs(os.path.dirname(os.path.abspath(meta)), exist_ok=True)
    from . import vc as _vc

    with open(meta, "w", encoding="utf-8") as fh:
        fh.write(_vc.dump_document(prov, "yaml"))
    return meta


def index_update(cache_dir: str, meta_path: str, url: str, sha256: Optional[str],
                 dest_path: str) -> None:
    """Append a reference to the central ``index.meta.yml`` (created if absent)."""
    import yaml

    os.makedirs(cache_dir, exist_ok=True)
    idx = index_path(cache_dir)
    data: Dict[str, Any] = {"filemetaschemaver": 1, "entries": []}
    if os.path.exists(idx):
        try:
            with open(idx, "r", encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh) or {}
            if isinstance(loaded, dict) and isinstance(loaded.get("entries"), list):
                data = loaded
        except OSError:
            pass
    data["entries"].append({
        "meta_path": meta_path,
        "source_url": url,
        "sha256": sha256,
        "dest_path": dest_path,
        "indexed_at": _utc_now_iso(),
    })
    with open(idx, "w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, sort_keys=True)


def query_ls(cache_dir: str) -> List[str]:
    """List all known metadata files (from the index and the cache tree)."""
    import yaml

    metas: set = set()
    idx = index_path(cache_dir)
    if os.path.exists(idx):
        try:
            with open(idx, "r", encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh) or {}
            for entry in loaded.get("entries", []) or []:
                if entry.get("meta_path"):
                    metas.add(entry["meta_path"])
        except OSError:
            pass
    cache_tree = os.path.join(cache_dir, "cache")
    for root, _dirs, files in os.walk(cache_tree):
        for name in files:
            if name.endswith(".meta.yml"):
                metas.add(os.path.join(root, name))
    return sorted(metas)


def query_show(path: str) -> Optional[str]:
    """Return the metadata text for an output path or a ``.meta.yml`` path."""
    meta = path if path.endswith(".meta.yml") else meta_sidecar_path(path)
    if not os.path.exists(meta):
        return None
    with open(meta, "r", encoding="utf-8") as fh:
        return fh.read()


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
        # Negotiated TLS parameters observed during the last download (if any).
        self.tls_version: Optional[str] = None
        self.tls_cipher: Optional[str] = None

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
        cmd = ["curl", "-fsSL", "-v", "--proto", "=https,http,file"]
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
        # curl -v prints the negotiated TLS parameters to stderr.
        self.tls_version, self.tls_cipher = parse_tls_info(proc.stderr)
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
        cmd = ["wget", "-d", "-O", part]
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
        # wget -d (debug) prints the negotiated TLS parameters to stderr.
        self.tls_version, self.tls_cipher = parse_tls_info(proc.stderr)
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
    sign: bool = False,
    keys_dir: Optional[str] = None,
    key_backend: Optional[KeyBackend] = None,
    cryptosuite: str = DEFAULT_CRYPTOSUITE,
    cache: bool = False,
    cache_dir: Optional[str] = None,
    log: Optional[logging.Logger] = None,
) -> FetchResult:
    """Fetch *url* with the selected strategy after verifying its crypto config.

    When *verify* is True and the crypto configuration cannot be verified, the
    download is refused and :class:`FetchError` is raised. When *sign* is True a
    DID-signed provenance sidecar (``<dest>.prov.json``) is written using a
    did-agent if available, else an on-disk key under *keys_dir*.
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

    # In cache mode the primary output goes into the central cache; an optional
    # dest receives a copy afterwards.
    final_dest = dest
    if cache:
        cache_dir = cache_dir or default_cache_dir(environ)
        target = cache_output_path(cache_dir, url)
    else:
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
    result.tls_version = strat.tls_version
    result.tls_cipher = strat.tls_cipher
    log.info("saved %s (%s bytes, sha256=%s)", target, result.bytes_written, result.sha256)
    if result.tls_cipher:
        log.info("tls: %s / %s", result.tls_version or "?", result.tls_cipher)

    # Resolve a signing backend once (shared by provenance + cache metadata).
    backend = None
    if sign or cache:
        backend = key_backend or resolve_key_backend(environ, keys_dir, log=log)

    prov = build_provenance(result)
    if backend is not None:
        prov = sign_provenance(prov, backend, cryptosuite)
        result.signed_by = backend.did()

    if cache:
        # Write YAML-LD metadata sidecar + central index, like fetchc.
        meta = write_meta(target, prov)
        index_update(cache_dir, meta, url, result.sha256, final_dest or target)
        result.provenance_path = meta
        log.info("wrote metadata %s", meta)
        if final_dest and os.path.abspath(final_dest) != os.path.abspath(target):
            if os.path.exists(final_dest) and not overwrite:
                raise FetchError("destination exists (use --overwrite): %s" % final_dest)
            os.makedirs(os.path.dirname(os.path.abspath(final_dest)), exist_ok=True)
            shutil.copy2(target, final_dest)
            log.info("copied cache -> %s", final_dest)
    elif sign:
        if backend is None:
            log.warning("signing requested but no key backend available; provenance unsigned")
        else:
            sidecar = provenance_sidecar_path(target)
            with open(sidecar, "w", encoding="utf-8") as fh:
                json.dump(prov, fh, indent=2)
            result.provenance_path = sidecar
            log.info("wrote signed provenance %s (issuer %s)", sidecar, backend.did())
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
    parser.add_argument("--sign", action="store_true",
                        help="Write a DID-signed provenance sidecar (<dest>.prov.json)")
    parser.add_argument("--cryptosuite", default=DEFAULT_CRYPTOSUITE,
                        help="signing cryptosuite (default: %s)" % DEFAULT_CRYPTOSUITE)
    parser.add_argument("--keys-dir",
                        help="On-disk key directory if no did-agent is available")
    parser.add_argument("--cache", action="store_true",
                        help="Store the download in the central cache with a signed .meta.yml")
    parser.add_argument("--cache-dir",
                        help="Central cache directory (default: $XDG_CACHE_HOME/tert/fetch)")
    parser.add_argument("--query", choices=["ls", "show"],
                        help="Query cached metadata: 'ls' lists, 'show <path>' prints a .meta.yml")
    parser.add_argument("--verify-file", metavar="PATH",
                        help="Verify a provenance sidecar JSON file and exit")
    parser.add_argument("--record", action=argparse.BooleanOptionalAction, default=True,
                        help="Record this fetch in the replog and register the downloaded "
                             "artifact (default: on; use --no-record to skip)")
    parser.add_argument("--reports-dir", default="reports",
                        help="Reports directory for recorded fetches")
    parser.add_argument("--replog-db", default="reports/replog.db",
                        help="Replog SQLite database path for recorded fetches")
    parser.add_argument("--json", action="store_true",
                        help="Emit the result as JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    return parser


def _strip_record_flags(argv: Sequence[str]) -> List[str]:
    """Remove the record-control flags so the rest can be replayed as fetch args."""
    out: List[str] = []
    skip = False
    for arg in argv:
        if skip:
            skip = False
            continue
        if arg in ("--record", "--no-record"):
            continue
        if arg in ("--reports-dir", "--replog-db"):
            skip = True
            continue
        if arg.startswith("--reports-dir=") or arg.startswith("--replog-db="):
            continue
        out.append(arg)
    return out


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    logger.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    strategy = args.strategy or "auto"

    if args.verify_file:
        ok = verify_provenance_file(args.verify_file)
        print("provenance verify: %s" % ("OK" if ok else "FAILED"))
        return 0 if ok else 1

    if args.query:
        cache_dir = args.cache_dir or default_cache_dir()
        if args.query == "ls":
            for meta in query_ls(cache_dir):
                print(meta)
            return 0
        # show
        if not args.url:
            parser.error("fetch --query show requires a path")
        text = query_show(args.url)
        if text is None:
            logger.error("no metadata found for %s", args.url)
            return 1
        print(text)
        return 0

    # Non-download actions (crypto-only / query / verify) are never recorded and
    # are handled below; an actual download is recorded by default (see --record).
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
            sign=args.sign,
            keys_dir=args.keys_dir,
            cryptosuite=args.cryptosuite,
            cache=args.cache,
            cache_dir=args.cache_dir,
        )
    except NotImplementedError as exc:
        logger.error("%s", exc)
        return 2
    except FetchError as exc:
        logger.error("%s", exc)
        return 1

    # Record the download in the replog by default (``--no-record`` to skip).
    if args.record:
        from pathlib import Path
        from .run_tests import record_run, ReplogDB

        artifact_paths = [p for p in (result.dest, result.provenance_path) if p]
        record_run(
            Path(args.reports_dir),
            ReplogDB(Path(args.replog_db)),
            command="fetch " + " ".join(_strip_record_flags(argv)),
            exit_code=result.exit_code,
            artifact_paths=artifact_paths,
            summary_sign=args.sign,
            keys_dir=args.keys_dir,
            cryptosuite=args.cryptosuite,
        )

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
