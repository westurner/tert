#!/usr/bin/env python3
"""
vc.py - sign and verify Verifiable Credential (VC) / YAML-LD documents.

This module provides the signing foundation shared by ``tert fetch`` provenance,
artifact summaries, and the standalone ``tert vc`` CLI:

    - Deterministic canonicalization (a JCS-style subset: sorted keys, compact,
      ``ensure_ascii``) used as the signing payload. The Python and Rust
      (``tert::vc``) implementations produce byte-identical canonical bytes.
    - A pluggable *cryptosuite* abstraction:
        * ``eddsa-jcs-2022``   - Ed25519 over canonical JSON (implemented)
        * ``mldsa-87-p256``    - post-quantum hybrid ML-DSA-87 + ECDSA-P256 (stub)
        * ``merkle-tree-certs``- Merkle Tree Certificates (stub)
    - Key backends: a did-agent (key in memory) or an on-disk Ed25519 key.

Documents are W3C Verifiable Credentials with a ``DataIntegrityProof``. Both
JSON and YAML (YAML-LD) serializations are supported.
"""

import os
import sys
import json
import base64
import logging
import argparse
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Sequence, Mapping, Tuple

from .crypto import (
    ed25519_publickey,
    ed25519_sign,
    ed25519_verify,
    did_key_from_pubkey,
    pubkey_from_did_key,
)

logger = logging.getLogger(__name__)

DEFAULT_CRYPTOSUITE = "eddsa-jcs-2022"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Canonicalization (JCS-style subset)
# ---------------------------------------------------------------------------


def canonicalize(obj: Any) -> bytes:
    """Deterministic canonical JSON bytes used as the signing payload.

    Sorted object keys, compact separators, and ``ensure_ascii`` escaping so the
    bytes are identical regardless of platform or language (the Rust port
    reproduces these exact bytes).
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# Key backends
# ---------------------------------------------------------------------------


class KeyBackend:
    """A signing key abstraction: produces a ``did:key`` and Ed25519 signatures."""

    kind = "base"

    def did(self) -> str:
        raise NotImplementedError

    def sign(self, data: bytes) -> bytes:
        raise NotImplementedError


class AgentKeyBackend(KeyBackend):
    """Signs through a running did-agent; the private key never touches disk."""

    kind = "agent"

    def __init__(self, client) -> None:
        self._client = client
        self._did: Optional[str] = None

    def did(self) -> str:
        if self._did is None:
            self._did = self._client.did()
        return self._did

    def sign(self, data: bytes) -> bytes:
        return self._client.sign(data)


class FileKeyBackend(KeyBackend):
    """Signs with an Ed25519 seed stored on disk (less secure fallback)."""

    kind = "file"

    def __init__(self, seed: bytes) -> None:
        self._seed = seed
        self._pubkey = ed25519_publickey(seed)
        self._did = did_key_from_pubkey(self._pubkey)

    def did(self) -> str:
        return self._did

    def sign(self, data: bytes) -> bytes:
        return ed25519_sign(self._seed, data, self._pubkey)

    @classmethod
    def load_or_create(cls, keys_dir: str) -> "FileKeyBackend":
        os.makedirs(keys_dir, exist_ok=True)
        try:
            os.chmod(keys_dir, 0o700)
        except OSError:
            pass
        key_path = os.path.join(keys_dir, "did_ed25519.key")
        if os.path.exists(key_path):
            with open(key_path, "r", encoding="ascii") as fh:
                seed = base64.b64decode(fh.read().strip())
        else:
            seed = os.urandom(32)
            old_umask = os.umask(0o077)
            try:
                with open(key_path, "w", encoding="ascii") as fh:
                    fh.write(base64.b64encode(seed).decode("ascii"))
            finally:
                os.umask(old_umask)
            try:
                os.chmod(key_path, 0o600)
            except OSError:
                pass
        return cls(seed)


def resolve_key_backend(
    environ: Optional[Mapping[str, str]] = None,
    keys_dir: Optional[str] = None,
    allow_file: bool = True,
    log: Optional[logging.Logger] = None,
) -> Optional[KeyBackend]:
    """Pick a signing backend: a running did-agent if available, else on-disk."""
    env = environ if environ is not None else os.environ
    log = log or logger
    sock = env.get("DID_AGENT_SOCK")
    if sock:
        try:
            from .did_agent import DidAgentClient

            client = DidAgentClient(sock)
            client.ping()
            return AgentKeyBackend(client)
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("did-agent at %s unavailable (%s)", sock, exc)
    if allow_file and keys_dir:
        log.warning(
            "signing with an on-disk key in %s; prefer a did-agent (set DID_AGENT_SOCK)",
            keys_dir,
        )
        return FileKeyBackend.load_or_create(keys_dir)
    return None


# ---------------------------------------------------------------------------
# Cryptosuites
# ---------------------------------------------------------------------------


class CryptosuiteError(Exception):
    """Raised when a cryptosuite operation is unsupported or fails."""


class Cryptosuite:
    name = "base"
    available = False

    def sign(self, payload: bytes, signer: KeyBackend) -> str:
        raise NotImplementedError

    def verify(self, payload: bytes, proof_value: str, issuer_did: str) -> bool:
        raise NotImplementedError


class EddsaJcs2022(Cryptosuite):
    """Ed25519 signatures over canonical JSON (W3C ``eddsa-jcs-2022``)."""

    name = "eddsa-jcs-2022"
    available = True

    def sign(self, payload: bytes, signer: KeyBackend) -> str:
        return base64.b64encode(signer.sign(payload)).decode("ascii")

    def verify(self, payload: bytes, proof_value: str, issuer_did: str) -> bool:
        pubkey = pubkey_from_did_key(issuer_did)
        sig = base64.b64decode(proof_value)
        return ed25519_verify(pubkey, payload, sig)


class MldsaP256Stub(Cryptosuite):
    """Post-quantum hybrid ML-DSA-87 + ECDSA-P256 (stub; not yet implemented)."""

    name = "mldsa-87-p256"
    available = False

    def sign(self, payload: bytes, signer: KeyBackend) -> str:
        raise CryptosuiteError(
            "cryptosuite 'mldsa-87-p256' is a stub: ML-DSA-87 (FIPS 204) post-quantum "
            "signing is not yet implemented"
        )

    def verify(self, payload: bytes, proof_value: str, issuer_did: str) -> bool:
        raise CryptosuiteError("cryptosuite 'mldsa-87-p256' verification is a stub")


class MerkleTreeCertsStub(Cryptosuite):
    """Merkle Tree Certificates (stub; planned)."""

    name = "merkle-tree-certs"
    available = False

    def sign(self, payload: bytes, signer: KeyBackend) -> str:
        raise CryptosuiteError(
            "cryptosuite 'merkle-tree-certs' is a stub: Merkle Tree Certificates are "
            "not yet implemented"
        )

    def verify(self, payload: bytes, proof_value: str, issuer_did: str) -> bool:
        raise CryptosuiteError("cryptosuite 'merkle-tree-certs' verification is a stub")


CRYPTOSUITES: Dict[str, Cryptosuite] = {
    suite.name: suite
    for suite in (EddsaJcs2022(), MldsaP256Stub(), MerkleTreeCertsStub())
}


def get_cryptosuite(name: str) -> Cryptosuite:
    try:
        return CRYPTOSUITES[name]
    except KeyError:
        raise CryptosuiteError(
            "unknown cryptosuite: %s (known: %s)" % (name, ", ".join(sorted(CRYPTOSUITES)))
        )


# ---------------------------------------------------------------------------
# Document signing / verification
# ---------------------------------------------------------------------------


def sign_document(
    doc: Dict[str, Any],
    signer: KeyBackend,
    cryptosuite: str = DEFAULT_CRYPTOSUITE,
    created: Optional[str] = None,
) -> Dict[str, Any]:
    """Return a copy of *doc* with a ``DataIntegrityProof`` over canonical JSON."""
    suite = get_cryptosuite(cryptosuite)
    base = {k: v for k, v in doc.items() if k != "proof"}
    base["issuer"] = signer.did()
    payload = canonicalize(base)
    proof_value = suite.sign(payload, signer)
    did = signer.did()
    out = dict(base)
    out["proof"] = {
        "type": "DataIntegrityProof",
        "cryptosuite": suite.name,
        "created": created or utc_now_iso(),
        "proofPurpose": "assertionMethod",
        "verificationMethod": did + "#" + did[len("did:key:"):],
        "proofValue": proof_value,
    }
    return out


def verify_document(doc: Dict[str, Any]) -> bool:
    """Verify the ``DataIntegrityProof`` on a VC document."""
    proof = doc.get("proof")
    if not isinstance(proof, dict) or "proofValue" not in proof:
        return False
    suite = CRYPTOSUITES.get(proof.get("cryptosuite", ""))
    if suite is None:
        return False
    issuer = doc.get("issuer")
    if not issuer:
        return False
    base = {k: v for k, v in doc.items() if k != "proof"}
    payload = canonicalize(base)
    try:
        return suite.verify(payload, proof["proofValue"], issuer)
    except CryptosuiteError:
        return False
    except Exception:  # pragma: no cover - defensive
        return False


# ---------------------------------------------------------------------------
# JSON / YAML / TOML document IO
# ---------------------------------------------------------------------------

# Provisional TOML embedding for W3C Verifiable Credentials: a VC is stored
# under this top-level TOML table. The whole VC data model lives inside it so
# the same credential canonicalizes identically across JSON, YAML and TOML.
# (Provisional: this key may change if a standard embedding is registered.)
TOML_VC_SECTION = "verifiableCredential"


def _detect_format(path: str, explicit: Optional[str] = None) -> str:
    if explicit:
        return explicit
    lowered = path.lower()
    if lowered.endswith((".yaml", ".yml")):
        return "yaml"
    if lowered.endswith(".toml"):
        return "toml"
    return "json"


def _toml_escape_str(value: str) -> str:
    out = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return '"' + "".join(
        c if ord(c) >= 0x20 else "\\u%04x" % ord(c) for c in out
    ) + '"'


def _toml_key(key: str) -> str:
    if key and all(c.isalnum() or c in "_-" for c in key) and key.isascii():
        return key
    return _toml_escape_str(key)


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, str):
        return _toml_escape_str(value)
    if value is None:
        raise CryptosuiteError("TOML cannot represent a null value")
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    if isinstance(value, dict):
        inner = ", ".join(
            "%s = %s" % (_toml_key(k), _toml_value(v)) for k, v in value.items()
        )
        return "{" + inner + "}"
    raise CryptosuiteError("unsupported TOML value type: %r" % type(value))


def _toml_dump(doc: Dict[str, Any], section: str = TOML_VC_SECTION) -> str:
    lines = ["[%s]" % section]
    for key, value in doc.items():
        lines.append("%s = %s" % (_toml_key(key), _toml_value(value)))
    return "\n".join(lines) + "\n"


def _toml_load(text: str, section: str = TOML_VC_SECTION) -> Dict[str, Any]:
    import tomllib

    data = tomllib.loads(text)
    if isinstance(data.get(section), dict):
        return data[section]
    return data


def load_document(path: str, fmt: Optional[str] = None) -> Tuple[Dict[str, Any], str]:
    """Load a VC document from a JSON, YAML or TOML file. Returns ``(doc, fmt)``."""
    fmt = _detect_format(path, fmt)
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    if fmt == "yaml":
        try:
            import yaml
        except ImportError:
            raise CryptosuiteError("PyYAML is required to read YAML documents")
        return yaml.safe_load(text), "yaml"
    if fmt == "toml":
        return _toml_load(text), "toml"
    return json.loads(text), "json"


def dump_document(doc: Dict[str, Any], fmt: str = "json") -> str:
    """Serialize a VC document as JSON (default), YAML or TOML."""
    if fmt == "yaml":
        try:
            import yaml
        except ImportError:
            raise CryptosuiteError("PyYAML is required to write YAML documents")
        return yaml.safe_dump(doc, sort_keys=True, default_flow_style=False)
    if fmt == "toml":
        return _toml_dump(doc)
    return json.dumps(doc, indent=2, sort_keys=True)


# ---------------------------------------------------------------------------
# CLI: tert vc
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tert vc",
        description="Sign and verify Verifiable Credential (JSON/YAML-LD/TOML) documents",
    )
    sub = parser.add_subparsers(dest="action", required=True)

    sign_p = sub.add_parser("sign", help="Sign a VC document")
    sign_p.add_argument("file", help="JSON, YAML or TOML document to sign")
    sign_p.add_argument("--cryptosuite", default=DEFAULT_CRYPTOSUITE,
                        help="cryptosuite (default: %s)" % DEFAULT_CRYPTOSUITE)
    sign_p.add_argument("--sock", help="did-agent socket path")
    sign_p.add_argument("--keys-dir", help="on-disk key directory fallback")
    sign_p.add_argument("--format", choices=["json", "yaml", "toml"], help="output format")
    sign_p.add_argument("-o", "--output", help="output file (default: stdout)")

    verify_p = sub.add_parser("verify", help="Verify a VC document")
    verify_p.add_argument("file", help="JSON or YAML document to verify")

    list_p = sub.add_parser("cryptosuites", help="List available cryptosuites")
    list_p.add_argument("--json", action="store_true", help="emit JSON")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.action == "cryptosuites":
        rows = [{"name": s.name, "available": s.available} for s in CRYPTOSUITES.values()]
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            for row in rows:
                print("%-20s %s" % (row["name"], "available" if row["available"] else "stub"))
        return 0

    if args.action == "sign":
        try:
            doc, in_fmt = load_document(args.file)
            sock = args.sock or os.environ.get("DID_AGENT_SOCK")
            environ = dict(os.environ)
            if sock:
                environ["DID_AGENT_SOCK"] = sock
            backend = resolve_key_backend(environ, args.keys_dir, log=logger)
            if backend is None:
                logger.error("no signing key available (run a did-agent or pass --keys-dir)")
                return 1
            signed = sign_document(doc, backend, cryptosuite=args.cryptosuite)
        except CryptosuiteError as exc:
            logger.error("%s", exc)
            return 2
        out_fmt = args.format or in_fmt
        text = dump_document(signed, out_fmt)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(text if text.endswith("\n") else text + "\n")
            logger.info("wrote signed document %s (issuer %s)", args.output, signed["issuer"])
        else:
            print(text)
        return 0

    if args.action == "verify":
        doc, _ = load_document(args.file)
        ok = verify_document(doc)
        print("verify: %s" % ("OK" if ok else "FAILED"))
        return 0 if ok else 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
