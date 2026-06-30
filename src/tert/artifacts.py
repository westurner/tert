#!/usr/bin/env python3
"""
artifacts.py - YAML-LD / W3C-PROV artifact summaries for ``tert run``.

An *artifact summary* is a small Verifiable Credential / PROV ``prov:Entity``
recording an input or output file's ``path``, ``size`` and ``sha256`` (and,
optionally, whether a supplied checksum matched). Summaries are generated and
printed before the run (for ``--input`` files) and after the run (for produced
artifacts), stored as YAML-LD next to the report, and shown with
``tert query artifact-summaries``.

Summaries can optionally be DID-signed using the same cryptosuites as
``tert vc`` / ``tert fetch`` (Ed25519 today; ML-DSA-87 / Merkle Tree
Certificates as stubs).
"""

import os
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple

from .fetch import file_size, file_sha256
from . import vc

ARTIFACT_CONTEXT = [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/prov",
]

ARTIFACT_SUFFIXES = (".artifact.yml", ".artifact.yaml", ".artifact.json")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_checksum(text: str) -> Tuple[str, str]:
    """Parse a ``sha256:<hex>`` (or bare ``<hex>``) checksum string."""
    text = text.strip()
    if ":" in text:
        algo, value = text.split(":", 1)
        return algo.strip().lower(), value.strip().lower()
    return "sha256", text.lower()


def build_artifact_summary(
    path: str,
    role: str = "input",
    checksum: Optional[str] = None,
    now: Optional[str] = None,
) -> Dict[str, Any]:
    """Build an (unsigned) YAML-LD/PROV artifact summary for *path*.

    When *checksum* is given (``sha256:<hex>``), ``checksum_verified`` records
    whether the file's digest matched.
    """
    size = file_size(path)
    digest = file_sha256(path)
    subject: Dict[str, Any] = {
        "type": "prov:Entity",
        "role": role,
        "path": os.path.abspath(path),
        "filename": os.path.basename(path),
        "size": size,
        "sha256": digest,
    }
    if checksum is not None:
        algo, expected = parse_checksum(checksum)
        if algo != "sha256":
            raise ValueError("only sha256 checksums are supported, got %r" % algo)
        subject["checksum_algorithm"] = algo
        subject["checksum_expected"] = expected
        subject["checksum_verified"] = digest == expected
    return {
        "@context": ARTIFACT_CONTEXT,
        "type": ["VerifiableCredential", "prov:Entity"],
        "issuanceDate": now or utc_now_iso(),
        "credentialSubject": subject,
    }


def summary_text(doc: Dict[str, Any], fmt: str = "yaml") -> str:
    """Serialize a summary document as YAML (default) or JSON."""
    return vc.dump_document(doc, fmt)


def write_summary(doc: Dict[str, Any], out_dir: str, fmt: str = "yaml") -> str:
    """Write a summary into *out_dir* and return its path."""
    os.makedirs(out_dir, exist_ok=True)
    subject = doc["credentialSubject"]
    role = subject.get("role", "artifact")
    name = subject.get("filename", "artifact")
    ext = "yml" if fmt == "yaml" else "json"
    path = os.path.join(out_dir, "%s.%s.artifact.%s" % (name, role, ext))
    text = summary_text(doc, fmt)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text if text.endswith("\n") else text + "\n")
    return path


def iter_summaries(directory: str) -> List[Tuple[str, Dict[str, Any]]]:
    """Load all artifact summaries in *directory* (sorted by filename)."""
    out: List[Tuple[str, Dict[str, Any]]] = []
    if not os.path.isdir(directory):
        return out
    for name in sorted(os.listdir(directory)):
        if name.endswith(ARTIFACT_SUFFIXES):
            path = os.path.join(directory, name)
            doc, _ = vc.load_document(path)
            out.append((path, doc))
    return out


def maybe_sign(
    doc: Dict[str, Any],
    backend: Optional["vc.KeyBackend"],
    cryptosuite: str = vc.DEFAULT_CRYPTOSUITE,
) -> Dict[str, Any]:
    """Sign *doc* with *backend* if provided, else return it unchanged."""
    if backend is None:
        return doc
    return vc.sign_document(doc, backend, cryptosuite=cryptosuite)
