# AGENTS.md — `tert`

Guidance for AI agents working in `src/tert`. Keep changes minimal, tested, and
consistent with the patterns below.

## What this project is

`tert` (Test Execution Report Tracker) is a test-runner harness with timestamped
reports and a SQLite "replog", plus a software-supply-chain toolchain: `tert
fetch` (verified downloads with crypto/CA logging), a did-agent (ssh-agent-style
Ed25519 signer), and `tert vc` (Verifiable Credential signing with pluggable
cryptosuites).

It is a **dual-language** project: a Python package and a parallel Rust crate
that mirror each other. A PyO3 extension module (`tert._rust`) exists but only
exposes small helpers (`strip_ansi`, `has_ansi`) — the crypto is **not** bridged.

## Layout

- `src/tert/*.py` — Python package (`run_tests.py`, `shellwrap.py`, `fetch.py`,
  `crypto.py`, `did_agent.py`, `vc.py`, `pq.py`, `artifacts.py`).
- `src/*.rs` — Rust library modules, registered in `src/lib.rs` via `pub mod`
  (`run_tests.rs`, `shellwrap.rs`, `fetch.rs`, `crypto.rs`, `did_agent.rs`,
  `vc.rs`, `pq.rs`).
- `src/bin/*.rs` — Rust binaries (`run_tests`, `shellwrap`, `did-agent`, `vc`).
- `tests/` — pytest suite; `tests/fixtures/` holds cross-language fixtures.
- Console scripts and the maturin config live in `pyproject.toml`; Rust deps and
  `[[bin]]` entries in `Cargo.toml`.

## Build, test, run

```bash
# Python tests (set PYTEST_RUNNING to disable the runner's recursion guard)
PYTEST_RUNNING= python3 -m pytest -p no:cacheprovider -q
# focused + coverage
PYTEST_RUNNING= python3 -m pytest -q tests/test_pq.py --cov=tert.pq --cov-report=term-missing

# Rust
cargo build
cargo test            # lib unit tests + tests/ integration
cargo run --bin vc -- cryptosuites
```

Both suites must stay green. Current baseline: **Python 322 passed / 39 skipped;
Rust 112 passed**.

## Conventions & gotchas

- **Python/Rust parity**: when you change one language's behavior for a shared
  feature (canonicalization, wire formats, cryptosuites), update the other and
  keep them byte-compatible. Cross-language interop is enforced by fixtures in
  `tests/fixtures/` (`vc_interop.*`, `vc_mldsa_interop.json`, `vc_mtc_interop.json`,
  `crypto_vectors.json`) that each language verifies.
- **Canonicalization**: signing payloads use a JCS-style subset —
  `json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True)` in
  Python, reproduced byte-for-byte by `vc.rs`. Do not change one side alone.
- **`fetch` name shadowing**: the package `__init__.py` exports a `fetch`
  *function*, so `from . import fetch` returns the function, not the submodule.
  Import names directly: `from .fetch import build_parser, main, ...`.
- **Recursion guard**: `run_tests.main()` refuses to run when `PYTEST_RUNNING`
  is set; conftest sets it. Pass `PYTEST_RUNNING=` to run pytest itself.
- **Crypto is hand-rolled / stdlib-only on the Python side** (pure Ed25519 in
  `crypto.py`, pure FIPS 204 ML-DSA-87 + ECDSA-P256 in `pq.py`). Do **not** add a
  PyO3 bridge or third-party crypto deps to Python. The Rust side may use audited
  crates (`fips204`, `p256`, `sha2`) for primitives but implements tree/wire
  formats itself in `pq.rs`.
- **Cryptosuites** (`vc.py` / `vc.rs`): `eddsa-jcs-2022` (default),
  `mldsa-87-p256` (hybrid ML-DSA-87 + ECDSA-P256), `merkle-tree-certs` (Merkle
  Tree Certificates). All implemented in both languages.
- **Style**: black + isort (line length 100) for Python; idiomatic rustfmt for
  Rust. Only touch code you're changing — no drive-by reformatting, docstrings,
  or comments on untouched code.

## Security

This is security-sensitive code (signatures, supply-chain provenance). Prefer
audited primitives; never weaken verification paths; keep tamper-rejection tests
passing. Do not commit secrets, key material, or build artifacts (e.g.
`.coverage`, `target/`, `__pycache__/`).

## When adding a feature

1. Implement in both languages if it's a shared format/behavior.
2. Add unit tests (both languages) plus a cross-language interop fixture/test if
   bytes cross the boundary.
3. Run both full suites; keep them green.
4. Update `README.md` if user-facing; do not create extra Markdown docs unless
   asked.
