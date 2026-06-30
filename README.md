# Test Execution Report Tracker (TERT)

A modern, composable test runner harness with timestamped reports and SQLite-backed reporting.

## Features

- **Multi-language test runner support**: pytest, cargo, go, jest, vitest, tox
- **Timestamped reports**: Each test run creates a uniquely timestamped report directory
- **SQLite replog**: Stores test metadata and artifacts in a queryable database
- **Colored output streaming**: Real-time terminal output with ANSI color preservation
- **Log dual-writing**: Maintains both ANSI-colored and plain-text logs simultaneously
- **Python + Cargo/Maturin**: Pure Python with optional Rust performance bindings
- **Coverage analysis**: Query coverage data from pytest/coverage runs
- **CLI and library API**: Use standalone or integrate into your test infrastructure

## Quick Start

### Installation

```bash
pip install tert
# or with development dependencies:
pip install tert[dev]
```

### Usage

#### As a Command-Line Tool

```bash
# Run pytest with report logging
tert pytest tests/

# Run cargo tests
tert run --runner cargo

# Query test history
tert query runs
tert query artifacts
tert query coverage-lines

# Short aliases
tert q r  # query runs
tert q a  # query artifacts
tert q l  # query coverage-lines
```

#### Fetching URLs with verified TLS configuration

```bash
# Download with the default strategy (curl if available, else wget)
tert fetch https://example.com/file.tar.gz

# Force a specific strategy
tert fetch --curl https://example.com/file.tar.gz
tert fetch --wget https://example.com/file.tar.gz
tert fetch --rust https://example.com/file.tar.gz   # stub: not yet implemented

# Only discover, log and verify the crypto config (no download)
tert fetch --crypto-only --curl
tert fetch --crypto-only --rust --json
```

For every strategy, `tert fetch` discovers, logs and verifies the active TLS
crypto configuration before downloading:

- the TLS backend (OpenSSL / GnuTLS / rustls / ...)
- the CA certificate bundle path and where it came from (env var vs system default)
- the CA bundle size, certificate count, and sha256 digest

A download is refused when the crypto configuration cannot be verified (pass
`--no-verify-crypto` to override). The `--rust` strategy is a stub that reports
and verifies its intended crypto config but does not yet download.

The negotiated TLS version and cipher (e.g. `TLSv1.3 / TLS_AES_128_GCM_SHA256`)
are parsed from the downloader's verbose output and recorded in the signed
metadata.

#### Central cache with signed YAML-LD metadata (fetchc-style)

```bash
# Cache under $XDG_CACHE_HOME/tert/fetch/cache/<host>/<file> with a signed
# <file>.meta.yml (VC 2.0 / W3C PROV) and a central index.meta.yml.
tert fetch --cache --keys-dir ./keys https://example.com/file.tar.gz

tert fetch --query ls                 # list cached metadata
tert fetch --query show <path>        # show a .meta.yml (or its output path)
```

#### Logging a fetch as a run

By default, `tert fetch` records each download in the replog and registers the
downloaded file as an output artifact (with an artifact summary), reusing the
same reporting machinery as test runs. Use `--no-record` for a plain download.
`fetch` is also registered as a runner.

```bash
tert fetch https://example.com/file.tar.gz            # records by default
tert fetch --no-record https://example.com/file.tar.gz # plain download
tert fetch --json https://example.com/file.tar.gz      # prints JSON *and* records
tert run --runner fetch -- https://example.com/file.tar.gz
tert query artifact-summaries reports/latest
```

#### DID-signed download provenance with the did-agent

`tert` ships an ssh-agent-style signing agent that holds an Ed25519 `did:key`
private key **in memory only** (never written to disk) and signs over a Unix
socket. This avoids leaving a DID key unprotected on disk: clients sign through
the agent instead of reading a key file.

```bash
# Start the agent (prints a DID_AGENT_SOCK export line); seed source can be an
# ephemeral key, a --seed-file, or the DID_AGENT_SEED env var.
eval "$(tert did-agent serve --print-env)"

# Client actions against $DID_AGENT_SOCK
tert did-agent did
tert did-agent pubkey
tert did-agent sign "some message"

# A native Rust binary speaks the same wire protocol and is interoperable:
did-agent serve --print-env        # cargo bin: target/release/did-agent
```

With an agent running (or an on-disk fallback key), `tert fetch --sign` writes a
DID-signed provenance sidecar (`<dest>.prov.json`, a VC-2.0 / W3C-PROV document)
recording the URL, sha256, strategy and the verified TLS/CA configuration:

```bash
tert fetch --sign https://example.com/file.tar.gz
tert fetch --verify-file file.tar.gz.prov.json
```

The agent protocol (newline-delimited UTF-8 over `AF_UNIX`):

```text
PING           -> OK pong
DID            -> OK did:key:z6Mk...
PUBKEY         -> OK <base64 public key>
SIGN <base64>  -> OK <base64 signature>
```

The Python (`tert.crypto`) and Rust (`tert::crypto`) Ed25519 implementations are
dependency-free, produce byte-identical signatures, and are validated against
OpenSSL.

#### Signing VC / YAML-LD documents and cryptosuites

`tert vc` signs and verifies Verifiable Credential documents (JSON or YAML-LD)
with a pluggable *cryptosuite*:

```bash
tert vc cryptosuites              # list suites and availability
tert vc sign doc.yaml --keys-dir ./keys -o doc.signed.yaml
tert vc verify doc.signed.yaml
```

| cryptosuite          | status | notes                                          |
|----------------------|--------|------------------------------------------------|
| `eddsa-jcs-2022`     | ready  | Ed25519 over canonical JSON (default)          |
| `mldsa-87-p256`      | stub   | post-quantum hybrid ML-DSA-87 + ECDSA-P256     |
| `merkle-tree-certs`  | stub   | Merkle Tree Certificates                       |

The canonicalization (a JCS-style subset) and `eddsa-jcs-2022` proofs are
byte-for-byte interoperable between Python (`tert.vc`) and Rust (`tert::vc`,
including the standalone `vc` binary). JSON, YAML-LD and TOML serializations are
all supported; in TOML a credential is embedded under the provisional
`[verifiableCredential]` table so it canonicalizes identically across formats.

#### Artifact summaries (YAML-LD / PROV)

`tert run` can record signed input/output artifact summaries (path, size,
sha256) as YAML-LD `prov:Entity` documents:

```bash
tert run --input data.csv --input-checksum sha256:<hex> \
         --summary-sign --keys-dir ./keys pytest tests/
tert query artifact-summaries reports/latest
```

Input summaries are generated, printed and stored before the run (failing the
run on a checksum mismatch); output summaries are generated for produced
artifacts after the run.

#### As a Python Library

```python
from tert import (
    Shellwrap,
    ReplogDB,
    run_tests,
    query_runs,
    query_artifacts,
)
from pathlib import Path

# Execute command with colored output and logging
sw = Shellwrap(
    log_file="build.log",
    log_file_ansi="build.log.ansi",
    keep_ansi=True,
    color_mode="always"
)
sw.commands = ["pytest tests/"]
exit_code = sw.execute_streaming()

# Run tests and record in replog
replog_db = ReplogDB(Path("reports/replog.db"))
reports_dir = Path("reports")

exit_code = run_tests(
    runner="pytest",
    reports_dir=reports_dir,
    replog_db=replog_db,
    skip_artifacts=False,
    "tests/"
)

# Query history
runs = query_runs(replog_db)
artifacts = query_artifacts(replog_db)
```

## Project Structure

```
src/tert/
├── src/tert/
│   ├── __init__.py           # Package initialization
│   ├── __main__.py           # CLI entry point
│   ├── shellwrap.py          # Command execution with colored output
│   └── run_tests.py          # Test runner harness and replog management
├── tests/
│   ├── conftest.py           # Pytest configuration with recursion protection
│   ├── test_shellwrap.py     # Shellwrap unit tests
│   └── test_run_tests.py     # Integration tests for run_tests
├── scripts/
│   └── shellwrap.sh          # Bash reference implementation
├── src/lib.rs                # Rust library (Maturin/PyO3)
├── Cargo.toml                # Cargo manifest with insta snapshots
└── pyproject.toml            # Python package configuration
```

## Key Components

### Shellwrap

Executes commands with:
- Real-time colored output streaming
- Dual log files (ANSI-preserved and plain-text)
- PTY support for interactive shells
- BASH_ENV injection for alias loading
- Environment variable configuration for colored output

### ReplogDB

SQLite database storing:
- Test run metadata (epoch, exit code, timestamp, output directory)
- Build artifacts (logs, coverage data, reports)
- Queryable schema for historical analysis

### TestRunner Classes

- `PytestRunner`: Runs pytest with coverage reporting
- `CargoRunner`: Runs Rust tests via cargo
- `GoRunner`: Runs Go tests
- `JestRunner`: Runs JavaScript tests via Jest
- `VitestRunner`: Runs Vue/Vitest tests
- `ToxRunner`: Runs tox test environments

### CLI Commands

- `run` [options]: Execute a test suite and record results
- `fetch` <url> [dest]: Download a URL with a selectable strategy (`--curl`, `--wget`, `--rust`), logging and verifying the TLS crypto config and CA cert bundle; `--sign` writes DID-signed provenance; `--cache` caches with a signed `.meta.yml` + index; `--query ls|show`
- `did-agent` [serve|did|pubkey|sign|ping]: ssh-agent-style in-memory Ed25519 `did:key` signer
- `vc` [sign|verify|cryptosuites]: sign/verify Verifiable Credential (JSON/YAML-LD) documents
- `ls` [args]: List report directories
- `show` [reportdir]: Display contents of a report
- `query` {runs|artifacts|coverage-lines}: Query the replog database

## Testing

The test suite includes:
- Unit tests for ANSI stripping and log handling
- Integration tests for multi-runner support
- Recursion protection to prevent pytest calling itself
- Global subprocess mocking to prevent actual command execution

Run tests:

```bash
pytest tests/

# With coverage
pytest tests/ --cov=src/tert --cov-report=html

# Without subprocess mocking
pytest tests/ -m "not requires_mock"
```

## Development

### Building with Maturin

```bash
pip install maturin
maturin develop  # Build Rust extension in development mode
```

### Using cargo-insta for Snapshots

The project includes cargo-insta support for snapshot testing:

```bash
cargo insta test
cargo insta review
```

### Code Style

- Python: Black (line length 100), isort, mypy
- Rust: `cargo fmt`, `cargo clippy`

## Performance Considerations

- Shellwrap uses threading for concurrent stdout/stderr streaming
- PTY mode preserves colors without subprocess wrapper overhead
- Replog uses indexed SQLite queries for fast historical lookups
- Rust extension available for ANSI stripping and SQLite operations

## Recursion Protection

The test suite includes protections against recursive pytest invocations:

1. `conftest.py` sets `PYTEST_RUNNING=1` at session start
2. `run_tests.py` checks this env var and refuses to call pytest
3. Tests mock `subprocess.run` to prevent actual command execution
4. The `@pytest.mark.requires_mock` marker identifies subprocess-dependent tests

This prevents the scenario:
```
run_tests.py run pytest tests/
  → pytest tests/test_run_tests.py
    → (if test calls main()) run_tests.py run pytest tests/
      → RECURSION! ❌
```

## License

MIT

## Author

westurner
