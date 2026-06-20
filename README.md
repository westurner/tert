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
