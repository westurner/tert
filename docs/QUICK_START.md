# TERT Package - Quick Start Guide

## 🎯 What Was Created

A complete Python+Rust package called **TERT** (Test Execution Report Tracker) with:
- Command execution engine with colored output streaming
- Test runner harness supporting pytest, cargo, go, jest, vitest, tox
- SQLite-backed test result repository
- Comprehensive test suite with recursion protection
- Maturin/PyO3 for Python-Rust integration
- cargo-insta for snapshot testing

## 📦 Location
```
/var/home/wturner/-wrk/-ve311/dotfiles/src/dotfiles/src/tert/
```

## ⚡ 5-Minute Setup

### 1. Install the Package
```bash
cd /var/home/wturner/-wrk/-ve311/dotfiles/src/dotfiles/src/tert
pip install -e .
# or with dev dependencies:
pip install -e ".[dev]"
```

### 2. Run Tests
```bash
pytest tests/ -v

# With coverage:
pytest tests/ --cov=src/tert --cov-report=html

# Run specific test file:
pytest tests/test_shellwrap.py -v
```

### 3. Try the CLI
```bash
# Show help
python -m tert --help

# Run pytest
python -m tert pytest tests/

# Query results
python -m tert query runs
python -m tert query artifacts
```

## 💻 Code Examples

### Execute Commands with Colored Output
```python
from tert import Shellwrap

sw = Shellwrap(
    log_file="build.log",
    log_file_ansi="build.log.ansi",
    keep_ansi=True,
    color_mode="always"
)

sw.commands = [
    "pytest tests/",
    "cargo test",
]

exit_code = sw.execute_streaming()
print(f"Exit code: {exit_code}")
```

### Run Tests and Query Results
```python
from pathlib import Path
from tert import ReplogDB, run_tests, query_runs, query_artifacts

# Setup
reports_dir = Path("reports")
replog_db = ReplogDB(reports_dir / "replog.db")

# Run tests
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

for run in runs:
    print(f"Run {run['epoch']}: exit_code={run['exit_code']}")

for artifact in artifacts:
    print(f"  {artifact['filename']}: {artifact['bytes']} bytes")
```

### Using Different Test Runners
```python
from pathlib import Path
from tert import run_tests, ReplogDB

reports_dir = Path("reports")
replog_db = ReplogDB(reports_dir / "replog.db")

# Python tests
run_tests("pytest", reports_dir, replog_db, False, "tests/")

# Rust tests
run_tests("cargo", reports_dir, replog_db, False)

# Go tests
run_tests("go", reports_dir, replog_db, False, "./...")

# JavaScript tests
run_tests("jest", reports_dir, replog_db, False, "tests/")
run_tests("vitest", reports_dir, replog_db, False, "src/")
```

## 📁 Package Contents

### Main Modules
- **`src/tert/shellwrap.py`** (850+ lines)
  - `Shellwrap` class: Execute commands with colored output streaming
  - ANSI stripping, dual logging, PTY support

- **`src/tert/run_tests.py`** (450+ lines)
  - `ReplogDB`: SQLite database for test metadata
  - `TestRunner` and subclasses: pytest, cargo, go, jest, vitest, tox
  - Functions: `run_tests()`, `query_runs()`, `query_artifacts()`, `query_coverage_lines()`

### Test Suite
- **`tests/conftest.py`**
  - Recursion protection (prevents pytest calling itself)
  - Global subprocess mocking
  - Custom pytest markers

- **`tests/test_shellwrap.py`** (220+ lines)
  - ANSI stripping tests
  - Color environment variable handling
  - Command execution with mocking
  - Argument parsing

- **`tests/test_run_tests.py`** (300+ lines)
  - ReplogDB operations (insert, query)
  - Multi-runner support
  - Coverage analysis queries
  - Integration tests

### Configuration
- **`pyproject.toml`**: Python package config with maturin, pytest, coverage, black, isort, mypy
- **`Cargo.toml`**: Rust package config with pyo3, insta

### Documentation
- **`README.md`**: Complete usage guide, examples, architecture
- **`MIGRATION_SUMMARY.md`**: Detailed migration notes, file manifest, next steps

## 🔧 Development

### Build Rust Extension (Optional)
```bash
pip install maturin
cd /var/home/wturner/-wrk/-ve311/dotfiles/src/dotfiles/src/tert
maturin develop
```

### Run Snapshot Tests (with Rust)
```bash
cd /var/home/wturner/-wrk/-ve311/dotfiles/src/dotfiles/src/tert
cargo insta test
cargo insta review
```

### Code Style
```bash
# Format with black
black src/tert tests

# Sort imports with isort
isort src/tert tests

# Type check with mypy
mypy src/tert
```

## 🚀 Common Use Cases

### Record Test Runs
```python
from tert import run_tests, ReplogDB
from pathlib import Path

replog_db = ReplogDB(Path("reports/replog.db"))
exit_code = run_tests("pytest", Path("reports"), replog_db, False, "tests/")
```

### View Test History
```bash
python -m tert query runs
# Output: JSON list of all test runs with timestamps and exit codes
```

### Stream Colored Output to Log Files
```python
from tert import Shellwrap

sw = Shellwrap(
    log_file="build.log",
    log_file_ansi="build.log.ansi",
    keep_ansi=True,
    color_mode="always"
)
sw.commands = ["pytest tests/ -v"]
exit_code = sw.execute_streaming()
# Creates both build.log (plain) and build.log.ansi (with colors)
```

### Query Test Coverage
```bash
python -m tert query coverage-lines reports/latest
# Output: JSON with file paths and covered line numbers
```

## ✅ What's Tested

✅ ANSI escape sequence removal
✅ Color environment variable handling
✅ Command execution and logging
✅ Multi-runner support (pytest, cargo, go, jest, vitest, tox)
✅ SQLite replog operations
✅ Coverage data analysis
✅ Recursion protection
✅ Subprocess mocking
✅ Argument parsing
✅ Integration with Maturin/PyO3

## 📊 Test Coverage

```bash
cd /var/home/wturner/-wrk/-ve311/dotfiles/src/dotfiles/src/tert
pytest tests/ --cov=src/tert --cov-report=html
# Open htmlcov/index.html to see coverage report
```

## 🎓 Learn More

1. **README.md** - Full documentation with examples
2. **tests/test_*.py** - Working examples of all features
3. **src/tert/run_tests.py** - Main CLI implementation
4. **src/tert/shellwrap.py** - Command execution details

## 🐛 Troubleshooting

### Import Errors
```bash
# Ensure you're in the right directory
cd /var/home/wturner/-wrk/-ve311/dotfiles/src/dotfiles/src/tert

# Reinstall in editable mode
pip install -e .
```

### Tests Failing
```bash
# Check recursion protection is set
export PYTEST_RUNNING=1

# Run with verbose output
pytest tests/ -vv

# Check specific test file
pytest tests/test_shellwrap.py::TestShellwrapAnsiStripping -v
```

### Rust Build Issues
```bash
# Ensure you have maturin and PyO3 dependencies
pip install maturin pyo3

# Clean and rebuild
cd /var/home/wturner/-wrk/-ve311/dotfiles/src/dotfiles/src/tert
maturin clean
maturin develop
```

## 📝 CLI Reference

```bash
# Run tests (creates timestamped report)
python -m tert run [--runner pytest|cargo|go|jest|vitest|tox] [args...]

# Query results
python -m tert query runs
python -m tert query artifacts
python -m tert query coverage-lines

# Short aliases
python -m tert q r  # query runs
python -m tert q a  # query artifacts
python -m tert q l  # query coverage-lines

# List reports
python -m tert ls

# Show report
python -m tert show [reportdir]
```

---

**Next Step:** Run `pytest tests/ -v` to verify everything works!
