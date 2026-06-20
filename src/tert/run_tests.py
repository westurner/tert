#!/usr/bin/env python3
"""
run_tests.py - Test runner harness with timestamped reports and SQLite replog.

Supports multiple test runners (pytest, cargo, go, jest, vitest, tox) and stores
test results, coverage data, and artifacts in a SQLite database for querying.

Usage:
    python3 run_tests.py [options] [runner_args]
    python3 run_tests.py ls [ls_args]
    python3 run_tests.py show [reportdir]
    python3 run_tests.py query <subquery> [reportdir]
"""

import os
import sys
import json
import sqlite3
import subprocess
import argparse
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from .shellwrap import Shellwrap

# Setup logging to mimic bash 'set -x'
logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("+ %(message)s"))
    logger.addHandler(handler)


def _run_command(cmd: List[str], *args, **kwargs) -> subprocess.CompletedProcess:
    """Wrapper around subprocess.run that logs the command like bash 'set -x'."""
    cmd_str = " ".join(str(c) for c in cmd)
    logger.debug(cmd_str)
    return subprocess.run(cmd, *args, **kwargs)


@dataclass
class TertTestRun:
    """Metadata for a single test run."""
    epoch: int
    exit_code: int
    timestamp: str
    out_dir: Path
    command: str = ""


class ReplogDB:
    """SQLite replog database for storing test runs and artifacts."""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()
    
    def _ensure_schema(self):
        """Create tables if they don't exist and migrate schema if needed."""

        print("tert database: %s ..." % self.db_path)

        with sqlite3.connect(self.db_path) as con:
            # Create schema_version table if it doesn't exist
            con.execute("""
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT
                )
            """)
            
            # Create initial tables
            con.execute("""
                CREATE TABLE IF NOT EXISTS test_runs (
                    epoch INTEGER PRIMARY KEY,
                    exit_code INTEGER,
                    timestamp TEXT,
                    out_dir TEXT,
                    command TEXT DEFAULT ''
                )
            """)
            
            con.execute("""
                CREATE TABLE IF NOT EXISTS test_artifacts (
                    epoch INTEGER,
                    out_dir TEXT,
                    filename TEXT,
                    content TEXT,
                    command TEXT DEFAULT '',
                    full_path TEXT,
                    PRIMARY KEY (epoch, filename)
                )
            """)
            
            # Get current schema version
            cursor = con.execute("SELECT MAX(version) FROM schema_version")
            result = cursor.fetchone()
            current_version = result[0] if result[0] else 0
            
            # Migrate to version 1 if needed
            if current_version < 1:
                logger.debug("Migrating schema to version 1")
                con.execute("INSERT INTO schema_version (version, applied_at) VALUES (1, datetime('now'))")
                current_version = 1
            
            # Migrate to version 2 if needed (add command and full_path)
            if current_version < 2:
                logger.debug("Migrating schema to version 2")
                # These columns were already created in the initial CREATE TABLE
                # Just mark the migration as complete
                con.execute("INSERT INTO schema_version (version, applied_at) VALUES (2, datetime('now'))")
                # Compute full_path for existing rows
                con.execute("UPDATE test_artifacts SET full_path = out_dir || '/' || filename WHERE full_path IS NULL")

            con.commit()
    
    def insert_run(self, run: TertTestRun):
        """Store a test run record."""
        with sqlite3.connect(self.db_path) as con:
            sql = "INSERT OR REPLACE INTO test_runs (epoch, exit_code, timestamp, out_dir, command) VALUES (?, ?, ?, ?, ?)"
            params = (run.epoch, run.exit_code, run.timestamp, str(run.out_dir), run.command)
            logger.debug(f"SQL: {sql} with params {params}")
            con.execute(sql, params)
            con.commit()
    
    def insert_artifact(self, epoch: int, out_dir: Path, filename: str, content: str, command: str = ""):
        """Store a build artifact."""
        full_path = str(out_dir / filename)
        with sqlite3.connect(self.db_path) as con:
            sql = "INSERT OR REPLACE INTO test_artifacts (epoch, out_dir, filename, content, command, full_path) VALUES (?, ?, ?, ?, ?, ?)"
            params = (epoch, str(out_dir), filename, content, command, full_path)
            logger.debug(f"SQL: {sql} with params (epoch={epoch}, out_dir={out_dir}, filename={filename}, content_len={len(content)}, command={command})")
            con.execute(sql, params)
            con.commit()
    
    def query_runs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent test runs."""
        with sqlite3.connect(self.db_path) as con:
            con.row_factory = sqlite3.Row
            sql = "SELECT epoch, exit_code, timestamp, out_dir FROM test_runs ORDER BY epoch DESC LIMIT ?"
            logger.debug(f"SQL: {sql} with params (limit={limit})")
            rows = con.execute(sql, (limit,)).fetchall()
            return [dict(row) for row in rows]
    
    def query_artifacts(self, out_dir: Optional[str] = None) -> List[Dict[str, Any]]:
        """List stored artifacts."""
        query = "SELECT epoch, filename, length(content) as bytes, out_dir FROM test_artifacts"
        params = []
        if out_dir:
            query += " WHERE out_dir = ?"
            params.append(out_dir)
        query += " ORDER BY epoch DESC, filename"
        
        logger.debug(f"SQL: {query} with params {params}")
        
        with sqlite3.connect(self.db_path) as con:
            con.row_factory = sqlite3.Row
            rows = con.execute(query, params).fetchall()
            return [dict(row) for row in rows]


class TertTestRunner:
    """Base test runner."""
    
    def __init__(self, out_dir: Path):
        self.out_dir = out_dir
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.build_log = self.out_dir / "build.log"
        self.shellwrap = Shellwrap(
            log_file=str(self.build_log),
            log_file_ansi=str(self.out_dir / "build.log.ansi"),
            keep_ansi=True,
            color_mode='always'
        )
        self.artifacts: List[Path] = [self.build_log]
    
    def run(self, *args) -> int:
        """Execute the test command; return exit code."""
        raise NotImplementedError
    
    def get_artifacts(self) -> List[Path]:
        """Return list of artifact files to store in replog."""
        return [p for p in self.artifacts if p.exists()]


class PytestRunner(TertTestRunner):
    """pytest test runner."""
    
    def __init__(self, out_dir: Path):
        super().__init__(out_dir)
        self.artifacts.extend([
            self.out_dir / "pytest-results.xml",
            self.out_dir / "coverage.json",
        ])
    
    def run(self, *args) -> int:
        """Run pytest with Shellwrap for colored output."""
        original_env = os.environ.copy()
        os.environ["SKIP_PYTEST_REPLOG"] = "1"
        os.environ["COVERAGE_FILE"] = str(self.out_dir / ".coverage")
        
        try:
            cmd = [
                sys.executable, "-m", "pytest",
                f"--junitxml={self.out_dir}/pytest-results.xml",
                f"--cov-report=json:{self.out_dir}/coverage.json",
                "--cov-report=term-missing:skip-covered",
            ]
            cmd.extend(args)

            self.shellwrap.set_color_env()
            self.shellwrap.commands = [' '.join(cmd)]
            exit_code = self.shellwrap.execute_streaming()
            return exit_code
        finally:
            os.environ.clear()
            os.environ.update(original_env)


class CargoRunner(TertTestRunner):
    """cargo test runner."""
    
    def run(self, *args) -> int:
        """Run cargo test with Shellwrap for colored output."""
        cmd = ["cargo", "test"] + list(args)

        self.shellwrap.set_color_env()
        self.shellwrap.commands = [' '.join(cmd)]
        return self.shellwrap.execute_streaming()


class GoRunner(TertTestRunner):
    """go test runner."""
    
    def run(self, *args) -> int:
        """Run go test with Shellwrap for colored output."""
        cmd = ["go", "test"] + list(args)

        self.shellwrap.set_color_env()
        self.shellwrap.commands = [' '.join(cmd)]
        return self.shellwrap.execute_streaming()


class JestRunner(TertTestRunner):
    """jest test runner."""
    
    def run(self, *args) -> int:
        """Run jest with Shellwrap for colored output."""
        cmd = ["npx", "jest"] + list(args)

        self.shellwrap.set_color_env()
        self.shellwrap.commands = [' '.join(cmd)]
        return self.shellwrap.execute_streaming()


class VitestRunner(TertTestRunner):
    """vitest test runner."""
    
    def __init__(self, out_dir: Path):
        super().__init__(out_dir)
        self.artifacts.append(self.out_dir / "junit.xml")
    
    def run(self, *args) -> int:
        """Run vitest with Shellwrap for colored output."""
        cmd = [
            "npx", "vitest", "run",
            "--reporter=junit",
            f"--outputFile={self.out_dir}/junit.xml",
        ] + list(args)

        self.shellwrap.set_color_env()
        self.shellwrap.commands = [' '.join(cmd)]
        return self.shellwrap.execute_streaming()


class ToxRunner(TertTestRunner):
    """tox test runner."""
    
    def run(self, *args) -> int:
        """Run tox with Shellwrap for colored output."""
        cmd = ["tox"] + list(args)

        self.shellwrap.set_color_env()
        self.shellwrap.commands = [' '.join(cmd)]
        return self.shellwrap.execute_streaming()


class BashcovRunner(TertTestRunner):
    """bashcov test runner for bash script coverage."""
    
    def run(self, *args) -> int:
        """Run bashcov if available."""
        try:
            cmd = ["bashcov"] + list(args)

            self.shellwrap.set_color_env()
            self.shellwrap.commands = [' '.join(cmd)]
            exit_code = self.shellwrap.execute_streaming()
            
            # Store coverage results if available
            try:
                coverage_file = self.out_dir / "bashcov-results.txt"
                if coverage_file.exists():
                    self.artifacts.append(coverage_file)
            except Exception:
                pass
            
            return exit_code
        except FileNotFoundError:
            logger.error("bashcov not found. Install with: pip install bashcov")
            return 127


class ShellcovRunner(TertTestRunner):
    """shellcov test runner (bash coverage wrapper, mimics bashcov output)."""
    
    def run(self, *args) -> int:
        """Run shellcov if available, fallback to bash."""
        try:
            # Try shellcov first
            cmd = ["shellcov"] + list(args)

            self.shellwrap.set_color_env()
            self.shellwrap.commands = [' '.join(cmd)]
            exit_code = self.shellwrap.execute_streaming()
            
            # Store coverage results if available
            try:
                coverage_file = self.out_dir / "shellcov-results.txt"
                if coverage_file.exists():
                    self.artifacts.append(coverage_file)
            except Exception:
                pass
            
            return exit_code
        except FileNotFoundError:
            # Fallback to bash if shellcov not found
            logger.warning("shellcov not found, falling back to bash")
            cmd = ["bash"] + list(args)

            self.shellwrap.set_color_env()
            self.shellwrap.commands = [' '.join(cmd)]
            return self.shellwrap.execute_streaming()


def get_runner(runner_name: str, out_dir: Path) -> TertTestRunner:
    """Instantiate the appropriate runner."""
    runners = {
        "pytest": PytestRunner,
        "cargo": CargoRunner,
        "go": GoRunner,
        "jest": JestRunner,
        "vitest": VitestRunner,
        "tox": ToxRunner,
        "bashcov": BashcovRunner,
        "shellcov": ShellcovRunner,
    }
    runner_class = runners.get(runner_name)
    if not runner_class:
        raise ValueError(f"Unknown runner: {runner_name}")
    return runner_class(out_dir)


def run_tests(
    runner: str,
    reports_dir: Path,
    replog_db: ReplogDB,
    skip_artifacts: bool = False,
    *args,
) -> int:
    """Execute a test suite and record results in the replog."""
    epoch = int(datetime.now().timestamp())
    timestamp = datetime.now().isoformat()
    out_dir_name = f"{epoch}-{datetime.now().strftime('%Y-%m-%dT%H-%M-%S%z')}"
    out_dir = reports_dir / out_dir_name
    
    test_runner = get_runner(runner, out_dir)
    exit_code = test_runner.run(*args)
    
    latest_link = reports_dir / "latest"
    if latest_link.is_symlink():
        latest_link.unlink()
    latest_link.symlink_to(out_dir_name)
    
    # Construct command string for logging
    if args:
        command = f"{runner} {' '.join(str(a) for a in args)}"
    else:
        command = runner
    
    run = TertTestRun(
        epoch=epoch,
        exit_code=exit_code,
        timestamp=timestamp,
        out_dir=out_dir,
        command=command,
    )
    replog_db.insert_run(run)
    
    if not skip_artifacts:
        for artifact_path in test_runner.get_artifacts():
            if artifact_path.exists():
                content = artifact_path.read_text(errors="replace")
                replog_db.insert_artifact(epoch, out_dir, artifact_path.name, content, command)
    
    return exit_code


def query_runs(replog_db: ReplogDB) -> List[Dict]:
    """List test runs."""
    return replog_db.query_runs()


def query_artifacts(replog_db: ReplogDB, out_dir: Optional[str] = None) -> List[Dict]:
    """List artifacts."""
    return replog_db.query_artifacts(out_dir)


def query_coverage_lines(coverage_db: Path, filter_path: Optional[str] = None) -> Dict[str, List[int]]:
    """Decode coverage.py line_bits and return covered lines per file."""
    if not coverage_db.exists():
        raise FileNotFoundError(f".coverage DB not found: {coverage_db}")
    
    def numbits_to_lines(blob: bytes) -> List[int]:
        lines = []
        for byte_i, byte in enumerate(blob):
            for bit_j in range(8):
                if byte & (1 << bit_j):
                    lines.append(byte_i * 8 + bit_j + 1)
        return lines
    
    result = {}
    with sqlite3.connect(coverage_db) as con:
        con.row_factory = sqlite3.Row
        query = "SELECT f.path, lb.numbits FROM line_bits lb JOIN file f ON f.id = lb.file_id"
        params = []
        if filter_path:
            query += " WHERE f.path LIKE ?"
            params.append(f"%{filter_path}%")
        query += " ORDER BY f.path"
        
        logger.debug(f"SQL: {query} with params {params}")
        rows = con.execute(query, params).fetchall()
        for row in rows:
            result[row["path"]] = numbits_to_lines(row["numbits"])
    
    return result


def main():
    """CLI entry point."""
    if os.environ.get("PYTEST_RUNNING") == "1":
        print("Error: Cannot run run_tests from within pytest (recursion protection)", file=sys.stderr)
        print("       Tests must use mocking instead of calling main()", file=sys.stderr)
        return 1
    
    known_runners = ["pytest", "cargo", "go", "jest", "vitest", "tox"]
    known_commands = ["run", "ls", "show", "query"]
    command_aliases = {"q": "query", "l": "ls", "s": "show"}
    subquery_aliases = {"l": "lines", "a": "artifacts", "r": "runs", "lines": "coverage-lines"}
    subquery_normalized = {"coverage-lines": "coverage-lines", "lines": "coverage-lines"}
    
    argv = sys.argv[1:]
    
    if argv and len(argv[0]) > 1 and not argv[0].startswith("-"):
        first_arg = argv[0]
        if first_arg[0] in command_aliases:
            cmd_alias = first_arg[0]
            remainder = first_arg[1:]
            argv[0] = command_aliases[cmd_alias]
            if remainder and remainder in subquery_aliases:
                argv.insert(1, subquery_aliases[remainder])
    
    if argv and argv[0] in command_aliases:
        argv[0] = command_aliases[argv[0]]
    
    if len(argv) >= 2 and argv[0] == "query":
        if argv[1] in subquery_aliases:
            argv[1] = subquery_aliases[argv[1]]
        if argv[1] in subquery_normalized:
            argv[1] = subquery_normalized[argv[1]]
    
    if argv and argv[0] not in known_commands:
        if argv[0] in known_runners:
            argv.insert(0, "run")
        elif not argv[0].startswith("-"):
            argv.insert(0, "run")
    elif not argv:
        argv.insert(0, "run")
    
    parser = argparse.ArgumentParser(
        description="Test runner with timestamped reports and SQLite replog"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    subparsers = parser.add_subparsers(dest="command")
    
    run_parser = subparsers.add_parser("run", help="Run tests")
    run_parser.add_argument("--runner", default="pytest", choices=["pytest", "cargo", "go", "jest", "vitest", "tox"], help="Test runner to use")
    run_parser.add_argument("--reports-dir", type=Path, default=Path("reports"), help="Reports directory")
    run_parser.add_argument("--replog-db", type=Path, default=Path("reports/replog.db"), help="Replog SQLite database path")
    run_parser.add_argument("--no-artifacts", action="store_true", help="Skip storing artifacts")
    run_parser.add_argument("runner_args", nargs="*", help="Arguments to pass to the test runner or path to tests")
    
    ls_parser = subparsers.add_parser("ls", help="List reports")
    ls_parser.add_argument("ls_args", nargs="*", help="Arguments to ls")
    
    show_parser = subparsers.add_parser("show", help="Show report")
    show_parser.add_argument("reportdir", nargs="?", default="reports/latest", help="Report directory")
    
    query_parser = subparsers.add_parser("query", help="Query replog")
    query_parser.add_argument("subquery", choices=["runs", "r", "artifacts", "a", "coverage-lines", "lines", "l"], help="Query type")
    query_parser.add_argument("--replog-db", type=Path, default=Path("reports/replog.db"), help="Replog SQLite database path")
    query_parser.add_argument("--jsonl", "--nl", action="store_true", help="Output as JSON Lines")
    query_parser.add_argument("query_args", nargs="*", help="Query arguments")
    
    args, unknown = parser.parse_known_args(argv)
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)
    
    if args.command == "run":
        runner = args.runner
        runner_args = list(args.runner_args) if args.runner_args else []
        runner_args.extend(unknown)
        
        if runner_args and runner_args[0] in ["pytest", "cargo", "go", "jest", "vitest", "tox"]:
            runner = runner_args[0]
            runner_args = runner_args[1:]
        
        replog_db = ReplogDB(args.replog_db)
        exit_code = run_tests(runner, args.reports_dir, replog_db, args.no_artifacts, *runner_args)
        return exit_code
    
    elif args.command == "ls":
        _run_command(["ls", "-al", "reports"] + args.ls_args)
    
    elif args.command == "show":
        report_dir = Path(args.reportdir)
        for file in sorted(report_dir.glob("*")):
            if file.is_file():
                print(f"\n===== {file.name} =====")
                print(file.read_text(errors="replace"))
    
    elif args.command == "query":
        replog_db = ReplogDB(args.replog_db)
        
        subquery_map = {"r": "runs", "a": "artifacts", "l": "coverage-lines", "lines": "coverage-lines"}
        subquery = subquery_map.get(args.subquery, args.subquery)
        
        if subquery == "runs":
            runs = query_runs(replog_db)
            if args.jsonl:
                for run in runs:
                    print(json.dumps(run))
            else:
                print(json.dumps(runs, indent=2))
        
        elif subquery == "artifacts":
            artifacts = query_artifacts(replog_db)
            if args.jsonl:
                for artifact in artifacts:
                    print(json.dumps(artifact))
            else:
                print(json.dumps(artifacts, indent=2))
        
        elif subquery == "coverage-lines":
            reportdir = Path(args.query_args[0] if args.query_args else "reports/latest")
            filter_path = args.query_args[1] if len(args.query_args) > 1 else None
            coverage_db = reportdir / ".coverage"
            if not coverage_db.exists():
                print(f"Error: {coverage_db} not found", file=sys.stderr)
                return 1
            lines = query_coverage_lines(coverage_db, filter_path)
            if args.jsonl:
                for file_path, line_nums in lines.items():
                    print(json.dumps({"file": file_path, "lines": line_nums}))
            else:
                print(json.dumps(lines, indent=2))
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
