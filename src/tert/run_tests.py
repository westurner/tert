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
import shlex
import sqlite3
import subprocess
import argparse
import logging
import time
from datetime import datetime, timezone
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


def _format_timestamp_ns(ns: int) -> str:
    """Format a nanosecond-resolution UNIX timestamp as ISO8601 with 9 decimal places."""
    secs = ns // 1_000_000_000
    nanos = ns % 1_000_000_000
    dt = datetime.fromtimestamp(secs, tz=timezone.utc)
    return dt.strftime('%Y-%m-%dT%H:%M:%S') + f'.{nanos:09d}+00:00'


def _interpreter_cmd(interpreter: str, args, command_flag: Optional[str] = "-c") -> List[str]:
    """Build an argv for an interpreter (sh/bash/zsh/python/ipython).

    - No args: just the interpreter.
    - First arg is an option (starts with '-'): pass args through verbatim so
      explicit invocations like ``-x -c "cmd"`` work as written.
    - First arg is an existing file: run it as a script.
    - Otherwise, when ``command_flag`` is set (shells): treat the remaining args
      as an inline command string via ``command_flag`` (e.g. ``sh -c "whoami"``).
      Args are re-joined with :func:`shlex.join` quoting so the original word
      boundaries and metacharacters are preserved.
    - Otherwise, when ``command_flag`` is ``None`` (python/ipython): pass args
      through verbatim. There is no implicit ``-c`` wrapping — an inline command
      must be requested explicitly (e.g. ``python -- -c "print(1)"``).
    """
    args = [str(a) for a in args]
    if not args:
        return [interpreter]
    if command_flag is None or args[0].startswith("-") or Path(args[0]).is_file():
        return [interpreter] + args
    return [interpreter, command_flag, shlex.join(args)]



@dataclass
class TertTestRun:
    """Metadata for a single test run."""
    timestamp_ns: str
    epoch_ns: int
    exit_code: int
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

        logger.info("tert database: %s ..." % self.db_path)

        # Enable WAL mode first — persists in the db file, benefits all subsequent connections
        with sqlite3.connect(self.db_path) as _wal:
            _wal.execute("PRAGMA journal_mode = WAL")

        with sqlite3.connect(self.db_path) as con:
            con.execute("PRAGMA foreign_keys = ON")

            # Create schema_version table if it doesn't exist
            con.execute("""
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT
                )
            """)

            # Get current schema version
            cursor = con.execute("SELECT MAX(version) FROM schema_version")
            result = cursor.fetchone()
            current_version = result[0] if result[0] else 0

            # Apply migrations in order
            if current_version < 1:
                logger.debug("Migrating schema to version 1")
                self._migrate_v1(con)
                current_version = 1

            if current_version < 2:
                logger.debug("Migrating schema to version 2")
                self._migrate_v2(con)
                current_version = 2

            if current_version < 3:
                logger.debug("Migrating schema to version 3")
                self._migrate_v3(con)
                current_version = 3

            if current_version < 4:
                logger.debug("Migrating schema to version 4")
                self._migrate_v4(con)
                current_version = 4

            if current_version < 5:
                logger.debug("Migrating schema to version 5")
                self._migrate_v5(con)
                current_version = 5

            if current_version < 6:
                logger.debug("Migrating schema to version 6")
                self._migrate_v6(con)
                current_version = 6

            if current_version < 7:
                logger.debug("Migrating schema to version 7")
                self._migrate_v7(con)
                current_version = 7

            if current_version < 8:
                logger.debug("Migrating schema to version 8")
                self._migrate_v8(con)
                current_version = 8

            con.commit()

    def _migrate_v1(self, con: "sqlite3.Connection") -> None:
        """Create full v5 schema for new databases, with WAL and FTS5."""
        con.execute("""
            CREATE TABLE IF NOT EXISTS test_runs (
                epoch_ns INTEGER PRIMARY KEY,
                exit_code INTEGER,
                command TEXT DEFAULT '',
                out_dir TEXT,
                timestamp_ns TEXT
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS test_artifacts (
                epoch_ns INTEGER NOT NULL,
                exit_code INTEGER,
                command TEXT DEFAULT '',
                filename TEXT,
                content TEXT,
                out_dir TEXT,
                timestamp_ns TEXT,
                full_path TEXT,
                PRIMARY KEY (epoch_ns, filename)
            )
        """)
        con.execute("INSERT INTO schema_version (version, applied_at) VALUES (1, datetime('now'))")
        # FTS5 tables and triggers are added by _migrate_v6

    def _migrate_v2(self, con: "sqlite3.Connection") -> None:
        """Add command and full_path columns to v1 databases (no-op for new databases)."""
        try:
            con.execute("ALTER TABLE test_runs ADD COLUMN command TEXT DEFAULT ''")
        except sqlite3.OperationalError:
            pass  # Column already exists
        try:
            con.execute("ALTER TABLE test_artifacts ADD COLUMN command TEXT DEFAULT ''")
        except sqlite3.OperationalError:
            pass
        try:
            con.execute("ALTER TABLE test_artifacts ADD COLUMN full_path TEXT")
        except sqlite3.OperationalError:
            pass
        con.execute("UPDATE test_artifacts SET full_path = out_dir || '/' || filename WHERE full_path IS NULL")
        con.execute("INSERT INTO schema_version (version, applied_at) VALUES (2, datetime('now'))")

    def _migrate_v3(self, con: "sqlite3.Connection") -> None:
        """Upgrade epoch-keyed v1/v2 databases to v5 schema (epoch_ns PK, exit_code in artifacts)."""
        cursor = con.execute("PRAGMA table_info(test_runs)")
        columns = {row[1] for row in cursor.fetchall()}
        if 'timestamp_ns' not in columns:
            # Disable FK enforcement during table reconstruction
            con.execute("PRAGMA foreign_keys = OFF")
            con.execute("ALTER TABLE test_artifacts RENAME TO test_artifacts_old")
            con.execute("ALTER TABLE test_runs RENAME TO test_runs_old")
            con.execute("""
                CREATE TABLE test_runs (
                    epoch_ns INTEGER PRIMARY KEY,
                    exit_code INTEGER,
                    command TEXT DEFAULT '',
                    out_dir TEXT,
                    timestamp_ns TEXT
                )
            """)
            con.execute("""
                INSERT OR IGNORE INTO test_runs (epoch_ns, exit_code, command, out_dir, timestamp_ns)
                SELECT epoch * 1000000000, exit_code, COALESCE(command, ''), out_dir,
                       CAST(epoch AS TEXT) || '.000000000+00:00'
                FROM test_runs_old
            """)
            con.execute("""
                CREATE TABLE test_artifacts (
                    epoch_ns INTEGER NOT NULL,
                    exit_code INTEGER,
                    command TEXT DEFAULT '',
                    filename TEXT,
                    content TEXT,
                    out_dir TEXT,
                    timestamp_ns TEXT,
                    full_path TEXT,
                    PRIMARY KEY (epoch_ns, filename)
                )
            """)
            con.execute("""
                INSERT OR IGNORE INTO test_artifacts
                    (epoch_ns, exit_code, command, filename, content, out_dir, timestamp_ns, full_path)
                SELECT ta.epoch * 1000000000,
                       COALESCE(tr.exit_code, 0),
                       COALESCE(ta.command, ''),
                       ta.filename, ta.content, ta.out_dir,
                       CAST(ta.epoch AS TEXT) || '.000000000+00:00',
                       COALESCE(ta.full_path, ta.out_dir || '/' || ta.filename)
                FROM test_artifacts_old ta
                LEFT JOIN test_runs_old tr ON ta.epoch = tr.epoch
            """)
            con.execute("DROP TABLE test_artifacts_old")
            con.execute("DROP TABLE test_runs_old")
            con.execute("PRAGMA foreign_keys = ON")
        con.execute("INSERT INTO schema_version (version, applied_at) VALUES (3, datetime('now'))")

    def _migrate_v4(self, con: "sqlite3.Connection") -> None:
        """Upgrade v3 databases (timestamp_ns PK, epoch seconds): convert to v5 schema with epoch_ns PK."""
        cursor = con.execute("PRAGMA table_info(test_runs)")
        columns = {row[1] for row in cursor.fetchall()}
        if 'epoch_ns' not in columns:
            con.execute("PRAGMA foreign_keys = OFF")
            con.execute("ALTER TABLE test_artifacts RENAME TO test_artifacts_old")
            con.execute("ALTER TABLE test_runs RENAME TO test_runs_old")
            con.execute("""
                CREATE TABLE test_runs (
                    epoch_ns INTEGER PRIMARY KEY,
                    command TEXT DEFAULT '',
                    exit_code INTEGER,
                    out_dir TEXT,
                    timestamp_ns TEXT
                )
            """)
            con.execute("""
                INSERT OR IGNORE INTO test_runs (epoch_ns, exit_code, command, out_dir, timestamp_ns)
                SELECT epoch * 1000000000, exit_code, COALESCE(command, ''), out_dir, timestamp_ns
                FROM test_runs_old
            """)
            con.execute("""
                CREATE TABLE test_artifacts (
                    epoch_ns INTEGER NOT NULL,
                    command TEXT DEFAULT '',
                    exit_code INTEGER,
                    filename TEXT,
                    content TEXT,
                    out_dir TEXT,
                    timestamp_ns TEXT,
                    full_path TEXT,
                    PRIMARY KEY (epoch_ns, filename)
                )
            """)
            con.execute("""
                INSERT OR IGNORE INTO test_artifacts
                    (epoch_ns, exit_code, command, filename, content, out_dir, timestamp_ns, full_path)
                SELECT ta.epoch * 1000000000,
                       COALESCE(tr.exit_code, 0),
                       COALESCE(ta.command, ''),
                       ta.filename, ta.content, ta.out_dir, ta.timestamp_ns,
                       COALESCE(ta.full_path, ta.out_dir || '/' || ta.filename)
                FROM test_artifacts_old ta
                LEFT JOIN test_runs_old tr ON ta.timestamp_ns = tr.timestamp_ns
            """)
            con.execute("DROP TABLE test_artifacts_old")
            con.execute("DROP TABLE test_runs_old")
            con.execute("PRAGMA foreign_keys = ON")
        con.execute("INSERT INTO schema_version (version, applied_at) VALUES (4, datetime('now'))")

    def _migrate_v5(self, con: "sqlite3.Connection") -> None:
        """Upgrade v4 databases (timestamp_ns PK, epoch_ns INTEGER): make epoch_ns PK, add exit_code to artifacts."""
        # Detect by checking if epoch_ns is the primary key in test_runs
        cursor = con.execute("PRAGMA table_info(test_runs)")
        rows = cursor.fetchall()
        epoch_ns_is_pk = any(row[1] == 'epoch_ns' and row[5] == 1 for row in rows)
        if not epoch_ns_is_pk:
            con.execute("PRAGMA foreign_keys = OFF")
            con.execute("ALTER TABLE test_artifacts RENAME TO test_artifacts_old")
            con.execute("ALTER TABLE test_runs RENAME TO test_runs_old")
            con.execute("""
                CREATE TABLE test_runs (
                    epoch_ns INTEGER PRIMARY KEY,
                    command TEXT DEFAULT '',
                    exit_code INTEGER,
                    out_dir TEXT,
                    timestamp_ns TEXT
                )
            """)
            con.execute("""
                INSERT OR IGNORE INTO test_runs (epoch_ns, exit_code, command, out_dir, timestamp_ns)
                SELECT epoch_ns, exit_code, COALESCE(command, ''), out_dir, timestamp_ns
                FROM test_runs_old
            """)
            con.execute("""
                CREATE TABLE test_artifacts (
                    epoch_ns INTEGER NOT NULL,
                    command TEXT DEFAULT '',
                    exit_code INTEGER,
                    filename TEXT,
                    content TEXT,
                    out_dir TEXT,
                    timestamp_ns TEXT,
                    full_path TEXT,
                    PRIMARY KEY (epoch_ns, filename)
                )
            """)
            con.execute("""
                INSERT OR IGNORE INTO test_artifacts
                    (epoch_ns, exit_code, command, filename, content, out_dir, timestamp_ns, full_path)
                SELECT ta.epoch_ns,
                       COALESCE(tr.exit_code, 0),
                       COALESCE(ta.command, ''),
                       ta.filename, ta.content, ta.out_dir, ta.timestamp_ns,
                       COALESCE(ta.full_path, ta.out_dir || '/' || ta.filename)
                FROM test_artifacts_old ta
                LEFT JOIN test_runs_old tr ON ta.epoch_ns = tr.epoch_ns
            """)
            con.execute("DROP TABLE test_artifacts_old")
            con.execute("DROP TABLE test_runs_old")
            con.execute("PRAGMA foreign_keys = ON")
        con.execute("INSERT INTO schema_version (version, applied_at) VALUES (5, datetime('now'))")

    def _migrate_v6(self, con: "sqlite3.Connection") -> None:
        """Add FTS5 content tables and sync triggers for Datasette auto-detection."""
        self._setup_fts_content_tables(con)
        con.execute("INSERT INTO schema_version (version, applied_at) VALUES (6, datetime('now'))")

    def _migrate_v8(self, con: "sqlite3.Connection") -> None:
        """Rebuild FTS as content tables so Datasette auto-detects them.

        DBs migrated through v6/v7 have standalone FTS5 tables (no content= option).
        Datasette only auto-detects FTS when CREATE VIRTUAL TABLE uses content=.
        For test_runs, epoch_ns INTEGER PRIMARY KEY is a rowid alias so
        content_rowid='epoch_ns' makes FTS rowid == epoch_ns for correct linkback.
        For test_artifacts (composite PK), FTS uses the table's internal rowid.
        """
        # Drop old standalone FTS tables and triggers
        for name in ('test_runs_fts', 'test_artifacts_fts'):
            con.execute(f"DROP TABLE IF EXISTS {name}")
        for t in ('test_runs_ai', 'test_runs_ad', 'test_runs_au',
                  'test_artifacts_ai', 'test_artifacts_ad', 'test_artifacts_au'):
            con.execute(f"DROP TRIGGER IF EXISTS {t}")
        self._setup_fts_content_tables(con)
        con.execute("INSERT INTO schema_version (version, applied_at) VALUES (8, datetime('now'))")

    def _setup_fts_content_tables(self, con: "sqlite3.Connection") -> None:
        """Create FTS5 content tables, populate them, and install sync triggers.

        Used by _migrate_v6 (new databases) and _migrate_v8 (upgrade path).
        """
        # test_runs: epoch_ns INTEGER PRIMARY KEY is a SQLite rowid alias.
        # content_rowid='epoch_ns' makes FTS rowid == epoch_ns so Datasette
        # can join back from FTS rowid to the source row correctly.
        con.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS test_runs_fts USING fts5(
                command, out_dir, timestamp_ns,
                content="test_runs",
                content_rowid="epoch_ns"
            )
        """)
        # test_artifacts: composite PK, so FTS uses the table's internal rowid.
        con.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS test_artifacts_fts USING fts5(
                epoch_ns UNINDEXED,
                command, filename, content, out_dir, timestamp_ns,
                content="test_artifacts"
            )
        """)
        # Populate
        try:
            con.execute("""
                INSERT INTO test_runs_fts(rowid, command, out_dir, timestamp_ns)
                SELECT epoch_ns, command, out_dir, timestamp_ns FROM test_runs
            """)
            con.execute("""
                INSERT INTO test_artifacts_fts(rowid, epoch_ns, command, filename, content, out_dir, timestamp_ns)
                SELECT rowid, epoch_ns, command, filename, content, out_dir, timestamp_ns FROM test_artifacts
            """)
        except sqlite3.OperationalError:
            pass  # empty tables on initial migration
        # Triggers — test_runs (rowid = epoch_ns for content table)
        con.execute("""
            CREATE TRIGGER IF NOT EXISTS test_runs_ai AFTER INSERT ON test_runs BEGIN
                INSERT INTO test_runs_fts(rowid, command, out_dir, timestamp_ns)
                VALUES (new.epoch_ns, new.command, new.out_dir, new.timestamp_ns);
            END
        """)
        con.execute("""
            CREATE TRIGGER IF NOT EXISTS test_runs_ad AFTER DELETE ON test_runs BEGIN
                INSERT INTO test_runs_fts(test_runs_fts, rowid, command, out_dir, timestamp_ns)
                VALUES ('delete', old.epoch_ns, old.command, old.out_dir, old.timestamp_ns);
            END
        """)
        con.execute("""
            CREATE TRIGGER IF NOT EXISTS test_runs_au AFTER UPDATE ON test_runs BEGIN
                INSERT INTO test_runs_fts(test_runs_fts, rowid, command, out_dir, timestamp_ns)
                VALUES ('delete', old.epoch_ns, old.command, old.out_dir, old.timestamp_ns);
                INSERT INTO test_runs_fts(rowid, command, out_dir, timestamp_ns)
                VALUES (new.epoch_ns, new.command, new.out_dir, new.timestamp_ns);
            END
        """)
        # Triggers — test_artifacts (rowid = source table internal rowid)
        con.execute("""
            CREATE TRIGGER IF NOT EXISTS test_artifacts_ai AFTER INSERT ON test_artifacts BEGIN
                INSERT INTO test_artifacts_fts(rowid, epoch_ns, command, filename, content, out_dir, timestamp_ns)
                VALUES (new.rowid, new.epoch_ns, new.command, new.filename, new.content, new.out_dir, new.timestamp_ns);
            END
        """)
        con.execute("""
            CREATE TRIGGER IF NOT EXISTS test_artifacts_ad AFTER DELETE ON test_artifacts BEGIN
                INSERT INTO test_artifacts_fts(test_artifacts_fts, rowid, epoch_ns, command, filename, content, out_dir, timestamp_ns)
                VALUES ('delete', old.rowid, old.epoch_ns, old.command, old.filename, old.content, old.out_dir, old.timestamp_ns);
            END
        """)
        con.execute("""
            CREATE TRIGGER IF NOT EXISTS test_artifacts_au AFTER UPDATE ON test_artifacts BEGIN
                INSERT INTO test_artifacts_fts(test_artifacts_fts, rowid, epoch_ns, command, filename, content, out_dir, timestamp_ns)
                VALUES ('delete', old.rowid, old.epoch_ns, old.command, old.filename, old.content, old.out_dir, old.timestamp_ns);
                INSERT INTO test_artifacts_fts(rowid, epoch_ns, command, filename, content, out_dir, timestamp_ns)
                VALUES (new.rowid, new.epoch_ns, new.command, new.filename, new.content, new.out_dir, new.timestamp_ns);
            END
        """)

    def _migrate_v7(self, con: "sqlite3.Connection") -> None:
        """Reorder columns: move exit_code before command."""
        cursor = con.execute("PRAGMA table_info(test_runs)")
        rows = cursor.fetchall()
        col_order = {row[1]: row[0] for row in rows}
        if col_order.get('exit_code', 2) > col_order.get('command', 1):
            # Drop FTS tables and triggers before renaming base tables
            for name in ('test_runs_fts', 'test_artifacts_fts'):
                con.execute(f"DROP TABLE IF EXISTS {name}")
            for t in ('test_runs_ai', 'test_runs_ad', 'test_runs_au',
                      'test_artifacts_ai', 'test_artifacts_ad', 'test_artifacts_au'):
                con.execute(f"DROP TRIGGER IF EXISTS {t}")
            con.execute("ALTER TABLE test_artifacts RENAME TO test_artifacts_old")
            con.execute("ALTER TABLE test_runs RENAME TO test_runs_old")
            con.execute("""
                CREATE TABLE test_runs (
                    epoch_ns INTEGER PRIMARY KEY,
                    exit_code INTEGER,
                    command TEXT DEFAULT '',
                    out_dir TEXT,
                    timestamp_ns TEXT
                )
            """)
            con.execute("""
                INSERT OR IGNORE INTO test_runs (epoch_ns, exit_code, command, out_dir, timestamp_ns)
                SELECT epoch_ns, exit_code, command, out_dir, timestamp_ns FROM test_runs_old
            """)
            con.execute("""
                CREATE TABLE test_artifacts (
                    epoch_ns INTEGER NOT NULL,
                    exit_code INTEGER,
                    command TEXT DEFAULT '',
                    filename TEXT,
                    content TEXT,
                    out_dir TEXT,
                    timestamp_ns TEXT,
                    full_path TEXT,
                    PRIMARY KEY (epoch_ns, filename)
                )
            """)
            con.execute("""
                INSERT OR IGNORE INTO test_artifacts
                    (epoch_ns, exit_code, command, filename, content, out_dir, timestamp_ns, full_path)
                SELECT epoch_ns, exit_code, command, filename, content, out_dir, timestamp_ns, full_path
                FROM test_artifacts_old
            """)
            con.execute("DROP TABLE test_artifacts_old")
            con.execute("DROP TABLE test_runs_old")
            # Recreate FTS tables and triggers inline (no schema_version insert)
            self._setup_fts_content_tables(con)
        con.execute("INSERT INTO schema_version (version, applied_at) VALUES (7, datetime('now'))")

    def insert_run(self, run: TertTestRun):
        """Store a test run record."""
        with sqlite3.connect(self.db_path) as con:
            sql = "INSERT OR REPLACE INTO test_runs (epoch_ns, exit_code, command, out_dir, timestamp_ns) VALUES (?, ?, ?, ?, ?)"
            params = (run.epoch_ns, run.exit_code, run.command, str(run.out_dir), run.timestamp_ns)
            logger.debug(f"SQL: {sql} with params {params}")
            con.execute(sql, params)
            con.commit()
    
    def insert_artifact(self, epoch_ns: int, timestamp_ns: str, out_dir: Path, filename: str, content: str, command: str = "", exit_code: int = 0):
        """Store a build artifact linked to a test run by epoch_ns."""
        full_path = str(out_dir / filename)
        with sqlite3.connect(self.db_path) as con:
            sql = "INSERT OR REPLACE INTO test_artifacts (epoch_ns, exit_code, command, filename, content, out_dir, timestamp_ns, full_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            params = (epoch_ns, exit_code, command, filename, content, str(out_dir), timestamp_ns, full_path)
            logger.debug(f"SQL: {sql} with params (epoch_ns={epoch_ns}, command={command}, exit_code={exit_code}, filename={filename}, content_len={len(content)}, out_dir={out_dir})")
            con.execute(sql, params)
            con.commit()
    
    def query_runs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent test runs, ordered by epoch_ns descending."""
        with sqlite3.connect(self.db_path) as con:
            sql = "SELECT epoch_ns, exit_code, command, out_dir, timestamp_ns FROM test_runs ORDER BY epoch_ns DESC LIMIT ?"
            logger.debug(f"SQL: {sql} with params (limit={limit})")
            rows = con.execute(sql, (limit,)).fetchall()
            return [
                {
                    'epoch_ns': row[0],
                    'exit_code': row[1],
                    'command': row[2],
                    'out_dir': row[3],
                    'timestamp_ns': row[4],
                }
                for row in rows
            ]
    
    def query_artifacts(self, out_dir: Optional[str] = None) -> List[Dict[str, Any]]:
        """List stored artifacts, ordered by epoch_ns descending."""
        query = "SELECT epoch_ns, exit_code, command, filename, length(content) as bytes, out_dir, timestamp_ns FROM test_artifacts"
        params: list = []
        if out_dir:
            query += " WHERE out_dir = ?"
            params.append(out_dir)
        query += " ORDER BY epoch_ns DESC, filename"

        logger.debug(f"SQL: {query} with params {params}")

        with sqlite3.connect(self.db_path) as con:
            rows = con.execute(query, params).fetchall()
            return [
                {
                    'epoch_ns': row[0],
                    'exit_code': row[1],
                    'command': row[2],
                    'filename': row[3],
                    'bytes': row[4],
                    'out_dir': row[5],
                    'timestamp_ns': row[6],
                }
                for row in rows
            ]


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


class ShRunner(TertTestRunner):
    """sh script runner."""

    def run(self, *args) -> int:
        """Run sh with Shellwrap for colored output."""
        cmd = _interpreter_cmd("sh", args)

        self.shellwrap.set_color_env()
        self.shellwrap.commands = [shlex.join(cmd)]
        return self.shellwrap.execute_streaming()


class BashRunner(TertTestRunner):
    """bash script runner."""

    def run(self, *args) -> int:
        """Run bash with Shellwrap for colored output."""
        cmd = _interpreter_cmd("bash", args)

        self.shellwrap.set_color_env()
        self.shellwrap.commands = [shlex.join(cmd)]
        return self.shellwrap.execute_streaming()


class ZshRunner(TertTestRunner):
    """zsh script runner."""

    def run(self, *args) -> int:
        """Run zsh with Shellwrap for colored output."""
        cmd = _interpreter_cmd("zsh", args)

        self.shellwrap.set_color_env()
        self.shellwrap.commands = [shlex.join(cmd)]
        return self.shellwrap.execute_streaming()


class PythonRunner(TertTestRunner):
    """python script runner."""

    def run(self, *args) -> int:
        """Run python with Shellwrap for colored output."""
        cmd = _interpreter_cmd(sys.executable, args, command_flag=None)

        self.shellwrap.set_color_env()
        self.shellwrap.commands = [shlex.join(cmd)]
        return self.shellwrap.execute_streaming()


class IpythonRunner(TertTestRunner):
    """ipython script runner."""

    def run(self, *args) -> int:
        """Run ipython with Shellwrap for colored output."""
        cmd = _interpreter_cmd("ipython", args, command_flag=None)

        self.shellwrap.set_color_env()
        self.shellwrap.commands = [shlex.join(cmd)]
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
        "sh": ShRunner,
        "bash": BashRunner,
        "zsh": ZshRunner,
        "python": PythonRunner,
        "ipython": IpythonRunner,
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
    ns = time.time_ns()
    epoch_ns = ns
    epoch_s = ns // 1_000_000_000
    timestamp_ns = _format_timestamp_ns(ns)
    out_dir_name = f"{epoch_s}-{datetime.fromtimestamp(epoch_s, tz=timezone.utc).strftime('%Y-%m-%dT%H-%M-%S+0000')}"
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
        timestamp_ns=timestamp_ns,
        epoch_ns=epoch_ns,
        exit_code=exit_code,
        out_dir=out_dir,
        command=command,
    )
    replog_db.insert_run(run)

    if not skip_artifacts:
        for artifact_path in test_runner.get_artifacts():
            if artifact_path.exists():
                content = artifact_path.read_text(errors="replace")
                replog_db.insert_artifact(epoch_ns, timestamp_ns, out_dir, artifact_path.name, content, command, exit_code)

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
    
    known_runners = ["pytest", "cargo", "go", "jest", "vitest", "tox", "sh", "bash", "zsh", "python", "ipython"]
    known_commands = ["run", "ls", "show", "query"]
    command_aliases = {"q": "query", "l": "ls", "s": "show"}
    subquery_aliases = {"l": "lines", "a": "artifacts", "r": "runs", "lines": "coverage-lines"}
    subquery_normalized = {"coverage-lines": "coverage-lines", "lines": "coverage-lines"}
    
    argv = sys.argv[1:]
    
    if (argv and len(argv[0]) > 1 and not argv[0].startswith("-")
            and argv[0] not in known_runners and argv[0] not in known_commands):
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
    run_parser.add_argument("--runner", default="pytest", choices=["pytest", "cargo", "go", "jest", "vitest", "tox", "sh", "bash", "zsh", "python", "ipython"], help="Test runner to use")
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
        
        if runner_args and runner_args[0] in known_runners:
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
