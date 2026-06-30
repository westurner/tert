#!/usr/bin/env python3
"""
tests/test_run_tests.py - Comprehensive test suite for run_tests.py

Uses pytest with parametrization, fixtures, mocks, and tmpdir.
Includes recursion protection to prevent pytest being called recursively.
"""

import os
import pytest
from unittest.mock import Mock, patch
import sqlite3

# Signal that tests are running to prevent recursion
os.environ["PYTEST_RUNNING"] = "1"

# Import the modules under test
from tert.run_tests import (
    ReplogDB,
    TertTestRun,
    _format_timestamp_ns,
    get_runner,
    PytestRunner,
    CargoRunner,
    GoRunner,
    run_tests,
    query_runs,
    query_artifacts,
    query_coverage_lines,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture(autouse=True)
def mock_subprocess_globally():
    """Global subprocess.run mock to prevent recursion (autouse)."""
    with patch("tert.run_tests.subprocess.run") as mock_run:
        mock_run.return_value = Mock(returncode=0)
        yield mock_run


@pytest.fixture
def tmp_reports_dir(tmp_path):
    """Temporary reports directory."""
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    return reports_dir


@pytest.fixture
def replog_db(tmp_reports_dir):
    """ReplogDB instance with temporary database."""
    db_path = tmp_reports_dir / "replog.db"
    return ReplogDB(db_path)


@pytest.fixture
def sample_test_run(tmp_reports_dir):
    """Sample TestRun object."""
    out_dir = tmp_reports_dir / "1704067200-2024-01-01T00-00-00+0000"
    out_dir.mkdir(parents=True, exist_ok=True)
    return TertTestRun(
        timestamp_ns="2024-01-01T00:00:00.000000000+00:00",
        epoch_ns=1704067200_000_000_000,
        exit_code=0,
        out_dir=out_dir,
    )


# ============================================================================
# TESTS: ReplogDB
# ============================================================================


class TestReplogDB:
    """Test ReplogDB functionality."""

    def test_init_creates_db(self, tmp_reports_dir):
        """Test that ReplogDB creates the database."""
        db_path = tmp_reports_dir / "test.db"
        db = ReplogDB(db_path)

        # 1. Verify file exists
        assert db_path.exists()

        # 2. Verify object state
        assert db.db_path == db_path

        # 3. Verify it's a valid SQLite database (check header)
        with open(db_path, "rb") as f:
            header = f.read(16)
            assert header.startswith(b"SQLite format 3"), (
                "Database file should have SQLite format header"
            )

        # 4. Verify schema by querying tables
        with sqlite3.connect(db_path) as con:
            cursor = con.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
            tables = [row[0] for row in cursor.fetchall()]
            assert "test_runs" in tables, "test_runs table should exist"
            assert "test_artifacts" in tables, "test_artifacts table should exist"
            assert "schema_version" in tables, "schema_version table should exist"

    def test_insert_and_query_runs(self, replog_db, sample_test_run):
        """Test inserting and querying test runs."""
        replog_db.insert_run(sample_test_run)
        runs = replog_db.query_runs()
        assert len(runs) == 1
        assert runs[0]["timestamp_ns"] == sample_test_run.timestamp_ns
        assert runs[0]["epoch_ns"] == sample_test_run.epoch_ns
        assert runs[0]["exit_code"] == 0

    def test_insert_and_query_artifacts(self, replog_db, sample_test_run):
        """Test inserting and querying artifacts."""
        replog_db.insert_run(sample_test_run)  # run must exist for FK
        replog_db.insert_artifact(
            sample_test_run.timestamp_ns,
            sample_test_run.epoch_ns,
            sample_test_run.out_dir,
            "build.log",
            "test content",
            "pytest tests/",
            sample_test_run.exit_code,
        )
        artifacts = replog_db.query_artifacts()
        assert len(artifacts) == 1
        assert artifacts[0]["filename"] == "build.log"
        assert artifacts[0]["bytes"] == len("test content")

    def test_query_artifacts_filter_by_outdir(self, replog_db, sample_test_run):
        """Test filtering artifacts by output directory."""
        replog_db.insert_run(sample_test_run)  # run must exist for FK
        replog_db.insert_artifact(
            sample_test_run.timestamp_ns,
            sample_test_run.epoch_ns,
            sample_test_run.out_dir,
            "build.log",
            "content1",
            "pytest tests/",
        )

        # Query with specific out_dir
        artifacts = replog_db.query_artifacts(str(sample_test_run.out_dir))
        assert len(artifacts) == 1

        # Query with different out_dir
        artifacts = replog_db.query_artifacts("/nonexistent/path")
        assert len(artifacts) == 0


# ============================================================================
# TESTS: Runners
# ============================================================================


@pytest.mark.parametrize(
    "runner_name,runner_class",
    [
        ("pytest", PytestRunner),
        ("cargo", CargoRunner),
        ("go", GoRunner),
    ],
)
def test_get_runner(runner_name, runner_class, tmp_path):
    """Test getting the correct runner."""
    runner = get_runner(runner_name, tmp_path)
    assert isinstance(runner, runner_class)


def test_get_runner_unknown(tmp_path):
    """Test that unknown runner raises ValueError."""
    with pytest.raises(ValueError, match="Unknown runner"):
        get_runner("unknown_runner", tmp_path)


@pytest.mark.parametrize("runner_name", ["pytest", "cargo", "go"])
def test_runner_creates_build_log(runner_name, tmp_path):
    """Test that runners create build.log artifact."""
    runner = get_runner(runner_name, tmp_path)
    assert runner.build_log == tmp_path / "build.log"


@patch("tert.run_tests.subprocess.Popen")
def test_pytest_runner_execute(mock_popen, tmp_path):
    """Test pytest runner execution."""
    mock_process = Mock()
    mock_process.stdout = iter([])
    mock_process.stderr = iter([])
    mock_process.wait.return_value = 0
    mock_popen.return_value = mock_process

    runner = PytestRunner(tmp_path)
    exit_code = runner.run("tests/")

    assert exit_code == 0
    # Verify Shellwrap was configured
    assert len(runner.artifacts) >= 1


@patch("tert.run_tests.subprocess.Popen")
def test_cargo_runner_execute(mock_popen, tmp_path):
    """Test cargo runner execution."""
    mock_process = Mock()
    mock_process.stdout = iter([])
    mock_process.stderr = iter([])
    mock_process.wait.return_value = 0
    mock_popen.return_value = mock_process

    runner = CargoRunner(tmp_path)
    exit_code = runner.run()

    assert exit_code == 0


class TestRunTests:
    """Test run_tests integration."""

    @patch("tert.run_tests.CargoRunner.run")
    def test_run_tests_stores_in_replog(self, mock_run, tmp_reports_dir, replog_db):
        """Test that run_tests stores results in replog."""
        mock_run.return_value = 0

        exit_code = run_tests("cargo", tmp_reports_dir, replog_db)

        assert exit_code == 0
        runs = replog_db.query_runs()
        assert len(runs) == 1
        assert runs[0]["exit_code"] == 0

    @patch("tert.run_tests.PytestRunner.run")
    def test_run_tests_propagates_exit_code(self, mock_run, tmp_reports_dir, replog_db):
        """Test that run_tests propagates runner exit code."""
        mock_run.return_value = 42

        exit_code = run_tests("pytest", tmp_reports_dir, replog_db)

        assert exit_code == 42
        runs = replog_db.query_runs()
        assert runs[0]["exit_code"] == 42

    @patch("tert.run_tests.CargoRunner.run")
    def test_run_tests_creates_latest_symlink(
        self, mock_run, tmp_reports_dir, replog_db
    ):
        """Test that run_tests creates latest symlink."""
        mock_run.return_value = 0

        run_tests("cargo", tmp_reports_dir, replog_db)

        latest_link = tmp_reports_dir / "latest"
        assert latest_link.is_symlink()


# ============================================================================
# TESTS: Query functions
# ============================================================================


def test_query_runs_returns_list(replog_db, sample_test_run):
    """Test that query_runs returns a list."""
    replog_db.insert_run(sample_test_run)
    runs = query_runs(replog_db)
    assert isinstance(runs, list)


def test_query_artifacts_returns_list(replog_db, sample_test_run):
    """Test that query_artifacts returns a list."""
    replog_db.insert_run(sample_test_run)  # run must exist for FK
    replog_db.insert_artifact(
        sample_test_run.epoch_ns,
        sample_test_run.timestamp_ns,
        sample_test_run.out_dir,
        "test.log",
        "content",
        "pytest tests/",
    )
    artifacts = query_artifacts(replog_db)
    assert isinstance(artifacts, list)


def test_query_artifacts_includes_byte_count(replog_db, sample_test_run):
    """Test that query_artifacts includes byte count."""
    replog_db.insert_run(sample_test_run)  # run must exist for FK
    content = "test content with some length"
    replog_db.insert_artifact(
        sample_test_run.epoch_ns,
        sample_test_run.timestamp_ns,
        sample_test_run.out_dir,
        "test.log",
        content,
        "pytest tests/",
    )
    artifacts = query_artifacts(replog_db)
    assert artifacts[0]["bytes"] == len(content)


class TestQueryCoverageLines:
    """Test coverage lines querying."""

    def test_query_coverage_lines_file_not_found(self, tmp_path):
        """Test that missing coverage db raises FileNotFoundError."""
        nonexistent_db = tmp_path / ".coverage"
        with pytest.raises(FileNotFoundError):
            query_coverage_lines(nonexistent_db)

    def test_query_coverage_lines_with_real_coverage_db(self, tmp_path):
        """Test querying coverage from a real coverage database."""
        # Create a mock .coverage database
        coverage_db = tmp_path / ".coverage"

        with sqlite3.connect(coverage_db) as con:
            # Create minimal schema
            con.execute("""
                CREATE TABLE IF NOT EXISTS file (
                    id INTEGER PRIMARY KEY,
                    path TEXT UNIQUE
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS line_bits (
                    file_id INTEGER,
                    numbits BLOB
                )
            """)
            con.commit()

            # Insert test data
            con.execute("INSERT INTO file (id, path) VALUES (1, 'test.py')")
            # Byte with bits 0,1,2 set = 0x07 (lines 1,2,3 covered)
            con.execute("INSERT INTO line_bits (file_id, numbits) VALUES (1, X'07')")
            con.commit()

        # Query the coverage
        result = query_coverage_lines(coverage_db)

        assert "test.py" in result
        assert result["test.py"] == [1, 2, 3]

    def test_query_coverage_lines_with_filter(self, tmp_path):
        """Test filtering coverage lines by path."""
        coverage_db = tmp_path / ".coverage"

        with sqlite3.connect(coverage_db) as con:
            con.execute(
                "CREATE TABLE IF NOT EXISTS file (id INTEGER PRIMARY KEY, path TEXT UNIQUE)"
            )
            con.execute(
                "CREATE TABLE IF NOT EXISTS line_bits (file_id INTEGER, numbits BLOB)"
            )
            con.execute("INSERT INTO file (id, path) VALUES (1, 'src/module.py')")
            con.execute("INSERT INTO file (id, path) VALUES (2, 'tests/test.py')")
            con.execute("INSERT INTO line_bits (file_id, numbits) VALUES (1, X'01')")
            con.execute("INSERT INTO line_bits (file_id, numbits) VALUES (2, X'02')")
            con.commit()

        result = query_coverage_lines(coverage_db, filter_path="src")

        # Should only include paths matching filter
        assert "src/module.py" in result
        assert "tests/test.py" not in result


class TestColorOutput:
    """Test color output functionality in test runners."""

    def test_shellwrap_set_color_env_enables_colors_when_always(self):
        """Test that set_color_env() enables colors when color_mode='always'."""
        from tert.shellwrap import Shellwrap
        import os

        # Save original env
        original_env = os.environ.copy()
        try:
            # Clear color vars
            for var in [
                "FORCE_COLOR",
                "CARGO_TERM_COLOR",
                "PYTEST_ADDOPTS",
                "NO_COLOR",
            ]:
                os.environ.pop(var, None)

            # Create Shellwrap with always color mode
            sw = Shellwrap(color_mode="always")
            sw.set_color_env()

            # Verify color environment variables are set
            assert os.environ.get("FORCE_COLOR") == "1", (
                "FORCE_COLOR should be set to '1'"
            )
            assert os.environ.get("CARGO_TERM_COLOR") == "always", (
                "CARGO_TERM_COLOR should be set to 'always'"
            )
            assert "--color=yes" in os.environ.get("PYTEST_ADDOPTS", ""), (
                "PYTEST_ADDOPTS should contain '--color=yes'"
            )
            assert "NO_COLOR" not in os.environ or os.environ.get("NO_COLOR") != "1", (
                "NO_COLOR should not be set when colors enabled"
            )
        finally:
            os.environ.clear()
            os.environ.update(original_env)

    def test_shellwrap_set_color_env_disables_colors_when_never(self):
        """Test that set_color_env() disables colors when color_mode='never'."""
        from tert.shellwrap import Shellwrap
        import os

        # Save original env
        original_env = os.environ.copy()
        try:
            # Set color vars first
            os.environ["FORCE_COLOR"] = "1"
            os.environ["CARGO_TERM_COLOR"] = "always"

            # Create Shellwrap with never color mode
            sw = Shellwrap(color_mode="never")
            sw.set_color_env()

            # Verify color environment variables are cleared
            assert os.environ.get("NO_COLOR") == "1", (
                "NO_COLOR should be set to '1' when colors disabled"
            )
            assert "FORCE_COLOR" not in os.environ, (
                "FORCE_COLOR should be removed when colors disabled"
            )
            assert "CARGO_TERM_COLOR" not in os.environ, (
                "CARGO_TERM_COLOR should be removed when colors disabled"
            )
        finally:
            os.environ.clear()
            os.environ.update(original_env)

    def test_pytest_runner_sets_color_env(self, tmp_path, mocker):
        """Test that PytestRunner calls set_color_env() during run."""
        from tert.run_tests import PytestRunner
        from tert.shellwrap import Shellwrap

        # Mock Shellwrap.execute_streaming to avoid actual execution
        mock_execute = mocker.patch.object(
            Shellwrap, "execute_streaming", return_value=0
        )
        mock_set_color = mocker.patch.object(Shellwrap, "set_color_env")

        runner = PytestRunner(tmp_path)
        runner.run("--co", "-q")

        # Verify set_color_env was called
        mock_set_color.assert_called_once()
        mock_execute.assert_called_once()

    def test_cargo_runner_sets_color_env(self, tmp_path, mocker):
        """Test that CargoRunner calls set_color_env() during run."""
        from tert.run_tests import CargoRunner
        from tert.shellwrap import Shellwrap

        # Mock Shellwrap.execute_streaming to avoid actual execution
        mock_execute = mocker.patch.object(
            Shellwrap, "execute_streaming", return_value=0
        )
        mock_set_color = mocker.patch.object(Shellwrap, "set_color_env")

        runner = CargoRunner(tmp_path)
        runner.run("--lib")

        # Verify set_color_env was called
        mock_set_color.assert_called_once()
        mock_execute.assert_called_once()

    def test_all_runners_have_color_mode_always(self, tmp_path):
        """Test that all runners initialize with color_mode='always'."""
        from tert.run_tests import (
            PytestRunner,
            CargoRunner,
            GoRunner,
            JestRunner,
            VitestRunner,
            ToxRunner,
        )

        runners = [
            PytestRunner(tmp_path),
            CargoRunner(tmp_path),
            GoRunner(tmp_path),
            JestRunner(tmp_path),
            VitestRunner(tmp_path),
            ToxRunner(tmp_path),
        ]

        for runner in runners:
            assert hasattr(runner, "shellwrap"), (
                f"{runner.__class__.__name__} should have shellwrap attribute"
            )
            assert runner.shellwrap.color_mode == "always", (
                f"{runner.__class__.__name__} should have color_mode='always'"
            )

    def test_shellwrap_color_mode_auto_detects_tty(self, mocker):
        """Test that auto color mode detects TTY correctly."""
        from tert.shellwrap import Shellwrap
        import sys
        import os

        # Save original env
        original_env = os.environ.copy()
        try:
            # Mock sys.stdout.isatty() to return True
            mocker.patch.object(sys.stdout, "isatty", return_value=True)

            for var in ["FORCE_COLOR", "CARGO_TERM_COLOR", "NO_COLOR"]:
                os.environ.pop(var, None)

            sw = Shellwrap(color_mode="auto")
            sw.set_color_env()

            # With isatty=True, should enable colors
            assert os.environ.get("FORCE_COLOR") == "1", (
                "Colors should be enabled when TTY detected"
            )

            # Now mock isatty to return False
            mocker.patch.object(sys.stdout, "isatty", return_value=False)

            for var in ["FORCE_COLOR", "CARGO_TERM_COLOR", "NO_COLOR"]:
                os.environ.pop(var, None)

            sw = Shellwrap(color_mode="auto")
            sw.set_color_env()

            # With isatty=False, should disable colors
            assert os.environ.get("NO_COLOR") == "1", (
                "Colors should be disabled when not a TTY"
            )
        finally:
            os.environ.clear()
            os.environ.update(original_env)


# ============================================================================
# TESTS: _format_timestamp_ns
# ============================================================================


class TestFormatTimestampNs:
    """Test _format_timestamp_ns helper."""

    def test_format_has_nine_decimal_places(self):
        """Output must have 9-digit nanosecond fraction."""
        ts = _format_timestamp_ns(0)
        dot_idx = ts.index(".")
        nano_part = ts[dot_idx + 1 : dot_idx + 10]
        assert len(nano_part) == 9
        assert nano_part.isdigit()

    def test_format_ends_with_utc_offset(self):
        """Output must end with +00:00."""
        ts = _format_timestamp_ns(1_000_000_000)
        assert ts.endswith("+00:00")

    def test_format_epoch_zero(self):
        """Epoch 0 maps to 1970-01-01T00:00:00."""
        ts = _format_timestamp_ns(0)
        assert ts.startswith("1970-01-01T00:00:00.")

    def test_format_nanoseconds_preserved(self):
        """Sub-second nanoseconds are encoded correctly."""
        # 1 second + 123456789 nanoseconds
        ns = 1_000_000_000 + 123_456_789
        ts = _format_timestamp_ns(ns)
        assert ".123456789+00:00" in ts

    def test_format_whole_seconds(self):
        """Whole-second timestamps have all-zero nanoseconds."""
        ns = 1_704_067_200 * 1_000_000_000  # 2024-01-01T00:00:00 UTC
        ts = _format_timestamp_ns(ns)
        assert ".000000000+00:00" in ts


# ============================================================================
# TESTS: Schema v3 migration
# ============================================================================


class TestMigrateV3:
    """Test migration from epoch-keyed v2 databases to timestamp_ns PK."""

    def _make_v2_db(self, db_path):
        """Create a minimal v2-style database with epoch as PK."""
        import sqlite3 as _sqlite3

        with _sqlite3.connect(db_path) as con:
            con.executescript("""
                CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT);
                INSERT INTO schema_version VALUES (2, datetime('now'));
                CREATE TABLE test_runs (
                    epoch INTEGER PRIMARY KEY, exit_code INTEGER,
                    command TEXT DEFAULT '', timestamp TEXT, out_dir TEXT
                );
                CREATE TABLE test_artifacts (
                    epoch INTEGER, out_dir TEXT, filename TEXT, content TEXT,
                    command TEXT DEFAULT '', full_path TEXT,
                    PRIMARY KEY (epoch, filename)
                );
                INSERT INTO test_runs VALUES (1700000000, 0, 'pytest', '2023-11-14', 'reports/r1');
                INSERT INTO test_artifacts
                    VALUES (1700000000, 'reports/r1', 'build.log', 'data', 'pytest', 'reports/r1/build.log');
            """)

    def test_migrate_v3_upgrades_epoch_schema(self, tmp_path):
        """ReplogDB opens a v2 db and upgrades it to v3 (timestamp_ns PK)."""
        db_path = tmp_path / "v2.db"
        self._make_v2_db(str(db_path))

        db = ReplogDB(db_path)
        runs = db.query_runs()
        assert len(runs) == 1
        assert runs[0]["timestamp_ns"].endswith(".000000000+00:00"), (
            "migrated timestamp_ns must have nanosecond suffix"
        )

    def test_migrate_v3_preserves_artifacts(self, tmp_path):
        """Artifacts survive v3→v5 migration and keep FK linkage."""
        db_path = tmp_path / "v2art.db"
        self._make_v2_db(str(db_path))

        db = ReplogDB(db_path)
        artifacts = db.query_artifacts()
        assert len(artifacts) == 1
        runs = db.query_runs()
        assert artifacts[0]["epoch_ns"] == runs[0]["epoch_ns"], (
            "migrated artifact must link to its run via epoch_ns (FK)"
        )

    def test_migrate_v3_is_idempotent(self, tmp_path):
        """Opening an already-v3 database twice does not corrupt it."""
        db_path = tmp_path / "v3.db"
        db1 = ReplogDB(db_path)
        run = TertTestRun(
            timestamp_ns="2024-06-01T00:00:00.000000000+00:00",
            epoch_ns=1717200000_000_000_000,
            exit_code=0,
            out_dir=tmp_path / "run",
        )
        db1.insert_run(run)

        db2 = ReplogDB(db_path)  # re-open triggers _ensure_schema again
        runs = db2.query_runs()
        assert len(runs) == 1

    def test_schema_version_is_5_after_migration(self, tmp_path):
        """schema_version table must record version 5+ after migration."""
        import sqlite3 as _sqlite3

        db_path = tmp_path / "ver.db"
        self._make_v2_db(str(db_path))
        ReplogDB(db_path)  # trigger migration

        with _sqlite3.connect(db_path) as con:
            version = con.execute("SELECT MAX(version) FROM schema_version").fetchone()[
                0
            ]
        assert version >= 7


# ============================================================================
# TESTS: timestamp_ns FK relationship
# ============================================================================


class TestTimestampNsForeignKey:
    """Test that test_artifacts are linked to test_runs via timestamp_ns."""

    def test_artifacts_share_run_timestamp_ns(self, replog_db, sample_test_run):
        """Multiple artifacts for one run all carry the run's timestamp_ns."""
        replog_db.insert_run(sample_test_run)
        for fname in ["build.log", "coverage.json", "results.xml"]:
            replog_db.insert_artifact(
                sample_test_run.epoch_ns,
                sample_test_run.timestamp_ns,
                sample_test_run.out_dir,
                fname,
                "content",
                "pytest",
                sample_test_run.exit_code,
            )

        artifacts = replog_db.query_artifacts()
        assert len(artifacts) == 3
        for a in artifacts:
            assert a["epoch_ns"] == sample_test_run.epoch_ns

    def test_query_runs_ordered_by_timestamp_ns(self, replog_db):
        """query_runs returns rows in timestamp_ns DESC order."""
        runs_data = [
            ("2024-01-01T00:00:00.000000001+00:00", 1704067200_000_000_001, 0),
            ("2024-01-01T00:00:00.000000003+00:00", 1704067202_000_000_003, 0),
            ("2024-01-01T00:00:00.000000002+00:00", 1704067201_000_000_002, 1),
        ]
        for ts, epoch_ns, ec in runs_data:
            replog_db.insert_run(
                TertTestRun(
                    timestamp_ns=ts,
                    epoch_ns=epoch_ns,
                    exit_code=ec,
                    out_dir=replog_db.db_path.parent / f"run{epoch_ns}",
                )
            )

        runs = replog_db.query_runs()
        assert len(runs) == 3
        # Must be sorted descending by timestamp_ns
        timestamps = [r["timestamp_ns"] for r in runs]
        assert timestamps == sorted(timestamps, reverse=True)
