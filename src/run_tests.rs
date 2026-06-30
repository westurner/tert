/// run_tests.rs - Rust port of run_tests.py
/// 
/// Test runner harness with timestamped reports and SQLite database.
/// Supports multiple test runners (pytest, cargo, go, jest, vitest, tox)
/// and stores test results, coverage data, and artifacts in SQLite for querying.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};

/// Metadata for a single test run
#[derive(Debug, Clone)]
pub struct TestRun {
    pub timestamp_ns: String,
    pub epoch_ns: u64,
    pub exit_code: i32,
    pub out_dir: PathBuf,
    pub command: String,
}

/// SQLite database for storing test runs and artifacts
pub struct ReplogDB {
    db_path: PathBuf,
}

impl ReplogDB {
    /// Create or open a replog database
    pub fn new(db_path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let db_path = db_path.as_ref().to_path_buf();
        
        // Create parent directories
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent).ok();
        }
        
        let replog = ReplogDB { db_path };
        replog.ensure_schema()?;
        
        Ok(replog)
    }
    
    /// Ensure database schema exists, with auto-migration
    fn ensure_schema(&self) -> rusqlite::Result<()> {
        // Enable WAL mode first (persists in the db file)
        {
            let wal_conn = Connection::open(&self.db_path)?;
            wal_conn.execute_batch("PRAGMA journal_mode = WAL")?;
        }

        let conn = Connection::open(&self.db_path)?;

        conn.execute("PRAGMA foreign_keys = ON", [])?;

        // Create schema version tracking table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT
            )",
            [],
        )?;

        // Get current schema version (default to 0 if not found)
        let current_version: u32 = conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get::<_, Option<u32>>(0).map(|v| v.unwrap_or(0))
            })
            .unwrap_or(0);

        // Apply migrations as needed
        if current_version < 1 {
            self.migrate_to_v1(&conn)?;
        }
        if current_version < 2 {
            self.migrate_to_v2(&conn)?;
        }
        if current_version < 3 {
            self.migrate_to_v3(&conn)?;
        }
        if current_version < 4 {
            self.migrate_to_v4(&conn)?;
        }
        if current_version < 5 {
            self.migrate_to_v5(&conn)?;
        }
        if current_version < 6 {
            self.migrate_to_v6(&conn)?;
        }
        if current_version < 7 {
            self.migrate_to_v7(&conn)?;
        }
        if current_version < 8 {
            self.migrate_to_v8(&conn)?;
        }

        Ok(())
    }
    
    /// Migration to v1: Create full v5 schema for new databases (FTS added by v6)
    fn migrate_to_v1(&self, conn: &Connection) -> rusqlite::Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS test_runs (
                epoch_ns INTEGER PRIMARY KEY,
                exit_code INTEGER,
                command TEXT DEFAULT '',
                out_dir TEXT,
                timestamp_ns TEXT
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS test_artifacts (
                epoch_ns INTEGER NOT NULL,
                exit_code INTEGER,
                command TEXT DEFAULT '',
                filename TEXT,
                content TEXT,
                out_dir TEXT,
                timestamp_ns TEXT,
                full_path TEXT,
                PRIMARY KEY (epoch_ns, filename)
            )",
            [],
        )?;

        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?, datetime('now'))",
            [1],
        )?;

        Ok(())
    }
    
    /// Migration to v2: Add command and full_path columns to existing v1 databases
    fn migrate_to_v2(&self, conn: &Connection) -> rusqlite::Result<()> {
        // Add command column to test_runs (no-op for new databases, upgrades old v1 dbs)
        conn.execute(
            "ALTER TABLE test_runs ADD COLUMN command TEXT DEFAULT ''",
            [],
        ).ok(); // Ignore if column already exists

        // Add command and full_path columns to test_artifacts (no-op for new databases)
        conn.execute(
            "ALTER TABLE test_artifacts ADD COLUMN command TEXT DEFAULT ''",
            [],
        ).ok(); // Ignore if column already exists

        conn.execute(
            "ALTER TABLE test_artifacts ADD COLUMN full_path TEXT",
            [],
        ).ok(); // Ignore if column already exists

        // Populate full_path for existing artifacts (out_dir/filename)
        conn.execute(
            "UPDATE test_artifacts SET full_path = out_dir || '/' || filename WHERE full_path IS NULL",
            [],
        )?;

        // Record migration
        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?, datetime('now'))",
            [2],
        )?;

        Ok(())
    }

    /// Migration to v3: Upgrade epoch-keyed v1/v2 databases to v5 schema (epoch_ns PK, exit_code in artifacts)
    fn migrate_to_v3(&self, conn: &Connection) -> rusqlite::Result<()> {
        let has_timestamp_ns: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('test_runs') WHERE name = 'timestamp_ns'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0;

        if !has_timestamp_ns {
            conn.execute("PRAGMA foreign_keys = OFF", [])?;
            conn.execute("ALTER TABLE test_artifacts RENAME TO test_artifacts_old", [])?;
            conn.execute("ALTER TABLE test_runs RENAME TO test_runs_old", [])?;

            conn.execute(
                "CREATE TABLE test_runs (
                    epoch_ns INTEGER PRIMARY KEY,
                    exit_code INTEGER,
                    command TEXT DEFAULT '',
                    out_dir TEXT,
                    timestamp_ns TEXT
                )",
                [],
            )?;
            conn.execute(
                "INSERT OR IGNORE INTO test_runs (epoch_ns, exit_code, command, out_dir, timestamp_ns)
                 SELECT epoch * 1000000000, exit_code, COALESCE(command, ''), out_dir,
                        CAST(epoch AS TEXT) || '.000000000+00:00'
                 FROM test_runs_old",
                [],
            )?;

            conn.execute(
                "CREATE TABLE test_artifacts (
                    epoch_ns INTEGER NOT NULL,
                    exit_code INTEGER,
                    command TEXT DEFAULT '',
                    filename TEXT,
                    content TEXT,
                    out_dir TEXT,
                    timestamp_ns TEXT,
                    full_path TEXT,
                    PRIMARY KEY (epoch_ns, filename)
                )",
                [],
            )?;
            conn.execute(
                "INSERT OR IGNORE INTO test_artifacts
                    (epoch_ns, exit_code, command, filename, content, out_dir, timestamp_ns, full_path)
                 SELECT ta.epoch * 1000000000, COALESCE(tr.exit_code, 0),
                        COALESCE(ta.command, ''),
                        ta.filename, ta.content, ta.out_dir,
                        CAST(ta.epoch AS TEXT) || '.000000000+00:00',
                        COALESCE(ta.full_path, ta.out_dir || '/' || ta.filename)
                 FROM test_artifacts_old ta
                 LEFT JOIN test_runs_old tr ON ta.epoch = tr.epoch",
                [],
            )?;

            conn.execute("DROP TABLE test_artifacts_old", [])?;
            conn.execute("DROP TABLE test_runs_old", [])?;
            conn.execute("PRAGMA foreign_keys = ON", [])?;
        }

        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?, datetime('now'))",
            [3],
        )?;

        Ok(())
    }

    /// Migration to v4: Convert epoch (seconds) column to epoch_ns (nanoseconds), upgrade to v5 schema
    fn migrate_to_v4(&self, conn: &Connection) -> rusqlite::Result<()> {
        let has_epoch_ns: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('test_runs') WHERE name = 'epoch_ns'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0;

        if !has_epoch_ns {
            conn.execute("PRAGMA foreign_keys = OFF", [])?;
            conn.execute("ALTER TABLE test_artifacts RENAME TO test_artifacts_old", [])?;
            conn.execute("ALTER TABLE test_runs RENAME TO test_runs_old", [])?;

            conn.execute(
                "CREATE TABLE test_runs (
                    epoch_ns INTEGER PRIMARY KEY,
                    command TEXT DEFAULT '',
                    exit_code INTEGER,
                    out_dir TEXT,
                    timestamp_ns TEXT
                )",
                [],
            )?;
            conn.execute(
                "INSERT OR IGNORE INTO test_runs (epoch_ns, exit_code, command, out_dir, timestamp_ns)
                 SELECT epoch * 1000000000, exit_code, COALESCE(command, ''), out_dir, timestamp_ns
                 FROM test_runs_old",
                [],
            )?;

            conn.execute(
                "CREATE TABLE test_artifacts (
                    epoch_ns INTEGER NOT NULL,
                    command TEXT DEFAULT '',
                    exit_code INTEGER,
                    filename TEXT,
                    content TEXT,
                    out_dir TEXT,
                    timestamp_ns TEXT,
                    full_path TEXT,
                    PRIMARY KEY (epoch_ns, filename)
                )",
                [],
            )?;
            conn.execute(
                "INSERT OR IGNORE INTO test_artifacts
                    (epoch_ns, exit_code, command, filename, content, out_dir, timestamp_ns, full_path)
                 SELECT ta.epoch * 1000000000, COALESCE(tr.exit_code, 0),
                        COALESCE(ta.command, ''),
                        ta.filename, ta.content, ta.out_dir, ta.timestamp_ns,
                        COALESCE(ta.full_path, ta.out_dir || '/' || ta.filename)
                 FROM test_artifacts_old ta
                 LEFT JOIN test_runs_old tr ON ta.timestamp_ns = tr.timestamp_ns",
                [],
            )?;

            conn.execute("DROP TABLE test_artifacts_old", [])?;
            conn.execute("DROP TABLE test_runs_old", [])?;
            conn.execute("PRAGMA foreign_keys = ON", [])?;
        }

        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?, datetime('now'))",
            [4],
        )?;

        Ok(())
    }

    /// Migration to v5: Make epoch_ns the primary key and add exit_code to test_artifacts
    fn migrate_to_v5(&self, conn: &Connection) -> rusqlite::Result<()> {
        // Detect v4-era schema: epoch_ns exists but is NOT the primary key
        let epoch_ns_is_pk: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('test_runs') WHERE name = 'epoch_ns' AND pk = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0;

        if !epoch_ns_is_pk {
            conn.execute("PRAGMA foreign_keys = OFF", [])?;
            conn.execute("ALTER TABLE test_artifacts RENAME TO test_artifacts_old", [])?;
            conn.execute("ALTER TABLE test_runs RENAME TO test_runs_old", [])?;

            conn.execute(
                "CREATE TABLE test_runs (
                    epoch_ns INTEGER PRIMARY KEY,
                    command TEXT DEFAULT '',
                    exit_code INTEGER,
                    out_dir TEXT,
                    timestamp_ns TEXT
                )",
                [],
            )?;
            conn.execute(
                "INSERT OR IGNORE INTO test_runs (epoch_ns, exit_code, command, out_dir, timestamp_ns)
                 SELECT epoch_ns, exit_code, COALESCE(command, ''), out_dir, timestamp_ns
                 FROM test_runs_old",
                [],
            )?;

            conn.execute(
                "CREATE TABLE test_artifacts (
                    epoch_ns INTEGER NOT NULL,
                    command TEXT DEFAULT '',
                    exit_code INTEGER,
                    filename TEXT,
                    content TEXT,
                    out_dir TEXT,
                    timestamp_ns TEXT,
                    full_path TEXT,
                    PRIMARY KEY (epoch_ns, filename)
                )",
                [],
            )?;
            conn.execute(
                "INSERT OR IGNORE INTO test_artifacts
                    (epoch_ns, exit_code, command, filename, content, out_dir, timestamp_ns, full_path)
                 SELECT ta.epoch_ns, COALESCE(tr.exit_code, 0),
                        COALESCE(ta.command, ''),
                        ta.filename, ta.content, ta.out_dir, ta.timestamp_ns,
                        COALESCE(ta.full_path, ta.out_dir || '/' || ta.filename)
                 FROM test_artifacts_old ta
                 LEFT JOIN test_runs_old tr ON ta.epoch_ns = tr.epoch_ns",
                [],
            )?;

            conn.execute("DROP TABLE test_artifacts_old", [])?;
            conn.execute("DROP TABLE test_runs_old", [])?;
            conn.execute("PRAGMA foreign_keys = ON", [])?;
        }

        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?, datetime('now'))",
            [5],
        )?;

        Ok(())
    }

    /// Migration to v6: Enable WAL and add FTS5 content tables for datasette full-text search
    fn migrate_to_v6(&self, conn: &Connection) -> rusqlite::Result<()> {
        self.setup_fts_content_tables(conn)?;

        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?, datetime('now'))",
            [6],
        )?;

        Ok(())
    }

    /// Migration to v7: Reorder columns — move exit_code before command
    fn migrate_to_v7(&self, conn: &Connection) -> rusqlite::Result<()> {
        // Check if exit_code comes after command (needs reordering)
        let exit_code_pos: i64 = conn
            .query_row(
                "SELECT cid FROM pragma_table_info('test_runs') WHERE name = 'exit_code'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(2);
        let command_pos: i64 = conn
            .query_row(
                "SELECT cid FROM pragma_table_info('test_runs') WHERE name = 'command'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(1);

        if exit_code_pos > command_pos {
            // Drop FTS tables and triggers before renaming
            conn.execute_batch(
                "DROP TABLE IF EXISTS test_runs_fts;
                 DROP TABLE IF EXISTS test_artifacts_fts;
                 DROP TRIGGER IF EXISTS test_runs_ai;
                 DROP TRIGGER IF EXISTS test_runs_ad;
                 DROP TRIGGER IF EXISTS test_runs_au;
                 DROP TRIGGER IF EXISTS test_artifacts_ai;
                 DROP TRIGGER IF EXISTS test_artifacts_ad;
                 DROP TRIGGER IF EXISTS test_artifacts_au;"
            )?;
            conn.execute("ALTER TABLE test_artifacts RENAME TO test_artifacts_old", [])?;
            conn.execute("ALTER TABLE test_runs RENAME TO test_runs_old", [])?;

            conn.execute(
                "CREATE TABLE test_runs (
                    epoch_ns INTEGER PRIMARY KEY,
                    exit_code INTEGER,
                    command TEXT DEFAULT '',
                    out_dir TEXT,
                    timestamp_ns TEXT
                )",
                [],
            )?;
            conn.execute(
                "INSERT OR IGNORE INTO test_runs (epoch_ns, exit_code, command, out_dir, timestamp_ns)
                 SELECT epoch_ns, exit_code, command, out_dir, timestamp_ns FROM test_runs_old",
                [],
            )?;

            conn.execute(
                "CREATE TABLE test_artifacts (
                    epoch_ns INTEGER NOT NULL,
                    exit_code INTEGER,
                    command TEXT DEFAULT '',
                    filename TEXT,
                    content TEXT,
                    out_dir TEXT,
                    timestamp_ns TEXT,
                    full_path TEXT,
                    PRIMARY KEY (epoch_ns, filename)
                )",
                [],
            )?;
            conn.execute(
                "INSERT OR IGNORE INTO test_artifacts
                    (epoch_ns, exit_code, command, filename, content, out_dir, timestamp_ns, full_path)
                 SELECT epoch_ns, exit_code, command, filename, content, out_dir, timestamp_ns, full_path
                 FROM test_artifacts_old",
                [],
            )?;

            conn.execute("DROP TABLE test_artifacts_old", [])?;
            conn.execute("DROP TABLE test_runs_old", [])?;

            // Recreate FTS tables and triggers
            self.migrate_to_v6(conn)?;
            // Remove the version 6 record just inserted by migrate_to_v6
            conn.execute("DELETE FROM schema_version WHERE version = 6", []).ok();
        }

        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?, datetime('now'))",
            [7],
        )?;

        Ok(())
    }

    /// Migration to v8: Rebuild FTS tables as content tables so Datasette auto-detects them.
    ///
    /// Databases upgraded through v6/v7 have standalone FTS5 tables (no `content=` option).
    /// Datasette only auto-detects FTS when the virtual table uses `content="source_table"`.
    /// For test_runs the FTS rowid must equal epoch_ns (which is the INTEGER PRIMARY KEY /
    /// rowid alias), so we use `content_rowid="epoch_ns"`.  For test_artifacts the FTS rowid
    /// maps to the table's internal rowid (composite PK, so no alias).
    fn migrate_to_v8(&self, conn: &Connection) -> rusqlite::Result<()> {
        // Drop old standalone FTS tables and their triggers
        conn.execute_batch(
            "DROP TABLE IF EXISTS test_runs_fts;
             DROP TABLE IF EXISTS test_artifacts_fts;
             DROP TRIGGER IF EXISTS test_runs_ai;
             DROP TRIGGER IF EXISTS test_runs_ad;
             DROP TRIGGER IF EXISTS test_runs_au;
             DROP TRIGGER IF EXISTS test_artifacts_ai;
             DROP TRIGGER IF EXISTS test_artifacts_ad;
             DROP TRIGGER IF EXISTS test_artifacts_au;"
        )?;

        // Recreate as content tables and repopulate
        self.setup_fts_content_tables(conn)?;

        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?, datetime('now'))",
            [8],
        )?;

        Ok(())
    }

    /// Create FTS5 content tables, populate them, and install sync triggers.
    /// Used by migrate_to_v6 (new databases) and migrate_to_v8 (upgrade path).
    fn setup_fts_content_tables(&self, conn: &Connection) -> rusqlite::Result<()> {
        conn.execute(
            "CREATE VIRTUAL TABLE IF NOT EXISTS test_runs_fts USING fts5(
                command, out_dir, timestamp_ns,
                content=\"test_runs\",
                content_rowid=\"epoch_ns\"
            )",
            [],
        )?;
        conn.execute(
            "CREATE VIRTUAL TABLE IF NOT EXISTS test_artifacts_fts USING fts5(
                epoch_ns UNINDEXED,
                command, filename, content, out_dir, timestamp_ns,
                content=\"test_artifacts\"
            )",
            [],
        )?;

        conn.execute_batch(
            "INSERT INTO test_runs_fts(rowid, command, out_dir, timestamp_ns)
             SELECT epoch_ns, command, out_dir, timestamp_ns FROM test_runs"
        )?;
        conn.execute_batch(
            "INSERT INTO test_artifacts_fts(rowid, epoch_ns, command, filename, content, out_dir, timestamp_ns)
             SELECT rowid, epoch_ns, command, filename, content, out_dir, timestamp_ns FROM test_artifacts"
        )?;

        conn.execute(
            "CREATE TRIGGER IF NOT EXISTS test_runs_ai AFTER INSERT ON test_runs BEGIN
                INSERT INTO test_runs_fts(rowid, command, out_dir, timestamp_ns)
                VALUES (new.epoch_ns, new.command, new.out_dir, new.timestamp_ns);
            END",
            [],
        )?;
        conn.execute(
            "CREATE TRIGGER IF NOT EXISTS test_runs_ad AFTER DELETE ON test_runs BEGIN
                INSERT INTO test_runs_fts(test_runs_fts, rowid, command, out_dir, timestamp_ns)
                VALUES ('delete', old.epoch_ns, old.command, old.out_dir, old.timestamp_ns);
            END",
            [],
        )?;
        conn.execute(
            "CREATE TRIGGER IF NOT EXISTS test_runs_au AFTER UPDATE ON test_runs BEGIN
                INSERT INTO test_runs_fts(test_runs_fts, rowid, command, out_dir, timestamp_ns)
                VALUES ('delete', old.epoch_ns, old.command, old.out_dir, old.timestamp_ns);
                INSERT INTO test_runs_fts(rowid, command, out_dir, timestamp_ns)
                VALUES (new.epoch_ns, new.command, new.out_dir, new.timestamp_ns);
            END",
            [],
        )?;
        conn.execute(
            "CREATE TRIGGER IF NOT EXISTS test_artifacts_ai AFTER INSERT ON test_artifacts BEGIN
                INSERT INTO test_artifacts_fts(rowid, epoch_ns, command, filename, content, out_dir, timestamp_ns)
                VALUES (new.rowid, new.epoch_ns, new.command, new.filename, new.content, new.out_dir, new.timestamp_ns);
            END",
            [],
        )?;
        conn.execute(
            "CREATE TRIGGER IF NOT EXISTS test_artifacts_ad AFTER DELETE ON test_artifacts BEGIN
                INSERT INTO test_artifacts_fts(test_artifacts_fts, rowid, epoch_ns, command, filename, content, out_dir, timestamp_ns)
                VALUES ('delete', old.rowid, old.epoch_ns, old.command, old.filename, old.content, old.out_dir, old.timestamp_ns);
            END",
            [],
        )?;
        conn.execute(
            "CREATE TRIGGER IF NOT EXISTS test_artifacts_au AFTER UPDATE ON test_artifacts BEGIN
                INSERT INTO test_artifacts_fts(test_artifacts_fts, rowid, epoch_ns, command, filename, content, out_dir, timestamp_ns)
                VALUES ('delete', old.rowid, old.epoch_ns, old.command, old.filename, old.content, old.out_dir, old.timestamp_ns);
                INSERT INTO test_artifacts_fts(rowid, epoch_ns, command, filename, content, out_dir, timestamp_ns)
                VALUES (new.rowid, new.epoch_ns, new.command, new.filename, new.content, new.out_dir, new.timestamp_ns);
            END",
            [],
        )?;

        Ok(())
    }

    /// Insert a test run record
    pub fn insert_run(&self, run: &TestRun) -> rusqlite::Result<()> {
        let conn = Connection::open(&self.db_path)?;
        conn.execute("PRAGMA foreign_keys = ON", [])?;

        conn.execute(
            "INSERT OR REPLACE INTO test_runs (epoch_ns, exit_code, command, out_dir, timestamp_ns) VALUES (?, ?, ?, ?, ?)",
            params![run.epoch_ns, run.exit_code, &run.command, run.out_dir.to_string_lossy(), &run.timestamp_ns],
        )?;

        Ok(())
    }
    
    /// Insert a test artifact linked to a test run by epoch_ns
    pub fn insert_artifact(
        &self,
        epoch_ns: u64,
        timestamp_ns: &str,
        out_dir: &Path,
        filename: &str,
        content: &str,
        command: &str,
        exit_code: i32,
    ) -> rusqlite::Result<()> {
        let conn = Connection::open(&self.db_path)?;
        conn.execute("PRAGMA foreign_keys = ON", [])?;

        let full_path = format!("{}/{}", out_dir.display(), filename);

        conn.execute(
            "INSERT OR REPLACE INTO test_artifacts (epoch_ns, exit_code, command, filename, content, out_dir, timestamp_ns, full_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![epoch_ns, exit_code, command, filename, content, out_dir.to_string_lossy(), timestamp_ns, &full_path],
        )?;

        Ok(())
    }
    
    /// Query all test runs, ordered by epoch_ns descending
    pub fn query_runs(&self) -> rusqlite::Result<Vec<TestRun>> {
        let conn = Connection::open(&self.db_path)?;
        let mut stmt = conn.prepare(
            "SELECT epoch_ns, exit_code, COALESCE(command, ''), out_dir, timestamp_ns FROM test_runs ORDER BY epoch_ns DESC"
        )?;

        let runs = stmt.query_map([], |row| {
            Ok(TestRun {
                epoch_ns: row.get(0)?,
                exit_code: row.get(1)?,
                command: row.get(2)?,
                out_dir: PathBuf::from(row.get::<_, String>(3)?),
                timestamp_ns: row.get(4)?,
            })
        })?;

        let mut result = Vec::new();
        for run in runs {
            result.push(run?);
        }

        Ok(result)
    }

    /// Query test artifacts - returns (epoch_ns, exit_code, command, filename, content, out_dir, timestamp_ns, full_path)
    pub fn query_artifacts(&self) -> rusqlite::Result<Vec<(u64, i32, String, String, String, PathBuf, String, String)>> {
        let conn = Connection::open(&self.db_path)?;
        let mut stmt = conn.prepare(
            "SELECT epoch_ns, exit_code, COALESCE(command, ''), filename, content, out_dir, timestamp_ns, COALESCE(full_path, out_dir || '/' || filename) FROM test_artifacts ORDER BY epoch_ns DESC"
        )?;

        let artifacts = stmt.query_map([], |row| {
            Ok((
                row.get::<_, u64>(0)?,               // epoch_ns
                row.get::<_, i32>(1)?,                // exit_code
                row.get::<_, String>(2)?,             // command
                row.get::<_, String>(3)?,             // filename
                row.get::<_, String>(4)?,             // content
                PathBuf::from(row.get::<_, String>(5)?),  // out_dir
                row.get::<_, String>(6)?,             // timestamp_ns
                row.get::<_, String>(7)?,             // full_path
            ))
        })?;

        let mut result = Vec::new();
        for artifact in artifacts {
            result.push(artifact?);
        }

        Ok(result)
    }
}

/// Base test runner trait
pub trait TestRunner {
    /// Get the name of this runner
    fn name(&self) -> &str;
    
    /// Run tests with the given arguments
    fn run(&self, args: &[&str]) -> std::io::Result<i32>;
}

/// Pytest test runner
#[allow(dead_code)]
pub struct PytestRunner {
    out_dir: PathBuf,
}

impl PytestRunner {
    pub fn new(out_dir: impl AsRef<Path>) -> Self {
        PytestRunner {
            out_dir: out_dir.as_ref().to_path_buf(),
        }
    }
}

impl TestRunner for PytestRunner {
    fn name(&self) -> &str {
        "pytest"
    }
    
    fn run(&self, args: &[&str]) -> std::io::Result<i32> {
        let mut cmd = Command::new("python3");
        cmd.arg("-m")
            .arg("pytest")
            .arg(format!("--junitxml={}/pytest-results.xml", self.out_dir.display()))
            .args(args);
        
        let status = cmd.status()?;
        Ok(status.code().unwrap_or(1))
    }
}

/// Cargo test runner
#[allow(dead_code)]
pub struct CargoRunner {
    out_dir: PathBuf,
}

impl CargoRunner {
    pub fn new(out_dir: impl AsRef<Path>) -> Self {
        CargoRunner {
            out_dir: out_dir.as_ref().to_path_buf(),
        }
    }
}

impl TestRunner for CargoRunner {
    fn name(&self) -> &str {
        "cargo"
    }
    
    fn run(&self, args: &[&str]) -> std::io::Result<i32> {
        let mut cmd = Command::new("cargo");
        
        // Determine the cargo subcommand
        if args.is_empty() {
            // Default to 'cargo test'
            cmd.arg("test");
        } else {
            // Check if first arg is a known cargo subcommand
            match args[0] {
                "test" | "run" | "build" | "check" | "bench" | "doc" | "clippy" => {
                    cmd.arg(args[0]);
                    if args.len() > 1 {
                        cmd.args(&args[1..]);
                    }
                }
                _ => {
                    // First arg doesn't look like a subcommand, default to 'test'
                    cmd.arg("test");
                    cmd.args(args);
                }
            }
        }
        
        let status = cmd.status()?;
        Ok(status.code().unwrap_or(1))
    }
}

/// Go test runner
#[allow(dead_code)]
pub struct GoRunner {
    out_dir: PathBuf,
}

impl GoRunner {
    pub fn new(out_dir: impl AsRef<Path>) -> Self {
        GoRunner {
            out_dir: out_dir.as_ref().to_path_buf(),
        }
    }
}

impl TestRunner for GoRunner {
    fn name(&self) -> &str {
        "go"
    }
    
    fn run(&self, args: &[&str]) -> std::io::Result<i32> {
        let mut cmd = Command::new("go");
        cmd.arg("test").args(args);
        
        let status = cmd.status()?;
        Ok(status.code().unwrap_or(1))
    }
}

/// Jest test runner
#[allow(dead_code)]
pub struct JestRunner {
    out_dir: PathBuf,
}

impl JestRunner {
    pub fn new(out_dir: impl AsRef<Path>) -> Self {
        JestRunner {
            out_dir: out_dir.as_ref().to_path_buf(),
        }
    }
}

impl TestRunner for JestRunner {
    fn name(&self) -> &str {
        "jest"
    }
    
    fn run(&self, args: &[&str]) -> std::io::Result<i32> {
        let mut cmd = Command::new("npx");
        cmd.arg("jest").args(args);
        
        let status = cmd.status()?;
        Ok(status.code().unwrap_or(1))
    }
}

/// Vitest test runner
#[allow(dead_code)]
pub struct VitestRunner {
    out_dir: PathBuf,
}

impl VitestRunner {
    pub fn new(out_dir: impl AsRef<Path>) -> Self {
        VitestRunner {
            out_dir: out_dir.as_ref().to_path_buf(),
        }
    }
}

impl TestRunner for VitestRunner {
    fn name(&self) -> &str {
        "vitest"
    }
    
    fn run(&self, args: &[&str]) -> std::io::Result<i32> {
        let mut cmd = Command::new("npx");
        cmd.arg("vitest")
            .arg("run")
            .arg("--reporter=junit")
            .arg(format!("--outputFile={}/junit.xml", self.out_dir.display()))
            .args(args);
        
        let status = cmd.status()?;
        Ok(status.code().unwrap_or(1))
    }
}

/// Tox test runner
#[allow(dead_code)]
pub struct ToxRunner {
    out_dir: PathBuf,
}

impl ToxRunner {
    pub fn new(out_dir: impl AsRef<Path>) -> Self {
        ToxRunner {
            out_dir: out_dir.as_ref().to_path_buf(),
        }
    }
}

impl TestRunner for ToxRunner {
    fn name(&self) -> &str {
        "tox"
    }
    
    fn run(&self, args: &[&str]) -> std::io::Result<i32> {
        let mut cmd = Command::new("tox");
        cmd.args(args);
        
        let status = cmd.status()?;
        Ok(status.code().unwrap_or(1))
    }
}

/// Bashcov test runner (runs bashcov if installed)
#[allow(dead_code)]
pub struct BashcovRunner {
    out_dir: PathBuf,
}

impl BashcovRunner {
    pub fn new(out_dir: impl AsRef<Path>) -> Self {
        BashcovRunner {
            out_dir: out_dir.as_ref().to_path_buf(),
        }
    }
}

impl TestRunner for BashcovRunner {
    fn name(&self) -> &str {
        "bashcov"
    }
    
    fn run(&self, args: &[&str]) -> std::io::Result<i32> {
        // Try to run bashcov if available
        let mut cmd = Command::new("bashcov");
        cmd.args(args)
            .env("BASHCOV_COVERAGE_FILE", format!("{}/bashcov-results.txt", self.out_dir.display()));
        
        match cmd.status() {
            Ok(status) => Ok(status.code().unwrap_or(1)),
            Err(_) => {
                // Fallback if bashcov not found
                eprintln!("bashcov not found, attempting fallback");
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "bashcov not installed",
                ))
            }
        }
    }
}

/// Shellcov test runner (bash coverage wrapper, mimics bashcov output)
#[allow(dead_code)]
pub struct ShellcovRunner {
    out_dir: PathBuf,
}

impl ShellcovRunner {
    pub fn new(out_dir: impl AsRef<Path>) -> Self {
        ShellcovRunner {
            out_dir: out_dir.as_ref().to_path_buf(),
        }
    }
}

impl TestRunner for ShellcovRunner {
    fn name(&self) -> &str {
        "shellcov"
    }
    
    fn run(&self, args: &[&str]) -> std::io::Result<i32> {
        // Try to run shellcov if available, otherwise run bash directly
        let mut cmd = Command::new("shellcov");
        cmd.args(args)
            .env("SHELLCOV_COVERAGE_FILE", format!("{}/shellcov-results.txt", self.out_dir.display()));
        
        match cmd.status() {
            Ok(status) => Ok(status.code().unwrap_or(1)),
            Err(_) => {
                // Fallback to bash if shellcov not found
                eprintln!("shellcov not found, attempting bash fallback");
                let mut fallback = Command::new("bash");
                fallback.args(args);
                
                match fallback.status() {
                    Ok(status) => Ok(status.code().unwrap_or(1)),
                    Err(e) => Err(e),
                }
            }
        }
    }
}

/// Build argv tail for an interpreter (sh/bash/zsh/python/ipython).
///
/// - No args: empty (just run the interpreter).
/// - First arg is an option (starts with '-'): pass through verbatim so
///   explicit invocations like `-x -c "cmd"` work as written.
/// - First arg is an existing file: run it as a script.
/// - Otherwise, when `command_flag` is `Some(flag)` (shells): treat the args as
///   an inline command string via `flag` (e.g. `sh -c "whoami"`). Args are
///   re-joined with `shlex` quoting so the original word boundaries and
///   metacharacters are preserved.
/// - Otherwise, when `command_flag` is `None` (python/ipython): pass args
///   through verbatim. There is no implicit `-c` wrapping — an inline command
///   must be requested explicitly (e.g. `python -- -c "print(1)"`).
fn interpreter_args(args: &[&str], command_flag: Option<&str>) -> Vec<String> {
    if args.is_empty() {
        return Vec::new();
    }
    if command_flag.is_none() || args[0].starts_with('-') || Path::new(args[0]).is_file() {
        return args.iter().map(|s| s.to_string()).collect();
    }
    let flag = command_flag.unwrap();
    let joined = shlex::try_join(args.iter().copied())
        .expect("interpreter command args must not contain NUL bytes");
    vec![flag.to_string(), joined]
}

/// Sh script runner
#[allow(dead_code)]
pub struct ShRunner {
    out_dir: PathBuf,
}

impl ShRunner {
    pub fn new(out_dir: impl AsRef<Path>) -> Self {
        ShRunner {
            out_dir: out_dir.as_ref().to_path_buf(),
        }
    }
}

impl TestRunner for ShRunner {
    fn name(&self) -> &str {
        "sh"
    }

    fn run(&self, args: &[&str]) -> std::io::Result<i32> {
        let mut cmd = Command::new("sh");
        cmd.args(interpreter_args(args, Some("-c")));

        let status = cmd.status()?;
        Ok(status.code().unwrap_or(1))
    }
}

/// Bash script runner
#[allow(dead_code)]
pub struct BashRunner {
    out_dir: PathBuf,
}

impl BashRunner {
    pub fn new(out_dir: impl AsRef<Path>) -> Self {
        BashRunner {
            out_dir: out_dir.as_ref().to_path_buf(),
        }
    }
}

impl TestRunner for BashRunner {
    fn name(&self) -> &str {
        "bash"
    }

    fn run(&self, args: &[&str]) -> std::io::Result<i32> {
        let mut cmd = Command::new("bash");
        cmd.args(interpreter_args(args, Some("-c")));

        let status = cmd.status()?;
        Ok(status.code().unwrap_or(1))
    }
}

/// Zsh script runner
#[allow(dead_code)]
pub struct ZshRunner {
    out_dir: PathBuf,
}

impl ZshRunner {
    pub fn new(out_dir: impl AsRef<Path>) -> Self {
        ZshRunner {
            out_dir: out_dir.as_ref().to_path_buf(),
        }
    }
}

impl TestRunner for ZshRunner {
    fn name(&self) -> &str {
        "zsh"
    }

    fn run(&self, args: &[&str]) -> std::io::Result<i32> {
        let mut cmd = Command::new("zsh");
        cmd.args(interpreter_args(args, Some("-c")));

        let status = cmd.status()?;
        Ok(status.code().unwrap_or(1))
    }
}

/// Python script runner
#[allow(dead_code)]
pub struct PythonRunner {
    out_dir: PathBuf,
}

impl PythonRunner {
    pub fn new(out_dir: impl AsRef<Path>) -> Self {
        PythonRunner {
            out_dir: out_dir.as_ref().to_path_buf(),
        }
    }
}

impl TestRunner for PythonRunner {
    fn name(&self) -> &str {
        "python"
    }

    fn run(&self, args: &[&str]) -> std::io::Result<i32> {
        let mut cmd = Command::new("python3");
        cmd.args(interpreter_args(args, None));

        let status = cmd.status()?;
        Ok(status.code().unwrap_or(1))
    }
}

/// IPython script runner
#[allow(dead_code)]
pub struct IpythonRunner {
    out_dir: PathBuf,
}

impl IpythonRunner {
    pub fn new(out_dir: impl AsRef<Path>) -> Self {
        IpythonRunner {
            out_dir: out_dir.as_ref().to_path_buf(),
        }
    }
}

impl TestRunner for IpythonRunner {
    fn name(&self) -> &str {
        "ipython"
    }

    fn run(&self, args: &[&str]) -> std::io::Result<i32> {
        let mut cmd = Command::new("ipython");
        cmd.args(interpreter_args(args, None));

        let status = cmd.status()?;
        Ok(status.code().unwrap_or(1))
    }
}

/// Factory function to create a test runner
pub fn get_runner(name: &str, out_dir: &Path) -> Option<Box<dyn TestRunner>> {
    match name {
        "pytest" => Some(Box::new(PytestRunner::new(out_dir))),
        "cargo" => Some(Box::new(CargoRunner::new(out_dir))),
        "go" => Some(Box::new(GoRunner::new(out_dir))),
        "jest" => Some(Box::new(JestRunner::new(out_dir))),
        "vitest" => Some(Box::new(VitestRunner::new(out_dir))),
        "tox" => Some(Box::new(ToxRunner::new(out_dir))),
        "bashcov" => Some(Box::new(BashcovRunner::new(out_dir))),
        "shellcov" => Some(Box::new(ShellcovRunner::new(out_dir))),
        "sh" => Some(Box::new(ShRunner::new(out_dir))),
        "bash" => Some(Box::new(BashRunner::new(out_dir))),
        "zsh" => Some(Box::new(ZshRunner::new(out_dir))),
        "python" => Some(Box::new(PythonRunner::new(out_dir))),
        "ipython" => Some(Box::new(IpythonRunner::new(out_dir))),
        _ => None,
    }
}

/// Get current UNIX timestamp in seconds
pub fn get_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Get current UNIX timestamp in nanoseconds
pub fn get_epoch_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Get current ISO8601 timestamp with nanosecond precision (9 decimal places)
pub fn get_timestamp_ns() -> String {
    let now: DateTime<Utc> = Utc::now();
    let nanos = now.timestamp_subsec_nanos();
    format!("{}.{:09}+00:00", now.format("%Y-%m-%dT%H:%M:%S"), nanos)
}

/// Get current ISO8601 timestamp (second precision, kept for compatibility)
pub fn get_timestamp() -> String {
    let now: DateTime<Utc> = Utc::now();
    now.format("%Y-%m-%dT%H:%M:%S").to_string()
}

/// Create reports directory with timestamp
pub fn create_reports_dir(base: &Path) -> std::io::Result<PathBuf> {
    let epoch = get_epoch();
    let timestamp = get_timestamp();
    
    let dir = base.join(format!(
        "{}-{}",
        epoch,
        timestamp.replace(":", "-")
    ));
    
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Create a symlink to the latest report
pub fn create_latest_symlink(base: &Path, target: &Path) -> std::io::Result<()> {
    let latest = base.join("latest");
    
    // Remove existing symlink if it exists
    let _ = fs::remove_file(&latest);
    
    // Create new symlink
    #[cfg(unix)]
    {
        use std::os::unix::fs as unix_fs;
        unix_fs::symlink(target, latest)?;
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_get_epoch() {
        let epoch = get_epoch();
        assert!(epoch > 0);
    }

    #[test]
    fn test_get_epoch_ns_resolution() {
        let epoch_s = get_epoch();
        let epoch_ns = get_epoch_ns();
        // epoch_ns should be approximately epoch_s * 1e9
        assert!(epoch_ns >= epoch_s * 1_000_000_000, "epoch_ns must be >= epoch_s * 1e9");
        assert!(epoch_ns < (epoch_s + 2) * 1_000_000_000, "epoch_ns must be within 2s of epoch_s");
    }

    #[test]
    fn test_get_timestamp_ns_format() {
        let ts = get_timestamp_ns();
        // Format: YYYY-MM-DDTHH:MM:SS.nnnnnnnnn+00:00
        assert!(ts.contains('T'), "timestamp_ns must contain 'T'");
        assert!(ts.ends_with("+00:00"), "timestamp_ns must end with +00:00");
        let dot_pos = ts.find('.').expect("timestamp_ns must have nanosecond decimal point");
        let nano_part = &ts[dot_pos + 1..dot_pos + 10];
        assert_eq!(nano_part.len(), 9, "nanosecond part must be 9 digits");
        assert!(nano_part.chars().all(|c| c.is_ascii_digit()), "nanoseconds must be digits");
    }

    #[test]
    fn test_get_timestamp_legacy() {
        let ts = get_timestamp();
        assert!(ts.contains('T'));
    }

    #[test]
    fn test_runner_factory() {
        let out_dir = PathBuf::from("/tmp");

        assert!(get_runner("pytest", &out_dir).is_some());
        assert!(get_runner("cargo", &out_dir).is_some());
        assert!(get_runner("go", &out_dir).is_some());
        assert!(get_runner("jest", &out_dir).is_some());
        assert!(get_runner("vitest", &out_dir).is_some());
        assert!(get_runner("tox", &out_dir).is_some());
        assert!(get_runner("unknown", &out_dir).is_none());
    }

    #[test]
    fn test_replogdb_insert_and_query_run() {
        let temp_dir = TempDir::new().expect("temp dir");
        let db = ReplogDB::new(temp_dir.path().join("test.db")).expect("db");

        let ts = get_timestamp_ns();
        let run = TestRun {
            timestamp_ns: ts.clone(),
            epoch_ns: get_epoch_ns(),
            exit_code: 0,
            out_dir: temp_dir.path().join("run"),
            command: "pytest tests/".to_string(),
        };
        db.insert_run(&run).expect("insert run");

        let runs = db.query_runs().expect("query runs");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].timestamp_ns, ts);
        assert_eq!(runs[0].exit_code, 0);
    }

    #[test]
    fn test_replogdb_artifact_linked_by_timestamp_ns() {
        let temp_dir = TempDir::new().expect("temp dir");
        let db = ReplogDB::new(temp_dir.path().join("test.db")).expect("db");
        let out_dir = temp_dir.path().join("run");

        let ts = get_timestamp_ns();
        let epoch_ns = get_epoch_ns();
        let run = TestRun {
            timestamp_ns: ts.clone(),
            epoch_ns,
            exit_code: 0,
            out_dir: out_dir.clone(),
            command: "".to_string(),
        };
        db.insert_run(&run).expect("insert run");
        db.insert_artifact(epoch_ns, &ts, &out_dir, "build.log", "content", "", 0)
            .expect("insert artifact");

        let artifacts = db.query_artifacts().expect("query artifacts");
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].0, epoch_ns);   // epoch_ns is index 0 (PK)
        assert_eq!(artifacts[0].3, "build.log");  // filename at index 3
        assert_eq!(artifacts[0].4, "content");    // content at index 4
    }

    #[test]
    fn test_migrate_v3_upgrades_epoch_schema() {
        use rusqlite::Connection;

        let temp_dir = TempDir::new().expect("temp dir");
        let db_path = temp_dir.path().join("v2.db");

        // Manually create a v2-style database with epoch as PK
        {
            let conn = Connection::open(&db_path).expect("open");
            conn.execute_batch("
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
                INSERT INTO test_runs VALUES (1700000000, 0, 'pytest', '2023-11-14T22:13:20', 'reports/run1');
                INSERT INTO test_artifacts VALUES (1700000000, 'reports/run1', 'build.log', 'ok', 'pytest', 'reports/run1/build.log');
            ").expect("setup v2 schema");
        }

        // Open with ReplogDB — should trigger v3+v4 migration
        let db = ReplogDB::new(&db_path).expect("migrate");
        let runs = db.query_runs().expect("query after migration");
        assert_eq!(runs.len(), 1);
        assert!(
            runs[0].timestamp_ns.ends_with(".000000000+00:00"),
            "migrated timestamp_ns should have nanosecond suffix"
        );
        assert_eq!(runs[0].epoch_ns, 1700000000_u64 * 1_000_000_000,
            "epoch_ns must be epoch seconds * 1e9");

        let artifacts = db.query_artifacts().expect("query artifacts");
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].0, runs[0].epoch_ns, "artifact epoch_ns must match run (FK)");
        assert_eq!(artifacts[0].6, runs[0].timestamp_ns, "artifact timestamp_ns must match run");
        assert_eq!(artifacts[0].1, 0_i32, "migrated artifact exit_code must default to 0");
    }
}
