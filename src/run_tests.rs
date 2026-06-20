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
    pub epoch: u64,
    pub exit_code: i32,
    pub timestamp: String,
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
        let conn = Connection::open(&self.db_path)?;
        
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
        
        Ok(())
    }
    
    /// Migration to v1: Create initial schema
    fn migrate_to_v1(&self, conn: &Connection) -> rusqlite::Result<()> {
        // Create test_runs table (v1)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS test_runs (
                epoch INTEGER PRIMARY KEY,
                exit_code INTEGER,
                timestamp TEXT,
                out_dir TEXT
            )",
            [],
        )?;
        
        // Create test_artifacts table (v1)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS test_artifacts (
                epoch INTEGER,
                out_dir TEXT,
                filename TEXT,
                content TEXT,
                PRIMARY KEY (epoch, filename)
            )",
            [],
        )?;
        
        // Record migration
        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?, datetime('now'))",
            [1],
        )?;
        
        Ok(())
    }
    
    /// Migration to v2: Add command and full_path columns
    fn migrate_to_v2(&self, conn: &Connection) -> rusqlite::Result<()> {
        // Add command column to test_runs (with default empty string for existing rows)
        conn.execute(
            "ALTER TABLE test_runs ADD COLUMN command TEXT DEFAULT ''",
            [],
        ).ok(); // Ignore if column already exists
        
        // Add command and full_path columns to test_artifacts
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
    
    /// Insert a test run record
    pub fn insert_run(&self, run: &TestRun) -> rusqlite::Result<()> {
        let conn = Connection::open(&self.db_path)?;
        
        conn.execute(
            "INSERT OR REPLACE INTO test_runs (epoch, exit_code, timestamp, out_dir, command) VALUES (?, ?, ?, ?, ?)",
            params![run.epoch, run.exit_code, &run.timestamp, run.out_dir.to_string_lossy(), &run.command],
        )?;
        
        Ok(())
    }
    
    /// Insert a test artifact with denormalized command and full path
    pub fn insert_artifact(
        &self,
        epoch: u64,
        out_dir: &Path,
        filename: &str,
        content: &str,
        command: &str,
    ) -> rusqlite::Result<()> {
        let conn = Connection::open(&self.db_path)?;
        
        // Compute full_path as out_dir/filename
        let full_path = format!("{}/{}", out_dir.display(), filename);
        
        conn.execute(
            "INSERT OR REPLACE INTO test_artifacts (epoch, out_dir, filename, content, command, full_path) VALUES (?, ?, ?, ?, ?, ?)",
            params![epoch, out_dir.to_string_lossy(), filename, content, command, &full_path],
        )?;
        
        Ok(())
    }
    
    /// Query all test runs
    pub fn query_runs(&self) -> rusqlite::Result<Vec<TestRun>> {
        let conn = Connection::open(&self.db_path)?;
        let mut stmt = conn.prepare("SELECT epoch, exit_code, timestamp, out_dir, COALESCE(command, '') FROM test_runs ORDER BY epoch DESC")?;
        
        let runs = stmt.query_map([], |row| {
            Ok(TestRun {
                epoch: row.get(0)?,
                exit_code: row.get(1)?,
                timestamp: row.get(2)?,
                out_dir: PathBuf::from(row.get::<_, String>(3)?),
                command: row.get(4)?,
            })
        })?;
        
        let mut result = Vec::new();
        for run in runs {
            result.push(run?);
        }
        
        Ok(result)
    }
    
    /// Query test artifacts - returns (epoch, out_dir, filename, content, command, full_path)
    pub fn query_artifacts(&self) -> rusqlite::Result<Vec<(u64, PathBuf, String, String, String, String)>> {
        let conn = Connection::open(&self.db_path)?;
        let mut stmt = conn.prepare(
            "SELECT epoch, out_dir, filename, content, COALESCE(command, ''), COALESCE(full_path, out_dir || '/' || filename) FROM test_artifacts ORDER BY epoch DESC"
        )?;
        
        let artifacts = stmt.query_map([], |row| {
            Ok((
                row.get(0)?,
                PathBuf::from(row.get::<_, String>(1)?),
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
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
            .arg(format!("--reporter=junit"))
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
        _ => None,
    }
}

/// Get current UNIX timestamp
pub fn get_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Get current ISO8601 timestamp
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
    
    #[test]
    fn test_get_epoch() {
        let epoch = get_epoch();
        assert!(epoch > 0);
    }
    
    #[test]
    fn test_get_timestamp() {
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
}
