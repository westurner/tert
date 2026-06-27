//! Comprehensive tests for run_tests CLI using rstest
//!
//! Tests cover:
//! - Parametrized runner selection
//! - Database query operations
//! - CLI argument parsing and routing
//! - Error handling and edge cases
//! - Integration scenarios with fixtures

use std::path::PathBuf;
use std::fs;
use tempfile::TempDir;
use rstest::{fixture, rstest};
use tert::run_tests::{TestRun, ReplogDB, get_runner, get_epoch_ns, get_timestamp_ns};

// ============================================================================
// FIXTURES
// ============================================================================

/// Temporary directory fixture for test isolation
#[fixture]
fn temp_dir() -> TempDir {
    TempDir::new().expect("Failed to create temp directory")
}

/// Test database fixture with pre-populated data
#[fixture]
fn test_db_with_data() -> (TempDir, ReplogDB) {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_results.db");
    let db = ReplogDB::new(&db_path).expect("Failed to create test database");
    
    // Insert test data
    let test_run = TestRun {
        timestamp_ns: "2026-06-28T12:00:00.000000000+00:00".to_string(),
        epoch_ns: 1719550000_u64 * 1_000_000_000,
        exit_code: 0,
        out_dir: temp_dir.path().join("reports/run1"),
        command: "".to_string(),
    };
    
    db.insert_run(&test_run).expect("Failed to insert test run");
    
    let test_run2 = TestRun {
        timestamp_ns: "2026-06-28T12:01:40.000000000+00:00".to_string(),
        epoch_ns: 1719550100_u64 * 1_000_000_000,
        exit_code: 1,
        out_dir: temp_dir.path().join("reports/run2"),
        command: "".to_string(),
    };
    
    db.insert_run(&test_run2).expect("Failed to insert second test run");
    
    (temp_dir, db)
}

/// Empty test database fixture
#[fixture]
fn empty_db() -> (TempDir, ReplogDB) {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_results.db");
    let db = ReplogDB::new(&db_path).expect("Failed to create empty test database");
    (temp_dir, db)
}

/// Reports directory structure fixture
#[fixture]
fn reports_dir() -> (TempDir, PathBuf) {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let reports = temp_dir.path().join("reports");
    fs::create_dir_all(&reports).expect("Failed to create reports directory");
    (temp_dir, reports)
}

// ============================================================================
// PARAMETRIZED TESTS - Runner Factory
// ============================================================================

/// Test runner factory with various runner types
#[rstest]
#[case("pytest")]
#[case("cargo")]
#[case("go")]
#[case("jest")]
#[case("vitest")]
#[case("tox")]
fn test_get_runner_factory_valid_runners(#[case] runner_name: &str) {
    let out_dir = PathBuf::from("/tmp/test");
    let runner = get_runner(runner_name, &out_dir);
    
    assert!(
        runner.is_some(),
        "Runner factory should create runner for: {}",
        runner_name
    );
}

/// Test runner factory with invalid runner names
#[rstest]
#[case("invalid")]
#[case("pytest3")]
#[case("python")]
#[case("node")]
#[case("")]
#[case("PYTEST")]
#[case("Cargo")]
fn test_get_runner_factory_invalid_runners(#[case] invalid_runner: &str) {
    let out_dir = PathBuf::from("/tmp/test");
    let runner = get_runner(invalid_runner, &out_dir);
    
    assert!(
        runner.is_none(),
        "Runner factory should reject invalid runner: {}",
        invalid_runner
    );
}

// ============================================================================
// DATABASE TESTS - Insert and Query
// ============================================================================

#[rstest]
fn test_db_insert_single_run(empty_db: (TempDir, ReplogDB)) {
    let (_temp_dir, db) = empty_db;
    
    let test_run = TestRun {
        timestamp_ns: "2026-06-28T12:00:00.000000000+00:00".to_string(),
        epoch_ns: 1719550000_u64 * 1_000_000_000,
        exit_code: 0,
        out_dir: PathBuf::from("reports/run1"),
        command: "".to_string(),
    };
    
    let result = db.insert_run(&test_run);
    assert!(result.is_ok(), "Insert should succeed");
    
    let runs = db.query_runs().expect("Failed to query runs");
    assert_eq!(runs.len(), 1, "Should have one run after insert");
    assert_eq!(runs[0].timestamp_ns, "2026-06-28T12:00:00.000000000+00:00");
    assert_eq!(runs[0].epoch_ns, 1719550000_u64 * 1_000_000_000);
    assert_eq!(runs[0].exit_code, 0);
}

#[rstest]
fn test_db_query_runs_sorted_descending(test_db_with_data: (TempDir, ReplogDB)) {
    let (_temp_dir, db) = test_db_with_data;
    
    let runs = db.query_runs().expect("Failed to query runs");
    
    assert_eq!(runs.len(), 2, "Should have two test runs");
    // Runs should be sorted by timestamp_ns DESC
    assert!(
        runs[0].timestamp_ns > runs[1].timestamp_ns,
        "Runs should be sorted descending by timestamp_ns"
    );
    assert_eq!(runs[0].epoch_ns, 1719550100_u64 * 1_000_000_000);
    assert_eq!(runs[1].epoch_ns, 1719550000_u64 * 1_000_000_000);
}

#[rstest]
fn test_db_insert_artifact(empty_db: (TempDir, ReplogDB)) {
    let (_temp_dir, db) = empty_db;

    // Insert a run first so the FK constraint is satisfied
    let ts = get_timestamp_ns();
    let epoch_ns = get_epoch_ns();
    let out_dir = PathBuf::from("reports/run1");
    let run = TestRun {
        timestamp_ns: ts.clone(),
        epoch_ns,
        exit_code: 0,
        out_dir: out_dir.clone(),
        command: "".to_string(),
    };
    db.insert_run(&run).expect("Failed to insert run");

    let result = db.insert_artifact(
        epoch_ns,
        &ts,
        &out_dir,
        "test_results.xml",
        "<testsuites><testsuite tests=\"1\"/></testsuites>",
        "pytest tests/",
        0,
    );
    
    assert!(result.is_ok(), "Insert artifact should succeed");
    
    let artifacts = db.query_artifacts().expect("Failed to query artifacts");
    assert_eq!(artifacts.len(), 1, "Should have one artifact");
    assert_eq!(artifacts[0].0, epoch_ns, "artifact epoch_ns must match run (FK)");
    assert_eq!(artifacts[0].6, ts, "artifact timestamp_ns must match run");
}

#[rstest]
fn test_db_query_empty_runs(empty_db: (TempDir, ReplogDB)) {
    let (_temp_dir, db) = empty_db;
    
    let runs = db.query_runs().expect("Failed to query runs");
    assert_eq!(runs.len(), 0, "Empty database should return no runs");
}

// ============================================================================
// PARAMETRIZED TESTS - Exit Code Scenarios
// ============================================================================

/// Test various exit codes from test runners
#[rstest]
#[case(0)]
#[case(1)]
#[case(2)]
#[case(127)]
#[case(255)]
fn test_db_store_various_exit_codes(
    #[case] exit_code: i32,
) {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test.db");
    let db = ReplogDB::new(&db_path).expect("Failed to create db");
    
    let test_run = TestRun {
        timestamp_ns: format!("2026-06-28T12:00:00.{:09}+00:00", exit_code as u64 * 1_000_000),
        epoch_ns: (1719550000_u64 + exit_code as u64) * 1_000_000_000,
        exit_code,
        out_dir: temp_dir.path().join(format!("run_{}", exit_code)),
        command: "".to_string(),
    };
    
    let result = db.insert_run(&test_run);
    assert!(result.is_ok());
    
    let runs = db.query_runs().expect("Query failed");
    let stored_run = runs.iter().find(|r| r.epoch_ns == test_run.epoch_ns)
        .expect("Run not found");
    
    assert_eq!(stored_run.exit_code, exit_code, "Exit code should match");
}

// ============================================================================
// PARAMETRIZED TESTS - Timestamp Formats
// ============================================================================

/// Test nanosecond timestamp storage and retrieval
#[rstest]
#[case("2026-06-28T12:00:00.000000000+00:00")]
#[case("2026-06-28T00:00:00.000000001+00:00")]
#[case("2026-12-31T23:59:59.999999999+00:00")]
#[case("2026-01-01T01:01:01.123456789+00:00")]
fn test_db_timestamp_ns_storage(
    #[case] timestamp_ns: &str,
) {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test.db");
    let db = ReplogDB::new(&db_path).expect("Failed to create db");
    
    let test_run = TestRun {
        timestamp_ns: timestamp_ns.to_string(),
        epoch_ns: 1719550000_u64 * 1_000_000_000,
        exit_code: 0,
        out_dir: temp_dir.path().join("run"),
        command: "".to_string(),
    };
    
    db.insert_run(&test_run).expect("Insert failed");
    
    let runs = db.query_runs().expect("Query failed");
    assert_eq!(runs[0].timestamp_ns, timestamp_ns);
}

// ============================================================================
// ARTIFACT TESTS
// ============================================================================

#[rstest]
fn test_db_insert_multiple_artifacts_same_epoch(empty_db: (TempDir, ReplogDB)) {
    let (_temp_dir, db) = empty_db;

    // Insert the run first
    let ts = "2026-06-28T12:00:00.000000000+00:00";
    let epoch_ns = 1719550000_u64 * 1_000_000_000;
    let out_dir = PathBuf::from("reports/run1");
    db.insert_run(&TestRun {
        timestamp_ns: ts.to_string(),
        epoch_ns,
        exit_code: 0,
        out_dir: out_dir.clone(),
        command: "".to_string(),
    }).expect("Failed to insert run");

    // Insert multiple artifacts linked to the same run
    db.insert_artifact(epoch_ns, ts, &out_dir, "output.log", "test output", "pytest tests/", 0)
        .expect("Failed to insert first artifact");
    
    db.insert_artifact(epoch_ns, ts, &out_dir, "coverage.xml", "<coverage/>", "pytest tests/", 0)
        .expect("Failed to insert second artifact");
    
    db.insert_artifact(epoch_ns, ts, &out_dir, "results.json", "{}", "pytest tests/", 0)
        .expect("Failed to insert third artifact");
    
    let artifacts = db.query_artifacts().expect("Query failed");
    assert_eq!(artifacts.len(), 3, "Should have three artifacts");
    // All artifacts share the same epoch_ns (PK FK)
    assert!(artifacts.iter().all(|a| a.0 == epoch_ns), "All artifacts must share the run epoch_ns");
}

#[rstest]
fn test_db_artifact_content_preservation(empty_db: (TempDir, ReplogDB)) {
    let (_temp_dir, db) = empty_db;

    let ts = "2026-06-28T12:00:00.000000000+00:00";
    let epoch_ns = 1719550000_u64 * 1_000_000_000;
    let out_dir = PathBuf::from("reports/run1");
    let content = "Complex content with special chars: <>&\"'äöü";

    db.insert_run(&TestRun {
        timestamp_ns: ts.to_string(),
        epoch_ns,
        exit_code: 0,
        out_dir: out_dir.clone(),
        command: "".to_string(),
    }).expect("Insert run failed");

    db.insert_artifact(epoch_ns, ts, &out_dir, "special.txt", content, "pytest tests/", 0)
        .expect("Insert failed");
    
    let artifacts = db.query_artifacts().expect("Query failed");
    assert_eq!(artifacts[0].4, content, "Content should be preserved");  // index 4 = content
}

// ============================================================================
// EDGE CASES AND ERROR HANDLING
// ============================================================================

#[rstest]
fn test_db_duplicate_timestamp_ns_overwrite(empty_db: (TempDir, ReplogDB)) {
    let (_temp_dir, db) = empty_db;

    let ts = "2026-06-28T12:00:00.000000000+00:00";

    let run1 = TestRun {
        timestamp_ns: ts.to_string(),
        epoch_ns: 1719550000_u64 * 1_000_000_000,
        exit_code: 0,
        out_dir: PathBuf::from("reports/run1"),
        command: "".to_string(),
    };
    
    db.insert_run(&run1).expect("First insert failed");
    
    // Insert with same timestamp_ns but different data (should replace)
    let run2 = TestRun {
        timestamp_ns: ts.to_string(),
        epoch_ns: 1719550000_u64 * 1_000_000_000,
        exit_code: 1,
        out_dir: PathBuf::from("reports/run2"),
        command: "".to_string(),
    };
    
    db.insert_run(&run2).expect("Second insert failed");
    
    let runs = db.query_runs().expect("Query failed");
    assert_eq!(runs.len(), 1, "Should still have one run (replaced)");
    assert_eq!(runs[0].exit_code, 1, "Exit code should be updated");
}

#[rstest]
fn test_db_path_separator_handling(temp_dir: TempDir) {
    let db_path = temp_dir.path().join("deep/nested/path/test.db");
    
    // ReplogDB should create parent directories
    let result = ReplogDB::new(&db_path);
    assert!(result.is_ok(), "Should handle nested paths");
}

#[rstest]
fn test_db_large_output_directory_path(empty_db: (TempDir, ReplogDB)) {
    let (_temp_dir, db) = empty_db;
    
    let long_path = PathBuf::from(
        "reports/very/long/nested/path/to/test/output/directory/with/many/segments/run"
    );
    
    let test_run = TestRun {
        timestamp_ns: "2026-06-28T12:00:00.000000000+00:00".to_string(),
        epoch_ns: 1719550000_u64 * 1_000_000_000,
        exit_code: 0,
        out_dir: long_path.clone(),
        command: "".to_string(),
    };
    
    db.insert_run(&test_run).expect("Insert failed");
    
    let runs = db.query_runs().expect("Query failed");
    assert_eq!(runs[0].out_dir, long_path, "Long paths should be preserved");
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

#[rstest]
fn test_integration_multiple_runs_and_artifacts(empty_db: (TempDir, ReplogDB)) {
    let (_temp_dir, db) = empty_db;
    
    // Create multiple test runs
    for i in 0..5 {
        let epoch_ns = (1719550000_u64 + (i * 100) as u64) * 1_000_000_000;
        let ts = format!("2026-06-28T12:0{}:00.000000000+00:00", i);
        let out_dir = PathBuf::from(format!("reports/run{}", i));
        let test_run = TestRun {
            timestamp_ns: ts.clone(),
            epoch_ns,
            exit_code: if i % 2 == 0 { 0 } else { 1 },
            out_dir: out_dir.clone(),
            command: "".to_string(),
        };
        
        db.insert_run(&test_run).expect("Insert failed");
        
        // Add artifacts for each run
        db.insert_artifact(epoch_ns, &ts, &out_dir, "output.log", "log content", "", 0)
            .expect("Artifact insert failed");
    }
    
    // Verify all data was stored
    let runs = db.query_runs().expect("Query runs failed");
    assert_eq!(runs.len(), 5, "Should have 5 runs");
    
    let artifacts = db.query_artifacts().expect("Query artifacts failed");
    assert_eq!(artifacts.len(), 5, "Should have 5 artifacts");
    
    // Verify runs are sorted DESC by epoch_ns
    for i in 0..runs.len()-1 {
        assert!(runs[i].epoch_ns > runs[i+1].epoch_ns, "Runs should be epoch_ns DESC sorted");
    }

    // Verify FK relationship: each artifact's epoch_ns matches a run
    let run_epoch_ns_set: std::collections::HashSet<_> = runs.iter().map(|r| r.epoch_ns).collect();
    for artifact in &artifacts {
        assert!(run_epoch_ns_set.contains(&artifact.0), "Artifact must be linked to an existing run");
    }
}

#[rstest]
fn test_integration_query_after_multiple_inserts(temp_dir: TempDir) {
    let db_path = temp_dir.path().join("test.db");
    
    // Phase 1: Create and populate database
    {
        let db = ReplogDB::new(&db_path).expect("Create db failed");
        for i in 0..3 {
            let test_run = TestRun {
                timestamp_ns: format!("2026-06-28T12:0{}:00.000000000+00:00", i),
                epoch_ns: (1719550000_u64 + (i * 100) as u64) * 1_000_000_000,
                exit_code: i as i32,
                out_dir: temp_dir.path().join(format!("run{}", i)),
                command: "".to_string(),
            };
            db.insert_run(&test_run).expect("Insert failed");
        }
    }
    
    // Phase 2: Re-open database and verify data persists
    {
        let db = ReplogDB::new(&db_path).expect("Open db failed");
        let runs = db.query_runs().expect("Query failed");
        assert_eq!(runs.len(), 3, "Data should persist across sessions");
    }
}

// ============================================================================
// RUNNER TRAIT TESTS
// ============================================================================

#[rstest]
fn test_runner_names_match_factory(reports_dir: (TempDir, PathBuf)) {
    let (_temp_dir, reports_dir) = reports_dir;
    let expected_runners = vec!["pytest", "cargo", "go", "jest", "vitest", "tox"];
    
    for runner_name in expected_runners {
        let runner = get_runner(runner_name, &reports_dir)
            .expect(&format!("Failed to create runner: {}", runner_name));
        
        assert_eq!(
            runner.name(),
            runner_name,
            "Runner name should match factory input"
        );
    }
}

// ============================================================================
// DIRECTORY STRUCTURE TESTS
// ============================================================================

#[rstest]
fn test_reports_directory_creation(temp_dir: TempDir) {
    let reports_dir = temp_dir.path().join("reports");
    assert!(!reports_dir.exists(), "Reports dir should not exist initially");
    
    fs::create_dir_all(&reports_dir).expect("Failed to create reports dir");
    
    assert!(
        reports_dir.exists(),
        "Reports dir should exist after creation"
    );
    assert!(
        reports_dir.is_dir(),
        "Reports path should be a directory"
    );
}

#[rstest]
fn test_nested_output_directories(temp_dir: TempDir) {
    let out_dir = temp_dir.path().join("reports/2026-06-28T12-00-00/artifacts");
    fs::create_dir_all(&out_dir).expect("Failed to create nested dirs");
    
    assert!(out_dir.exists());
    assert!(out_dir.parent().unwrap().exists());
}

// ============================================================================
// NANOSECOND TIMESTAMP TESTS
// ============================================================================

#[rstest]
fn test_get_timestamp_ns_has_nanosecond_precision() {
    let ts = get_timestamp_ns();
    // Format: YYYY-MM-DDTHH:MM:SS.nnnnnnnnn+00:00
    assert!(ts.contains('T'), "must contain date-time separator");
    assert!(ts.ends_with("+00:00"), "must be UTC");
    let dot = ts.find('.').expect("must have nanosecond decimal point");
    let nano_str = &ts[dot + 1..dot + 10];
    assert_eq!(nano_str.len(), 9, "must have 9-digit nanosecond part");
    assert!(nano_str.chars().all(|c| c.is_ascii_digit()));
}

#[rstest]
fn test_timestamp_ns_lexicographic_ordering() {
    // Two timestamps a microsecond apart must sort correctly
    let t1 = "2026-06-28T12:00:00.000000000+00:00";
    let t2 = "2026-06-28T12:00:00.000001000+00:00";
    assert!(t2 > t1, "later nanosecond timestamp must sort higher");
}

// ============================================================================
// FK RELATIONSHIP TESTS
// ============================================================================

#[rstest]
fn test_artifacts_linked_to_run_by_timestamp_ns(empty_db: (TempDir, ReplogDB)) {
    let (temp_dir, db) = empty_db;

    let ts = "2026-06-28T12:00:00.123456789+00:00";
    let epoch_ns = 1719550000_u64 * 1_000_000_000;
    let out_dir = temp_dir.path().join("run");

    db.insert_run(&TestRun {
        timestamp_ns: ts.to_string(),
        epoch_ns,
        exit_code: 0,
        out_dir: out_dir.clone(),
        command: "pytest".to_string(),
    }).expect("insert run");

    for name in &["build.log", "coverage.json", "pytest-results.xml"] {
        db.insert_artifact(epoch_ns, ts, &out_dir, name, "content", "pytest", 0)
            .expect("insert artifact");
    }

    let artifacts = db.query_artifacts().expect("query artifacts");
    assert_eq!(artifacts.len(), 3);
    // All must share the run's epoch_ns (PK)
    assert!(artifacts.iter().all(|a| a.0 == epoch_ns));
}

// ============================================================================
// SCHEMA MIGRATION TESTS
// ============================================================================

#[rstest]
fn test_migrate_v3_from_v2_epoch_schema(temp_dir: TempDir) {
    use rusqlite::Connection;

    let db_path = temp_dir.path().join("v2legacy.db");

    // Simulate a v2 database with epoch as PK (no timestamp_ns)
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
            INSERT INTO test_runs VALUES (1700000000, 0, 'pytest', '2023-11-14', 'reports/r1');
            INSERT INTO test_runs VALUES (1700000100, 1, 'cargo', '2023-11-14', 'reports/r2');
            INSERT INTO test_artifacts VALUES (1700000000, 'reports/r1', 'build.log', 'ok', 'pytest', 'reports/r1/build.log');
        ").expect("create v2 schema");
    }

    // Opening with ReplogDB should trigger migrate_to_v3
    let db = ReplogDB::new(&db_path).expect("open with migration");
    let runs = db.query_runs().expect("query runs after migration");
    assert_eq!(runs.len(), 2, "both runs must survive migration");
    for run in &runs {
        assert!(
            run.timestamp_ns.ends_with(".000000000+00:00"),
            "migrated timestamp_ns must have nanosecond suffix: {}", run.timestamp_ns
        );
        // epoch_ns must equal original epoch_seconds * 1e9
        assert!(run.epoch_ns > 0 && run.epoch_ns % 1_000_000_000 == 0,
            "migrated epoch_ns must be a whole-second multiple");
    }

    let artifacts = db.query_artifacts().expect("query artifacts after migration");
    assert_eq!(artifacts.len(), 1);
    // artifact[0].0 is epoch_ns (the PK/FK)
    let run_epoch_ns_set: std::collections::HashSet<_> = runs.iter().map(|r| r.epoch_ns).collect();
    assert!(run_epoch_ns_set.contains(&artifacts[0].0), "migrated artifact FK must match a run");
    assert!(artifacts[0].0 % 1_000_000_000 == 0, "artifact epoch_ns must be whole-second multiple");
    assert_eq!(artifacts[0].1, 0_i32, "migrated exit_code must default to 0");
}

#[rstest]
fn test_schema_version_reaches_v6_on_new_db(empty_db: (TempDir, ReplogDB)) {
    use rusqlite::Connection;
    let (temp_dir, _db) = empty_db;
    let db_path = temp_dir.path().join("test_results.db");

    let conn = Connection::open(&db_path).expect("open");
    let version: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
        .expect("query version");
    assert_eq!(version, 8, "new databases must be at schema version 8");
}

