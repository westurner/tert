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
use tert::run_tests::{TestRun, ReplogDB, get_runner, get_epoch};

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
        epoch: 1719550000,
        exit_code: 0,
        timestamp: "2026-06-28T12:00:00".to_string(),
        out_dir: temp_dir.path().join("reports/run1"),
        command: "".to_string(),
    };
    
    db.insert_run(&test_run).expect("Failed to insert test run");
    
    let test_run2 = TestRun {
        epoch: 1719550100,
        exit_code: 1,
        timestamp: "2026-06-28T12:01:40".to_string(),
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
        epoch: 1719550000,
        exit_code: 0,
        timestamp: "2026-06-28T12:00:00".to_string(),
        out_dir: PathBuf::from("reports/run1"),
        command: "".to_string(),
    };
    
    let result = db.insert_run(&test_run);
    assert!(result.is_ok(), "Insert should succeed");
    
    let runs = db.query_runs().expect("Failed to query runs");
    assert_eq!(runs.len(), 1, "Should have one run after insert");
    assert_eq!(runs[0].epoch, 1719550000);
    assert_eq!(runs[0].exit_code, 0);
}

#[rstest]
fn test_db_query_runs_sorted_descending(test_db_with_data: (TempDir, ReplogDB)) {
    let (_temp_dir, db) = test_db_with_data;
    
    let runs = db.query_runs().expect("Failed to query runs");
    
    assert_eq!(runs.len(), 2, "Should have two test runs");
    // Runs should be sorted by epoch DESC
    assert!(
        runs[0].epoch > runs[1].epoch,
        "Runs should be sorted descending by epoch"
    );
    assert_eq!(runs[0].epoch, 1719550100);
    assert_eq!(runs[1].epoch, 1719550000);
}

#[rstest]
fn test_db_insert_artifact(empty_db: (TempDir, ReplogDB)) {
    let (_temp_dir, db) = empty_db;
    
    let epoch = get_epoch();
    let out_dir = PathBuf::from("reports/run1");
    
    let result = db.insert_artifact(
        epoch,
        &out_dir,
        "test_results.xml",
        "<testsuites><testsuite tests=\"1\"/></testsuites>",
        "pytest tests/",
    );
    
    assert!(result.is_ok(), "Insert artifact should succeed");
    
    let artifacts = db.query_artifacts().expect("Failed to query artifacts");
    assert_eq!(artifacts.len(), 1, "Should have one artifact");
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
        epoch: 1719550000 + exit_code as u64,
        exit_code,
        timestamp: format!("2026-06-28T12:00:00"),
        out_dir: temp_dir.path().join(format!("run_{}", exit_code)),
        command: "".to_string(),
    };
    
    let result = db.insert_run(&test_run);
    assert!(result.is_ok());
    
    let runs = db.query_runs().expect("Query failed");
    let stored_run = runs.iter().find(|r| r.epoch == test_run.epoch)
        .expect("Run not found");
    
    assert_eq!(stored_run.exit_code, exit_code, "Exit code should match");
}

// ============================================================================
// PARAMETRIZED TESTS - Timestamp Formats
// ============================================================================

/// Test various timestamp formats
#[rstest]
#[case("2026-06-28T12:00:00")]
#[case("2026-06-28T00:00:00")]
#[case("2026-12-31T23:59:59")]
#[case("2026-01-01T01:01:01")]
fn test_db_timestamp_storage(
    #[case] timestamp: &str,
) {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test.db");
    let db = ReplogDB::new(&db_path).expect("Failed to create db");
    
    let test_run = TestRun {
        epoch: 1719550000,
        exit_code: 0,
        timestamp: timestamp.to_string(),
        out_dir: temp_dir.path().join("run"),
        command: "".to_string(),
    };
    
    db.insert_run(&test_run).expect("Insert failed");
    
    let runs = db.query_runs().expect("Query failed");
    assert_eq!(runs[0].timestamp, timestamp);
}

// ============================================================================
// ARTIFACT TESTS
// ============================================================================

#[rstest]
fn test_db_insert_multiple_artifacts_same_epoch(empty_db: (TempDir, ReplogDB)) {
    let (_temp_dir, db) = empty_db;
    
    let epoch = 1719550000;
    let out_dir = PathBuf::from("reports/run1");
    
    // Insert multiple artifacts with same epoch but different filenames
    db.insert_artifact(epoch, &out_dir, "output.log", "test output", "pytest tests/")
        .expect("Failed to insert first artifact");
    
    db.insert_artifact(epoch, &out_dir, "coverage.xml", "<coverage/>", "pytest tests/")
        .expect("Failed to insert second artifact");
    
    db.insert_artifact(epoch, &out_dir, "results.json", "{}", "pytest tests/")
        .expect("Failed to insert third artifact");
    
    let artifacts = db.query_artifacts().expect("Query failed");
    assert_eq!(artifacts.len(), 3, "Should have three artifacts");
}

#[rstest]
fn test_db_artifact_content_preservation(empty_db: (TempDir, ReplogDB)) {
    let (_temp_dir, db) = empty_db;
    
    let epoch = 1719550000;
    let out_dir = PathBuf::from("reports/run1");
    let content = "Complex content with special chars: <>&\"'äöü";
    
    db.insert_artifact(epoch, &out_dir, "special.txt", content, "pytest tests/")
        .expect("Insert failed");
    
    let artifacts = db.query_artifacts().expect("Query failed");
    assert_eq!(artifacts[0].3, content, "Content should be preserved");
}

// ============================================================================
// EDGE CASES AND ERROR HANDLING
// ============================================================================

#[rstest]
fn test_db_duplicate_epoch_overwrite(empty_db: (TempDir, ReplogDB)) {
    let (_temp_dir, db) = empty_db;
    
    let run1 = TestRun {
        epoch: 1719550000,
        exit_code: 0,
        timestamp: "2026-06-28T12:00:00".to_string(),
        out_dir: PathBuf::from("reports/run1"),
        command: "".to_string(),
    };
    
    db.insert_run(&run1).expect("First insert failed");
    
    // Insert with same epoch but different data (should replace)
    let run2 = TestRun {
        epoch: 1719550000,
        exit_code: 1,
        timestamp: "2026-06-28T12:01:00".to_string(),
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
        epoch: 1719550000,
        exit_code: 0,
        timestamp: "2026-06-28T12:00:00".to_string(),
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
        let epoch = 1719550000 + (i * 100) as u64;
        let test_run = TestRun {
            epoch,
            exit_code: if i % 2 == 0 { 0 } else { 1 },
            timestamp: format!("2026-06-28T12:0{}:00", i),
            out_dir: PathBuf::from(format!("reports/run{}", i)),
            command: "".to_string(),
        };
        
        db.insert_run(&test_run).expect("Insert failed");
        
        // Add artifacts for each run
        db.insert_artifact(epoch, &test_run.out_dir, "output.log", "log content", "")
            .expect("Artifact insert failed");
    }
    
    // Verify all data was stored
    let runs = db.query_runs().expect("Query runs failed");
    assert_eq!(runs.len(), 5, "Should have 5 runs");
    
    let artifacts = db.query_artifacts().expect("Query artifacts failed");
    assert_eq!(artifacts.len(), 5, "Should have 5 artifacts");
    
    // Verify runs are sorted DESC
    for i in 0..runs.len()-1 {
        assert!(runs[i].epoch > runs[i+1].epoch, "Runs should be DESC sorted");
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
                epoch: 1719550000 + (i * 100) as u64,
                exit_code: i as i32,
                timestamp: format!("2026-06-28T12:0{}:00", i),
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
