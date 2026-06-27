/// run_tests binary - CLI for the Rust test runner
/// 
/// Provides a command-line interface for running tests with multiple backends
/// and storing results in a SQLite database for querying.

use std::env;
use std::process;
use std::path::PathBuf;
use tert::run_tests::{
    TestRun, ReplogDB, get_runner, get_epoch, get_epoch_ns, get_timestamp_ns,
    create_reports_dir, create_latest_symlink
};

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_usage(&args[0]);
        process::exit(1);
    }
    
    let subcommand = &args[1];
    let remaining_args: Vec<&str> = args.iter().skip(2).map(|s| s.as_str()).collect();
    
    match subcommand.as_str() {
        "--help" | "-h" | "help" => {
            print_help();
            process::exit(0);
        }
        "--version" | "-v" | "version" => {
            println!("tert run_tests 0.1.0");
            process::exit(0);
        }
        "query" => {
            cmd_query(&remaining_args);
        }
        "ls" | "list" => {
            cmd_list(&remaining_args);
        }
        "show" => {
            cmd_show(&remaining_args);
        }
        "run" => {
            cmd_run(&remaining_args);
        }
        "cargo" => {
            cmd_cargo(&remaining_args);
        }
        _ => {
            eprintln!("Unknown subcommand: {}", subcommand);
            print_usage(&args[0]);
            process::exit(1);
        }
    }
}

/// Handle 'tert cargo' subcommand - convenience wrapper for cargo test/run
fn cmd_cargo(args: &[&str]) {
    // Determine the cargo subcommand (test, run, build, check, etc.)
    let (cargo_subcmd, remaining_args) = if args.is_empty() {
        // Default to 'cargo test' if no args provided
        ("test", vec![])
    } else if args[0] == "test" || args[0] == "run" || args[0] == "build" || args[0] == "check" {
        // Explicit cargo subcommand provided
        (args[0], args[1..].to_vec())
    } else {
        // First arg doesn't look like a cargo subcommand, default to 'test'
        ("test", args.to_vec())
    };
    
    // Build args for cmd_run: ["cargo", "test|run|...", remaining...]
    let mut full_args: Vec<&str> = vec!["cargo", cargo_subcmd];
    for arg in &remaining_args {
        full_args.push(arg.as_ref());
    }
    
    cmd_run(&full_args);
}

fn cmd_run(args: &[&str]) {
    if args.is_empty() {
        eprintln!("Usage: run_tests run <runner> [args...]");
        eprintln!("Runners: pytest, cargo, go, jest, vitest, tox");
        process::exit(1);
    }
    
    let runner_name = args[0];
    let runner_args = if args.len() > 1 { &args[1..] } else { &[] };
    
    // Build command string for logging
    let command = if runner_args.is_empty() {
        runner_name.to_string()
    } else {
        format!("{} {}", runner_name, runner_args.join(" "))
    };
    
    // Create reports directory
    let reports_dir = PathBuf::from("reports");
    let out_dir = match create_reports_dir(&reports_dir) {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("Failed to create reports directory: {}", e);
            process::exit(1);
        }
    };
    
    println!("Running {} tests in {}", runner_name, out_dir.display());
    
    // Get the runner
    let runner = match get_runner(runner_name, &out_dir) {
        Some(r) => r,
        None => {
            eprintln!("Unknown runner: {}", runner_name);
            eprintln!("Available runners: pytest, cargo, go, jest, vitest, tox");
            process::exit(1);
        }
    };
    
    // Run tests
    let exit_code = match runner.run(runner_args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Failed to run tests: {}", e);
            process::exit(1);
        }
    };
    
    // Store results in database
    let epoch_ns = get_epoch_ns();
    let timestamp_ns = get_timestamp_ns();
    let test_run = TestRun {
        timestamp_ns: timestamp_ns.clone(),
        epoch_ns,
        exit_code,
        out_dir: out_dir.clone(),
        command,
    };
    
    // Initialize database
    let db_path = reports_dir.join("test_results.db");
    match ReplogDB::new(&db_path) {
        Ok(db) => {
            if let Err(e) = db.insert_run(&test_run) {
                eprintln!("Warning: Failed to store test run: {}", e);
            }
        }
        Err(e) => {
            eprintln!("Warning: Failed to initialize database: {}", e);
        }
    }
    
    // Create/update latest symlink
    if let Err(e) = create_latest_symlink(&reports_dir, &out_dir) {
        eprintln!("Warning: Failed to create latest symlink: {}", e);
    }
    
    println!("Test run complete: exit code {}", exit_code);
    println!("Results stored in: {}", out_dir.display());
    
    process::exit(exit_code);
}

fn cmd_query(args: &[&str]) {
    if args.is_empty() {
        eprintln!("Usage: run_tests query <type> [options]");
        eprintln!("Types: runs, artifacts, coverage");
        process::exit(1);
    }
    
    let query_type = args[0];
    let db_path = PathBuf::from("reports/test_results.db");
    
    match ReplogDB::new(&db_path) {
        Ok(db) => {
            match query_type {
                "runs" | "r" => {
                    match db.query_runs() {
                        Ok(runs) => {
                            println!("Test Runs:");
                            println!("{:-<80}", "");
                            for run in runs {
                                println!(" Timestamp: {}", run.timestamp_ns);
                                println!("  Epoch ns: {}", run.epoch_ns);
                                println!("  Exit Code: {}", run.exit_code);
                                println!("  Command: {}", run.command);
                                println!("  Output Dir: {}", run.out_dir.display());
                                println!();
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to query runs: {}", e);
                            process::exit(1);
                        }
                    }
                }
                "artifacts" | "a" => {
                    match db.query_artifacts() {
                        Ok(artifacts) => {
                            println!("Test Artifacts:");
                            println!("{:-<80}", "");
                            for (epoch_ns, command, exit_code, filename, _content, out_dir, timestamp_ns, full_path) in artifacts {
                                println!(" Timestamp: {}", timestamp_ns);
                                println!("  Epoch ns:  {}", epoch_ns);
                                println!("  Exit Code: {}", exit_code);
                                println!("  File: {}", filename);
                                println!("  Out Dir: {}", out_dir.display());
                                println!("  Full Path: {}", full_path);
                                println!("  Command: {}", command);
                                println!();
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to query artifacts: {}", e);
                            process::exit(1);
                        }
                    }
                }
                "coverage" | "cov" => {
                    println!("Coverage query not yet implemented");
                }
                _ => {
                    eprintln!("Unknown query type: {}", query_type);
                    eprintln!("Available types: runs, artifacts, coverage");
                    process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to open database: {}", e);
            eprintln!("Database path: {}", db_path.display());
            process::exit(1);
        }
    }
}

fn cmd_list(args: &[&str]) {
    let limit = if args.is_empty() {
        10
    } else {
        args[0].parse::<usize>().unwrap_or(10)
    };
    
    let db_path = PathBuf::from("reports/test_results.db");
    
    match ReplogDB::new(&db_path) {
        Ok(db) => {
            match db.query_runs() {
                Ok(runs) => {
                    println!("Recent Test Runs (showing up to {}):", limit);
                    println!("{:-<80}", "");
                    for (i, run) in runs.iter().take(limit).enumerate() {
                        println!("{}. [{}] {} (exit: {})", 
                            i + 1, run.epoch_ns, run.timestamp_ns, run.exit_code);
                        println!("   {}", run.out_dir.display());
                    }
                    if runs.len() > limit {
                        println!("... and {} more", runs.len() - limit);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to list runs: {}", e);
                    process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to open database: {}", e);
            process::exit(1);
        }
    }
}

fn cmd_show(args: &[&str]) {
    if args.is_empty() {
        eprintln!("Usage: run_tests show <reportdir_or_epoch>");
        process::exit(1);
    }
    
    let query_str = args[0];
    let db_path = PathBuf::from("reports/test_results.db");
    
    match ReplogDB::new(&db_path) {
        Ok(db) => {
            match db.query_runs() {
                Ok(runs) => {
                    // Try to parse as epoch_ns first, then as path
                    let epoch_ns: Option<u64> = query_str.parse().ok();
                    
                    let matching_runs: Vec<_> = runs.iter()
                        .filter(|r| {
                            if let Some(e) = epoch_ns {
                                r.epoch_ns == e
                            } else {
                                r.out_dir.to_string_lossy().contains(query_str)
                            }
                        })
                        .collect();
                    
                    if matching_runs.is_empty() {
                        eprintln!("No matching test runs found for: {}", query_str);
                        process::exit(1);
                    }
                    
                    for run in matching_runs {
                        println!("Test Run Details:");
                        println!("{:-<80}", "");
                        println!("Timestamp: {}", run.timestamp_ns);
                        println!("Epoch ns:  {}", run.epoch_ns);
                        println!("Exit Code: {}", run.exit_code);
                        println!("Output Dir: {}", run.out_dir.display());
                        println!();
                    }
                }
                Err(e) => {
                    eprintln!("Failed to retrieve test runs: {}", e);
                    process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to open database: {}", e);
            process::exit(1);
        }
    }
}

fn print_usage(prog: &str) {
    eprintln!("Usage: {} <subcommand> [options]", prog);
    eprintln!("Try '{} --help' for more information.", prog);
}

fn print_help() {
    println!("Test Execution Report Tracker - Run Tests CLI");
    println!();
    println!("USAGE:");
    println!("    run_tests [OPTIONS] <SUBCOMMAND>");
    println!();
    println!("SUBCOMMANDS:");
    println!("    cargo [test|run] [args]  Run cargo with logging (defaults to 'cargo test')");
    println!("    run <runner>             Run tests with the specified runner");
    println!("    query <type>             Query test results database");
    println!("    ls, list [limit]         List recent test runs (default: 10)");
    println!("    show <id_or_path>        Show details of a specific test run");
    println!("    help                     Show this help message");
    println!();
    println!("RUNNERS:");
    println!("    pytest                   Python pytest");
    println!("    cargo                    Rust cargo");
    println!("    go                       Go testing");
    println!("    jest                     JavaScript Jest");
    println!("    vitest                   JavaScript Vitest");
    println!("    tox                      Multi-environment tox");
    println!();
    println!("QUERY TYPES:");
    println!("    runs, r                  List all test runs");
    println!("    artifacts, a             List all test artifacts");
    println!("    coverage, cov            Query coverage information");
    println!();
    println!("OPTIONS:");
    println!("    --help, -h               Show this help message");
    println!("    --version, -v            Show version information");
    println!();
    println!("EXAMPLES:");
    println!("    run_tests cargo                 # cargo test (with logging)");
    println!("    run_tests cargo run --bin foo   # cargo run --bin foo (with logging)");
    println!("    run_tests cargo test --all      # cargo test --all (with logging)");
    println!("    run_tests run pytest tests/");
    println!("    run_tests query runs");
    println!("    run_tests list 20");
    println!("    run_tests show 1719550000");
    println!();
}
