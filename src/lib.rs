//! Test Execution Report Tracker Rust library with cargo-insta integration
//!
//! Provides performance-critical components for test report management and analysis.
//! Includes high-performance ANSI stripping and shellwrap utilities.

pub mod shellwrap;
pub mod run_tests;
pub mod fetch;
pub mod crypto;
pub mod did_agent;
pub mod vc;

use pyo3::prelude::*;
use regex::Regex;

/// Fast ANSI escape code stripper using compiled regex
/// Matches the pattern: ESC [ followed by digits/semicolons, ending with a letter
/// Performance: ~3-5x faster than Python regex on large outputs
pub fn strip_ansi_fast(text: &str) -> String {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]").expect("Failed to compile regex")
    });
    re.replace_all(text, "").to_string()
}

/// Python-exposed function to strip ANSI escape codes from text
/// 
/// Args:
///     text: String potentially containing ANSI escape codes
/// 
/// Returns:
///     String with all ANSI codes removed
/// 
/// Examples:
///     >>> strip_ansi("\x1b[32mGreen text\x1b[0m")
///     'Green text'
#[pyfunction]
fn strip_ansi(text: &str) -> PyResult<String> {
    Ok(strip_ansi_fast(text))
}

/// Python-exposed function to check if text contains ANSI codes
/// 
/// Args:
///     text: String to check
/// 
/// Returns:
///     bool: True if text contains ANSI escape codes
#[pyfunction]
fn has_ansi(text: &str) -> PyResult<bool> {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]").expect("Failed to compile regex")
    });
    Ok(re.is_match(text))
}

/// Python module definition for PyO3
/// Exports performance-critical functions for Python integration
#[pymodule]
fn _rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", "0.1.0")?;
    m.add_function(wrap_pyfunction!(strip_ansi, m)?)?;
    m.add_function(wrap_pyfunction!(has_ansi, m)?)?;
    Ok(())
}
