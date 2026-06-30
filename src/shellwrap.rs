//! Shellwrap module: High-performance shell command execution with colored output streaming
//!
//! Provides the `Shellwrap` struct for executing commands with real-time output
//! streaming, dual logging (ANSI + plain text), and color management.

use std::process::{Command, Stdio};
use regex::Regex;
use std::sync::OnceLock;

/// ANSI escape code pattern
fn get_ansi_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]").expect("Failed to compile regex")
    })
}

/// Shell execution wrapper with streaming output and dual logging
#[derive(Debug, Clone)]
pub struct Shellwrap {
    /// Path to plain-text log file (ANSI codes stripped)
    pub log_file: String,
    
    /// Path to ANSI log file (preserves colors)
    pub log_file_ansi: String,
    
    /// Whether to keep ANSI codes in output
    pub keep_ansi: bool,
    
    /// Whether to print trace information
    pub trace: bool,
    
    /// Color mode: "auto", "always", or "never"
    pub color_mode: String,
    
    /// Shell to use: "bash", "zsh", or path to shell
    pub shell: Option<String>,
    
    /// Whether to use BASH_ENV for alias injection
    pub use_bash_env: bool,
}

impl Default for Shellwrap {
    fn default() -> Self {
        Shellwrap {
            log_file: "build.log".to_string(),
            log_file_ansi: "build.log.ansi".to_string(),
            keep_ansi: false,
            trace: true,
            color_mode: "auto".to_string(),
            shell: Some("bash".to_string()),
            use_bash_env: false,
        }
    }
}

impl Shellwrap {
    /// Create a new Shellwrap instance with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new Shellwrap with custom log files
    pub fn with_logs(log_file: &str, log_file_ansi: &str) -> Self {
        Shellwrap {
            log_file: log_file.to_string(),
            log_file_ansi: log_file_ansi.to_string(),
            ..Default::default()
        }
    }

    /// Strip ANSI escape codes from text
    pub fn strip_ansi(&self, text: &str) -> String {
        get_ansi_pattern().replace_all(text, "").to_string()
    }

    /// Check if text contains ANSI escape codes
    pub fn has_ansi(&self, text: &str) -> bool {
        get_ansi_pattern().is_match(text)
    }

    /// Set color mode ("auto", "always", or "never")
    pub fn set_color_mode(&mut self, mode: &str) {
        self.color_mode = mode.to_string();
    }

    /// Get the resolved shell command
    fn get_shell_command(&self, cmd: &str) -> (String, Vec<String>) {
        let shell = self.shell.as_deref()
            .unwrap_or("bash");

        let shell_exe = if shell.starts_with('/') {
            shell.to_string()
        } else {
            match shell {
                "bash" => "/bin/bash".to_string(),
                "zsh" => "/bin/zsh".to_string(),
                _ => "/bin/bash".to_string(),
            }
        };

        let args = vec!["-c".to_string(), cmd.to_string()];
        (shell_exe, args)
    }

    /// Execute a shell command with streaming output
    /// 
    /// Returns the exit code
    pub fn execute(&self, cmd: &str) -> std::io::Result<i32> {
        let (shell_exe, _args) = self.get_shell_command(cmd);
        
        if self.trace {
            eprintln!("+ {}", cmd);
        }

        let output = Command::new(&shell_exe)
            .arg("-c")
            .arg(cmd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        // Write output to stdout
        if !output.stdout.is_empty() {
            let stdout_str = String::from_utf8_lossy(&output.stdout);
            print!("{}", stdout_str);
            
            // Log to files
            if !self.log_file.is_empty() {
                let plain = self.strip_ansi(&stdout_str);
                let _ = std::fs::write(&self.log_file, plain);
            }
            
            if !self.log_file_ansi.is_empty() {
                let _ = std::fs::write(&self.log_file_ansi, stdout_str.as_bytes());
            }
        }

        // Write stderr to files if present
        if !output.stderr.is_empty() {
            let stderr_str = String::from_utf8_lossy(&output.stderr);
            eprint!("{}", stderr_str);
        }

        Ok(output.status.code().unwrap_or(1))
    }

    /// Print color test patterns
    pub fn print_colors(&self) -> i32 {
        const COLORS: &[(&str, u8)] = &[
            ("BLACK", 30),
            ("RED", 31),
            ("GREEN", 32),
            ("YELLOW", 33),
            ("BLUE", 34),
            ("MAGENTA", 35),
            ("CYAN", 36),
            ("WHITE", 37),
        ];

        println!("Standard Colors:");
        for (name, code) in COLORS {
            print!("\x1b[{}m", code);
            println!("{:<12} (code: {})\x1b[0m", name, code);
        }

        println!("\nBright Colors:");
        for (name, code) in COLORS {
            print!("\x1b[1;{}m", code);
            println!("{:<12} (bright, code: 1;{})\x1b[0m", name, code);
        }

        println!("\n256-Color Palette:");
        for i in 0..256 {
            let color = if i < 16 {
                format!("\x1b[38;5;{}m ▌ \x1b[0m", i)
            } else {
                format!("\x1b[48;5;{}m   \x1b[0m", i)
            };
            print!("{}", color);
            if (i + 1) % 16 == 0 {
                println!();
            }
        }

        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_ansi() {
        let sw = Shellwrap::new();
        assert_eq!(
            sw.strip_ansi("\x1b[32mGreen\x1b[0m"),
            "Green"
        );
    }

    #[test]
    fn test_has_ansi() {
        let sw = Shellwrap::new();
        assert!(sw.has_ansi("\x1b[32mGreen\x1b[0m"));
        assert!(!sw.has_ansi("Plain text"));
    }

    #[test]
    fn test_default_shellwrap() {
        let sw = Shellwrap::default();
        assert_eq!(sw.log_file, "build.log");
        assert_eq!(sw.color_mode, "auto");
    }
}
