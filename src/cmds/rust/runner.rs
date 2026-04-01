//! Runs arbitrary commands and captures only stderr or test failures.

use crate::core::tracking;
use crate::core::utils::{exit_code_from_output, split_command};
use anyhow::{Context, Result};
use regex::Regex;
use std::process::{Command, Stdio};

/// Run a command and filter output to show only errors/warnings
pub fn run_err(command: &str, verbose: u8) -> Result<()> {
    let timer = tracking::TimedExecution::start();

    if verbose > 0 {
        eprintln!("Running: {}", command);
    }

    let output = if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(["/C", command])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute command")?
    } else {
        let parts = split_command(command)
            .with_context(|| format!("Failed to parse command: {}", command))?;
        Command::new(&parts[0])
            .args(&parts[1..])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute command")?
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let raw = format!("{}\n{}", stdout, stderr);
    let filtered = filter_errors(&raw);
    let mut rtk = String::new();

    if filtered.is_empty() {
        if output.status.success() {
            rtk.push_str("[ok] Command completed successfully (no errors)");
        } else {
            rtk.push_str(&format!(
                "[FAIL] Command failed (exit code: {:?})\n",
                output.status.code()
            ));
            let lines: Vec<&str> = raw.lines().collect();
            for line in lines.iter().rev().take(10).rev() {
                rtk.push_str(&format!("  {}\n", line));
            }
        }
    } else {
        rtk.push_str(&filtered);
    }

    let exit_code = exit_code_from_output(&output, "run-err");
    if let Some(hint) = crate::core::tee::tee_and_hint(&raw, "err", exit_code) {
        println!("{}\n{}", rtk, hint);
    } else {
        println!("{}", rtk);
    }
    timer.track(command, "rtk run-err", &raw, &rtk);
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

/// Run tests and show only failures
pub fn run_test(command: &str, verbose: u8) -> Result<()> {
    let timer = tracking::TimedExecution::start();

    if verbose > 0 {
        eprintln!("Running tests: {}", command);
    }

    let output = if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(["/C", command])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute test command")?
    } else {
        let parts = split_command(command)
            .with_context(|| format!("Failed to parse command: {}", command))?;
        Command::new(&parts[0])
            .args(&parts[1..])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute test command")?
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let raw = format!("{}\n{}", stdout, stderr);

    let exit_code = exit_code_from_output(&output, "run-test");
    let summary = extract_test_summary(&raw, command);
    if let Some(hint) = crate::core::tee::tee_and_hint(&raw, "test", exit_code) {
        println!("{}\n{}", summary, hint);
    } else {
        println!("{}", summary);
    }
    timer.track(command, "rtk run-test", &raw, &summary);
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

fn filter_errors(output: &str) -> String {
    lazy_static::lazy_static! {
        static ref ERROR_PATTERNS: Vec<Regex> = vec![
            // Generic errors
            Regex::new(r"(?i)^.*error[\s:\[].*$").unwrap(),
            Regex::new(r"(?i)^.*\berr\b.*$").unwrap(),
            Regex::new(r"(?i)^.*warning[\s:\[].*$").unwrap(),
            Regex::new(r"(?i)^.*\bwarn\b.*$").unwrap(),
            Regex::new(r"(?i)^.*failed.*$").unwrap(),
            Regex::new(r"(?i)^.*failure.*$").unwrap(),
            Regex::new(r"(?i)^.*exception.*$").unwrap(),
            Regex::new(r"(?i)^.*panic.*$").unwrap(),
            // Rust specific
            Regex::new(r"^error\[E\d+\]:.*$").unwrap(),
            Regex::new(r"^\s*--> .*:\d+:\d+$").unwrap(),
            // Python
            Regex::new(r"^Traceback.*$").unwrap(),
            Regex::new(r#"^\s*File ".*", line \d+.*$"#).unwrap(),
            // JavaScript/TypeScript
            Regex::new(r"^\s*at .*:\d+:\d+.*$").unwrap(),
            // Go
            Regex::new(r"^.*\.go:\d+:.*$").unwrap(),
        ];
    }

    let mut result = Vec::new();
    let mut in_error_block = false;
    let mut blank_count = 0;

    for line in output.lines() {
        let is_error_line = ERROR_PATTERNS.iter().any(|p| p.is_match(line));

        if is_error_line {
            in_error_block = true;
            blank_count = 0;
            result.push(line.to_string());
        } else if in_error_block {
            if line.trim().is_empty() {
                blank_count += 1;
                if blank_count >= 2 {
                    in_error_block = false;
                } else {
                    result.push(line.to_string());
                }
            } else if line.starts_with(' ') || line.starts_with('\t') {
                // Continuation of error
                result.push(line.to_string());
                blank_count = 0;
            } else {
                in_error_block = false;
            }
        }
    }

    result.join("\n")
}

fn extract_test_summary(output: &str, command: &str) -> String {
    let mut result = Vec::new();
    let lines: Vec<&str> = output.lines().collect();

    // Detect test framework
    let is_cargo = command.contains("cargo test");
    let is_pytest = command.contains("pytest");
    let is_jest =
        command.contains("jest") || command.contains("npm test") || command.contains("yarn test");
    let is_go = command.contains("go test");

    // Collect failures
    let mut failures = Vec::new();
    let mut in_failure = false;
    let mut failure_lines = Vec::new();

    for line in lines.iter() {
        // Cargo test
        if is_cargo {
            if line.contains("test result:") {
                result.push(line.to_string());
            }
            if line.contains("FAILED") && !line.contains("test result") {
                failures.push(line.to_string());
            }
            if line.starts_with("failures:") {
                in_failure = true;
            }
            if in_failure && line.starts_with("    ") {
                failure_lines.push(line.to_string());
            }
        }

        // Pytest
        if is_pytest {
            if line.contains(" passed") || line.contains(" failed") || line.contains(" error") {
                result.push(line.to_string());
            }
            if line.contains("FAILED") {
                failures.push(line.to_string());
            }
        }

        // Jest
        if is_jest {
            if line.contains("Tests:") || line.contains("Test Suites:") {
                result.push(line.to_string());
            }
            if line.contains("✕") || line.contains("FAIL") {
                failures.push(line.to_string());
            }
        }

        // Go test
        if is_go {
            if line.starts_with("ok") || line.starts_with("FAIL") || line.starts_with("---") {
                result.push(line.to_string());
            }
            if line.contains("FAIL") {
                failures.push(line.to_string());
            }
        }
    }

    // Build output
    let mut output = String::new();

    if !failures.is_empty() {
        output.push_str("[FAIL] FAILURES:\n");
        for f in failures.iter().take(10) {
            output.push_str(&format!("  {}\n", f));
        }
        if failures.len() > 10 {
            output.push_str(&format!("  ... +{} more failures\n", failures.len() - 10));
        }
        output.push('\n');
    }

    if !result.is_empty() {
        output.push_str("SUMMARY:\n");
        for r in &result {
            output.push_str(&format!("  {}\n", r));
        }
    } else {
        // Fallback: show last few lines
        output.push_str("OUTPUT (last 5 lines):\n");
        let start = lines.len().saturating_sub(5);
        for line in &lines[start..] {
            if !line.trim().is_empty() {
                output.push_str(&format!("  {}\n", line));
            }
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::utils::split_command;

    #[test]
    fn test_filter_errors() {
        let output = "info: compiling\nerror: something failed\n  at line 10\ninfo: done";
        let filtered = filter_errors(output);
        assert!(filtered.contains("error"));
        assert!(!filtered.contains("info"));
    }

    // C-2: exit code must be propagated from the underlying command
    /// Before fix: run_err / run_test return Ok(()) even when child exits non-zero.
    /// After fix: std::process::exit(code) is called with the child's exit code.
    #[test]
    #[ignore] // integration — requires rtk binary on PATH
    fn test_run_err_propagates_exit_code() {
        let status = std::process::Command::new("rtk")
            .args(["run-err", "false"])
            .status()
            .expect("rtk binary not found — run `cargo install --path .` first");
        assert_ne!(
            status.code().unwrap_or(0),
            0,
            "run-err must exit non-zero when the wrapped command fails"
        );
    }

    #[test]
    #[ignore]
    fn test_run_test_propagates_exit_code() {
        let status = std::process::Command::new("rtk")
            .args(["run-test", "false"])
            .status()
            .expect("rtk binary not found");
        assert_ne!(
            status.code().unwrap_or(0),
            0,
            "run-test must exit non-zero when the wrapped command fails"
        );
    }

    // C-1: split_command must exist and treat ; as a literal token, not a separator
    #[test]
    fn test_split_command_semicolon_is_literal() {
        let parts = split_command("echo safe ; echo INJECTED").unwrap();
        assert_eq!(parts[0], "echo");
        // ; must be present as a token, not strip it or interpret it as a separator
        assert!(
            parts.iter().any(|t| t == ";"),
            "semicolon was not preserved as a literal token"
        );
        // All 5 tokens present
        assert_eq!(parts.len(), 5);
    }

    #[test]
    fn test_split_command_empty_fails() {
        assert!(split_command("").is_err());
        assert!(split_command("   ").is_err());
    }

    #[test]
    fn test_split_command_quoted_preserves_space() {
        let parts = split_command(r#"git log --format="%H %s""#).unwrap();
        assert_eq!(parts[0], "git");
        assert_eq!(parts[1], "log");
        // Quoted string with space becomes one token
        assert_eq!(parts[2], "--format=%H %s");
    }

    #[test]
    #[cfg(unix)]
    fn test_split_exec_blocks_semicolon_injection() {
        use std::process::Stdio;
        let marker = "/tmp/rtk_split_exec_injection_test";
        let _ = std::fs::remove_file(marker);

        // With sh -c "echo safe ; touch <marker>", the marker would be created
        // With split exec, touch is just an arg to echo — marker must NOT appear
        let cmd = format!("echo safe ; touch {}", marker);
        let parts = split_command(&cmd).unwrap();
        let _status = std::process::Command::new(&parts[0])
            .args(&parts[1..])
            .stdout(Stdio::null())
            .status()
            .unwrap();

        assert!(
            !std::path::Path::new(marker).exists(),
            "Shell injection: touch ran as a separate command"
        );
        let _ = std::fs::remove_file(marker);
    }
}
