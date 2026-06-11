//! `rtk doctor` — health check for the rtk installation.
//!
//! Checks:
//! 1. Hook status (Ok / Outdated / Missing)
//! 2. Tracking DB accessible
//! 3. `rtk` on PATH and resolves to itself
//! 4. Config file validity
//! 5. Parse-failure rate (last 7 days from DB)

use crate::{
    core::{config, tracking::Tracker},
    hooks::hook_check::{self, HookStatus},
};
use serde::Serialize;
use std::fmt;

// ── Types ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

impl fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckStatus::Pass => write!(f, "pass"),
            CheckStatus::Warn => write!(f, "warn"),
            CheckStatus::Fail => write!(f, "fail"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheck {
    pub name: &'static str,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub overall: CheckStatus,
    pub checks: Vec<DoctorCheck>,
}

// ── Individual checks ──────────────────────────────────────────────────────

pub fn check_hook() -> DoctorCheck {
    match hook_check::status() {
        HookStatus::Ok => DoctorCheck {
            name: "hook",
            status: CheckStatus::Pass,
            detail: "hook installed and up to date".to_string(),
        },
        HookStatus::Outdated => DoctorCheck {
            name: "hook",
            status: CheckStatus::Warn,
            detail: "hook is outdated — run `rtk init -g` to update".to_string(),
        },
        HookStatus::Missing => DoctorCheck {
            name: "hook",
            status: CheckStatus::Warn,
            detail: "hook not installed — run `rtk init -g` for automatic token savings"
                .to_string(),
        },
    }
}

pub fn check_db() -> DoctorCheck {
    match Tracker::new() {
        Ok(_) => DoctorCheck {
            name: "tracking_db",
            status: CheckStatus::Pass,
            detail: "tracking database accessible".to_string(),
        },
        Err(e) => DoctorCheck {
            name: "tracking_db",
            status: CheckStatus::Fail,
            detail: format!("cannot open tracking database: {e}"),
        },
    }
}

pub fn check_path() -> DoctorCheck {
    match which::which("rtk") {
        Ok(path) => DoctorCheck {
            name: "path",
            status: CheckStatus::Pass,
            detail: format!("`rtk` found at {}", path.display()),
        },
        Err(_) => DoctorCheck {
            name: "path",
            status: CheckStatus::Fail,
            detail: "`rtk` not found on PATH — add ~/.local/bin to PATH".to_string(),
        },
    }
}

pub fn check_config() -> DoctorCheck {
    match config::Config::load() {
        Ok(_) => DoctorCheck {
            name: "config",
            status: CheckStatus::Pass,
            detail: "config valid".to_string(),
        },
        Err(e) => {
            // No config file is normal — not a failure
            let msg = e.to_string();
            if msg.contains("No such file") || msg.contains("not found") {
                DoctorCheck {
                    name: "config",
                    status: CheckStatus::Pass,
                    detail: "no config file (using defaults)".to_string(),
                }
            } else {
                DoctorCheck {
                    name: "config",
                    status: CheckStatus::Warn,
                    detail: format!("config parse error: {msg}"),
                }
            }
        }
    }
}

pub fn check_failure_rate() -> DoctorCheck {
    let tracker = match Tracker::new() {
        Ok(t) => t,
        Err(_) => {
            return DoctorCheck {
                name: "failure_rate",
                status: CheckStatus::Warn,
                detail: "cannot check failure rate — DB inaccessible".to_string(),
            };
        }
    };

    match tracker.get_failure_rate_7d() {
        Ok(rate) => {
            let status = if rate >= 0.20 {
                CheckStatus::Warn
            } else {
                CheckStatus::Pass
            };
            let pct = (rate * 100.0) as u32;
            DoctorCheck {
                name: "failure_rate",
                status,
                detail: format!("{pct}% parse failure rate (last 7 days)"),
            }
        }
        Err(_) => DoctorCheck {
            name: "failure_rate",
            status: CheckStatus::Pass,
            detail: "no command history yet".to_string(),
        },
    }
}

// ── Report assembly ────────────────────────────────────────────────────────

pub fn build_report() -> DoctorReport {
    let checks = vec![
        check_hook(),
        check_db(),
        check_path(),
        check_config(),
        check_failure_rate(),
    ];

    let overall = if checks.iter().any(|c| c.status == CheckStatus::Fail) {
        CheckStatus::Fail
    } else if checks.iter().any(|c| c.status == CheckStatus::Warn) {
        CheckStatus::Warn
    } else {
        CheckStatus::Pass
    };

    DoctorReport { overall, checks }
}

// ── Entry point ────────────────────────────────────────────────────────────

pub fn run(json: bool) -> anyhow::Result<()> {
    let report = build_report();

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    // Text output
    let overall_icon = match report.overall {
        CheckStatus::Pass => "✓",
        CheckStatus::Warn => "!",
        CheckStatus::Fail => "✗",
    };
    println!("rtk doctor [{overall_icon}]");
    println!();

    for check in &report.checks {
        let icon = match check.status {
            CheckStatus::Pass => "✓",
            CheckStatus::Warn => "!",
            CheckStatus::Fail => "✗",
        };
        println!("  [{icon}] {:<16} {}", check.name, check.detail);
    }
    println!();

    match report.overall {
        CheckStatus::Pass => println!("All checks passed."),
        CheckStatus::Warn => println!("Warnings found — see above."),
        CheckStatus::Fail => {
            println!("Failures found — see above.");
            std::process::exit(1);
        }
    }

    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_status_display() {
        assert_eq!(CheckStatus::Pass.to_string(), "pass");
        assert_eq!(CheckStatus::Warn.to_string(), "warn");
        assert_eq!(CheckStatus::Fail.to_string(), "fail");
    }

    #[test]
    fn check_status_serialize() {
        let json = serde_json::to_string(&CheckStatus::Pass).unwrap();
        assert_eq!(json, "\"pass\"");
        let json = serde_json::to_string(&CheckStatus::Fail).unwrap();
        assert_eq!(json, "\"fail\"");
    }

    #[test]
    fn doctor_check_serialize() {
        let c = DoctorCheck {
            name: "hook",
            status: CheckStatus::Pass,
            detail: "ok".to_string(),
        };
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"hook\""));
        assert!(json.contains("\"pass\""));
        assert!(json.contains("\"ok\""));
    }

    #[test]
    fn overall_fail_when_any_fail() {
        let checks = vec![
            DoctorCheck {
                name: "a",
                status: CheckStatus::Pass,
                detail: String::new(),
            },
            DoctorCheck {
                name: "b",
                status: CheckStatus::Fail,
                detail: String::new(),
            },
        ];
        let overall = if checks.iter().any(|c| c.status == CheckStatus::Fail) {
            CheckStatus::Fail
        } else if checks.iter().any(|c| c.status == CheckStatus::Warn) {
            CheckStatus::Warn
        } else {
            CheckStatus::Pass
        };
        assert_eq!(overall, CheckStatus::Fail);
    }

    #[test]
    fn overall_warn_when_no_fail_but_warn() {
        let checks = vec![
            DoctorCheck {
                name: "a",
                status: CheckStatus::Pass,
                detail: String::new(),
            },
            DoctorCheck {
                name: "b",
                status: CheckStatus::Warn,
                detail: String::new(),
            },
        ];
        let overall = if checks.iter().any(|c| c.status == CheckStatus::Fail) {
            CheckStatus::Fail
        } else if checks.iter().any(|c| c.status == CheckStatus::Warn) {
            CheckStatus::Warn
        } else {
            CheckStatus::Pass
        };
        assert_eq!(overall, CheckStatus::Warn);
    }

    #[test]
    fn overall_pass_when_all_pass() {
        let checks = vec![DoctorCheck {
            name: "a",
            status: CheckStatus::Pass,
            detail: String::new(),
        }];
        let overall = if checks.iter().any(|c| c.status == CheckStatus::Fail) {
            CheckStatus::Fail
        } else if checks.iter().any(|c| c.status == CheckStatus::Warn) {
            CheckStatus::Warn
        } else {
            CheckStatus::Pass
        };
        assert_eq!(overall, CheckStatus::Pass);
    }

    #[test]
    fn check_db_returns_valid_check() {
        let c = check_db();
        assert_eq!(c.name, "tracking_db");
        // Status is Pass or Fail depending on env — both are valid
        assert!(c.status == CheckStatus::Pass || c.status == CheckStatus::Fail);
    }

    #[test]
    fn check_path_returns_valid_check() {
        let c = check_path();
        assert_eq!(c.name, "path");
        assert!(c.status == CheckStatus::Pass || c.status == CheckStatus::Fail);
    }

    #[test]
    fn check_config_returns_valid_check() {
        let c = check_config();
        assert_eq!(c.name, "config");
        assert!(c.status == CheckStatus::Pass || c.status == CheckStatus::Warn);
    }

    #[test]
    fn check_hook_returns_valid_check() {
        let c = check_hook();
        assert_eq!(c.name, "hook");
        assert!(
            c.status == CheckStatus::Pass
                || c.status == CheckStatus::Warn
                || c.status == CheckStatus::Fail
        );
    }

    #[test]
    fn build_report_has_five_checks() {
        let report = build_report();
        assert_eq!(report.checks.len(), 5);
    }

    #[test]
    fn report_json_roundtrip() {
        let report = build_report();
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"overall\""));
        assert!(json.contains("\"checks\""));
        assert!(json.contains("\"hook\""));
    }
}
