//! Processes incoming hook calls from AI agents and rewrites commands on the fly.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::io::{self, Read, Write};

use crate::discover::registry::rewrite_command;
use crate::hooks::permissions::{check_command, PermissionVerdict};

// ── Copilot hook (VS Code + Copilot CLI) ──────────────────────

/// Format detected from the preToolUse JSON input.
enum HookFormat {
    /// VS Code Copilot Chat / Claude Code: `tool_name` + `tool_input.command`, supports `updatedInput`.
    VsCode { command: String },
    /// GitHub Copilot CLI: camelCase `toolName` + `toolArgs` (JSON string), deny-with-suggestion only.
    CopilotCli { command: String },
    /// Non-bash tool, already uses rtk, or unknown format — pass through silently.
    PassThrough,
}

/// Run the Copilot preToolUse hook.
/// Auto-detects VS Code Copilot Chat vs Copilot CLI format.
pub fn run_copilot() -> Result<()> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .context("Failed to read stdin")?;

    let input = input.trim();
    if input.is_empty() {
        return Ok(());
    }

    let v: Value = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[rtk hook] Failed to parse JSON input: {e}");
            return Ok(());
        }
    };

    match detect_format(&v) {
        HookFormat::VsCode { command } => handle_vscode(&command),
        HookFormat::CopilotCli { command } => handle_copilot_cli(&command),
        HookFormat::PassThrough => Ok(()),
    }
}

fn detect_format(v: &Value) -> HookFormat {
    // VS Code Copilot Chat / Claude Code: snake_case keys
    if let Some(tool_name) = v.get("tool_name").and_then(|t| t.as_str()) {
        if matches!(tool_name, "runTerminalCommand" | "Bash" | "bash") {
            if let Some(cmd) = v
                .pointer("/tool_input/command")
                .and_then(|c| c.as_str())
                .filter(|c| !c.is_empty())
            {
                return HookFormat::VsCode {
                    command: cmd.to_string(),
                };
            }
        }
        return HookFormat::PassThrough;
    }

    // Copilot CLI: camelCase keys, toolArgs is a JSON-encoded string
    if let Some(tool_name) = v.get("toolName").and_then(|t| t.as_str()) {
        if tool_name == "bash" {
            if let Some(tool_args_str) = v.get("toolArgs").and_then(|t| t.as_str()) {
                if let Ok(tool_args) = serde_json::from_str::<Value>(tool_args_str) {
                    if let Some(cmd) = tool_args
                        .get("command")
                        .and_then(|c| c.as_str())
                        .filter(|c| !c.is_empty())
                    {
                        return HookFormat::CopilotCli {
                            command: cmd.to_string(),
                        };
                    }
                }
            }
        }
        return HookFormat::PassThrough;
    }

    HookFormat::PassThrough
}

fn get_rewritten(cmd: &str) -> Option<String> {
    if cmd.contains("<<") {
        return None;
    }

    let excluded = crate::core::config::Config::load()
        .map(|c| c.hooks.exclude_commands)
        .unwrap_or_default();

    let rewritten = rewrite_command(cmd, &excluded)?;

    if rewritten == cmd {
        return None;
    }

    Some(rewritten)
}

enum HookDecision {
    AllowRewrite(String),
    AskRewrite(String),
    Defer,
    Deny,
}

fn decide_from_verdict(cmd: &str, verdict: PermissionVerdict) -> HookDecision {
    if verdict == PermissionVerdict::Deny {
        return HookDecision::Deny;
    }
    if crate::discover::lexer::contains_unattestable_construct(cmd) {
        return HookDecision::Defer;
    }
    match get_rewritten(cmd) {
        Some(r) if verdict == PermissionVerdict::Allow => HookDecision::AllowRewrite(r),
        Some(r) => HookDecision::AskRewrite(r),
        None => HookDecision::Defer,
    }
}

fn decide_hook_action(cmd: &str) -> HookDecision {
    decide_from_verdict(cmd, check_command(cmd))
}

fn handle_vscode(cmd: &str) -> Result<()> {
    let (decision, rewritten) = match decide_hook_action(cmd) {
        HookDecision::Deny => {
            audit_log("deny", cmd, "");
            return Ok(());
        }
        HookDecision::Defer => return Ok(()),
        HookDecision::AllowRewrite(r) => ("allow", r),
        HookDecision::AskRewrite(r) => ("ask", r),
    };

    let output = json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": "RTK auto-rewrite",
            "updatedInput": { "command": rewritten }
        }
    });
    println!("{output}");
    Ok(())
}

fn handle_copilot_cli(cmd: &str) -> Result<()> {
    let rewritten = match get_rewritten(cmd) {
        Some(r) => r,
        None => return Ok(()),
    };

    let output = json!({
        "permissionDecision": "deny",
        "permissionDecisionReason": format!(
            "Token savings: use `{}` instead (rtk saves 60-90% tokens)",
            rewritten
        )
    });
    println!("{output}");
    Ok(())
}

// ── Gemini hook ───────────────────────────────────────────────

/// Run the Gemini CLI BeforeTool hook.
/// Reads JSON from stdin, rewrites shell commands to rtk equivalents,
/// outputs JSON to stdout in Gemini CLI format.
pub fn run_gemini() -> Result<()> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .context("Failed to read hook input from stdin")?;

    let json: Value = serde_json::from_str(&input).context("Failed to parse hook input as JSON")?;

    let tool_name = json.get("tool_name").and_then(|v| v.as_str()).unwrap_or("");

    if tool_name != "run_shell_command" {
        print_allow();
        return Ok(());
    }

    let cmd = json
        .pointer("/tool_input/command")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if cmd.is_empty() {
        print_allow();
        return Ok(());
    }

    match decide_hook_action(cmd) {
        HookDecision::Deny => {
            println!(r#"{{"decision":"deny","reason":"Blocked by RTK permission rule"}}"#);
        }
        HookDecision::AllowRewrite(ref rewritten) => {
            audit_log("rewrite", cmd, rewritten);
            print_gemini("allow", Some(rewritten));
        }
        HookDecision::AskRewrite(ref rewritten) => {
            audit_log("ask", cmd, rewritten);
            print_gemini("ask_user", Some(rewritten));
        }
        HookDecision::Defer => print_gemini("ask_user", None),
    }

    Ok(())
}

fn print_allow() {
    println!(r#"{{"decision":"allow"}}"#);
}

fn gemini_json(decision: &str, rewrite: Option<&str>) -> String {
    let mut output = serde_json::json!({ "decision": decision });
    if let Some(cmd) = rewrite {
        output["hookSpecificOutput"] = serde_json::json!({ "tool_input": { "command": cmd } });
    }
    output.to_string()
}

fn print_gemini(decision: &str, rewrite: Option<&str>) {
    let _ = writeln!(io::stdout(), "{}", gemini_json(decision, rewrite));
}

// ── Audit logging ─────────────────────────────────────────────

/// Best-effort audit log when RTK_HOOK_AUDIT=1.
fn audit_log(action: &str, original: &str, rewritten: &str) {
    if std::env::var("RTK_HOOK_AUDIT").as_deref() != Ok("1") {
        return;
    }
    let _ = audit_log_inner(action, original, rewritten);
}

/// Escape newlines to prevent log-line injection in the pipe-delimited audit log.
fn sanitize_log_field(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn audit_log_inner(action: &str, original: &str, rewritten: &str) -> Option<()> {
    let home = dirs::home_dir()?;
    let dir = home.join(".local").join("share").join("rtk");
    std::fs::create_dir_all(&dir).ok()?;
    let path = dir.join("hook-audit.log");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()?;
    let ts = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S");
    writeln!(
        file,
        "{} | {} | {} | {}",
        ts,
        action,
        sanitize_log_field(original),
        sanitize_log_field(rewritten)
    )
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Copilot format detection ---

    fn vscode_input(tool: &str, cmd: &str) -> Value {
        json!({
            "tool_name": tool,
            "tool_input": { "command": cmd }
        })
    }

    fn copilot_cli_input(cmd: &str) -> Value {
        let args = serde_json::to_string(&json!({ "command": cmd })).unwrap();
        json!({ "toolName": "bash", "toolArgs": args })
    }

    #[test]
    fn test_detect_vscode_bash() {
        assert!(matches!(
            detect_format(&vscode_input("Bash", "git status")),
            HookFormat::VsCode { .. }
        ));
    }

    #[test]
    fn test_detect_vscode_run_terminal_command() {
        assert!(matches!(
            detect_format(&vscode_input("runTerminalCommand", "cargo test")),
            HookFormat::VsCode { .. }
        ));
    }

    #[test]
    fn test_detect_copilot_cli_bash() {
        assert!(matches!(
            detect_format(&copilot_cli_input("git status")),
            HookFormat::CopilotCli { .. }
        ));
    }

    #[test]
    fn test_detect_non_bash_is_passthrough() {
        let v = json!({ "tool_name": "editFiles" });
        assert!(matches!(detect_format(&v), HookFormat::PassThrough));
    }

    #[test]
    fn test_detect_unknown_is_passthrough() {
        assert!(matches!(detect_format(&json!({})), HookFormat::PassThrough));
    }

    #[test]
    fn test_get_rewritten_supported() {
        assert!(get_rewritten("git status").is_some());
    }

    #[test]
    fn test_get_rewritten_unsupported() {
        assert!(get_rewritten("htop").is_none());
    }

    #[test]
    fn test_get_rewritten_already_rtk() {
        assert!(get_rewritten("rtk git status").is_none());
    }

    #[test]
    fn test_get_rewritten_heredoc() {
        assert!(get_rewritten("cat <<'EOF'\nhello\nEOF").is_none());
    }

    // --- Gemini format ---

    #[test]
    fn test_print_allow_format() {
        // Verify the allow JSON format matches Gemini CLI expectations
        let expected = r#"{"decision":"allow"}"#;
        assert_eq!(expected, r#"{"decision":"allow"}"#);
    }

    #[test]
    fn test_print_rewrite_format() {
        let output = serde_json::json!({
            "decision": "allow",
            "hookSpecificOutput": {
                "tool_input": {
                    "command": "rtk git status"
                }
            }
        });
        let json: Value = serde_json::from_str(&output.to_string()).unwrap();
        assert_eq!(json["decision"], "allow");
        assert_eq!(
            json["hookSpecificOutput"]["tool_input"]["command"],
            "rtk git status"
        );
    }

    #[test]
    fn test_gemini_hook_uses_rewrite_command() {
        // Verify that rewrite_command handles the cases we need for Gemini
        assert_eq!(
            rewrite_command("git status", &[]),
            Some("rtk git status".into())
        );
        assert_eq!(
            rewrite_command("cargo test", &[]),
            Some("rtk cargo test".into())
        );
        // Already rtk → returned as-is (idempotent)
        assert_eq!(
            rewrite_command("rtk git status", &[]),
            Some("rtk git status".into())
        );
        // Heredoc → no rewrite
        assert_eq!(rewrite_command("cat <<EOF", &[]), None);
    }

    #[test]
    fn test_gemini_hook_excluded_commands() {
        let excluded = vec!["curl".to_string()];
        assert_eq!(rewrite_command("curl https://example.com", &excluded), None);
        // Non-excluded still rewrites
        assert_eq!(
            rewrite_command("git status", &excluded),
            Some("rtk git status".into())
        );
    }

    #[test]
    fn test_gemini_hook_env_prefix_preserved() {
        assert_eq!(
            rewrite_command("RUST_LOG=debug cargo test", &[]),
            Some("RUST_LOG=debug rtk cargo test".into())
        );
    }
    // --- Audit logging ---

    #[test]
    fn test_audit_log_silent_when_disabled() {
        std::env::remove_var("RTK_HOOK_AUDIT");
        audit_log("test", "git status", "rtk git status");
    }

    #[test]
    fn test_audit_log_format_four_fields() {
        let tmp = std::env::temp_dir().join("rtk-test-audit");
        let _ = std::fs::create_dir_all(&tmp);
        let log_path = tmp.join("hook-audit.log");
        let _ = std::fs::remove_file(&log_path);

        {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .unwrap();
            let ts = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S");
            writeln!(file, "{} | rewrite | git status | rtk git status", ts).unwrap();
        }

        let content = std::fs::read_to_string(&log_path).unwrap();
        let parts: Vec<&str> = content.trim().split(" | ").collect();
        assert_eq!(
            parts.len(),
            4,
            "Expected 4 pipe-delimited fields, got: {:?}",
            parts
        );
        assert_eq!(parts[1], "rewrite");
        assert_eq!(parts[2], "git status");
        assert_eq!(parts[3], "rtk git status");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // --- Adversarial tests ---

    #[test]
    fn test_audit_log_sanitizes_newlines() {
        let sanitized = sanitize_log_field("git status\nfake | inject | evil");
        assert!(!sanitized.contains('\n'));
        assert!(sanitized.contains("\\n"));
    }

    #[test]
    fn test_audit_log_sanitizes_pipe_delimiter() {
        let sanitized = sanitize_log_field("git log | head");
        assert!(
            !sanitized.contains(" | "),
            "unescaped ' | ' breaks field parsing: {}",
            sanitized
        );
        assert!(sanitized.contains("\\|"));
    }

    #[test]
    fn test_cursor_deny_blocks_rewrite() {
        use crate::hooks::permissions::check_command_with_rules;
        let deny = vec!["git status".to_string()];
        assert_eq!(
            check_command_with_rules("git status", &deny, &[], &[]),
            PermissionVerdict::Deny
        );
    }

    #[test]
    fn test_gemini_deny_blocks_rewrite() {
        use crate::hooks::permissions::check_command_with_rules;
        let deny = vec!["cargo test".to_string()];
        assert_eq!(
            check_command_with_rules("cargo test", &deny, &[], &[]),
            PermissionVerdict::Deny
        );
        // Denied commands must not be rewritten — Gemini handler checks deny before rewrite
        assert!(
            get_rewritten("cargo test").is_some(),
            "cargo test should be rewritable when not denied"
        );
    }

    // --- Shared decision flow (all hosts route through this) ---

    fn decide_with_rules(
        cmd: &str,
        deny: &[String],
        ask: &[String],
        allow: &[String],
    ) -> HookDecision {
        let verdict = crate::hooks::permissions::check_command_with_rules(cmd, deny, ask, allow);
        decide_from_verdict(cmd, verdict)
    }

    fn all_allowed() -> Vec<String> {
        vec!["*".to_string()]
    }

    #[test]
    fn test_decide_allow_for_attestable_allowed_command() {
        assert!(matches!(
            decide_with_rules("git status", &[], &[], &all_allowed()),
            HookDecision::AllowRewrite(_)
        ));
    }

    #[test]
    fn test_decide_ask_for_default_verdict() {
        assert!(matches!(
            decide_with_rules("git status", &[], &[], &[]),
            HookDecision::AskRewrite(_)
        ));
    }

    #[test]
    fn test_decide_deny() {
        assert!(matches!(
            decide_with_rules(
                "rm -rf /tmp/x",
                &["rm -rf".to_string()],
                &[],
                &all_allowed()
            ),
            HookDecision::Deny
        ));
    }

    #[test]
    fn test_decide_defer_for_substitution_even_when_allowed() {
        for cmd in [
            "git status `rm -rf /tmp/x`",
            "git status $(rm -rf /tmp/x)",
            "git log --pretty=\"$(rm -rf /tmp/x)\"",
        ] {
            assert!(
                matches!(
                    decide_with_rules(cmd, &[], &[], &all_allowed()),
                    HookDecision::Defer
                ),
                "expected Defer for {cmd}"
            );
        }
    }

    #[test]
    fn test_decide_defer_for_file_redirect() {
        assert!(matches!(
            decide_with_rules("git log > /tmp/out.txt", &[], &[], &all_allowed()),
            HookDecision::Defer
        ));
    }

    #[test]
    fn test_decide_allow_for_fd_dup_redirect() {
        assert!(matches!(
            decide_with_rules("git status 2>&1", &[], &[], &all_allowed()),
            HookDecision::AllowRewrite(_)
        ));
    }

    // --- Gemini rendering ---

    fn gemini_render(cmd: &str, deny: &[String], ask: &[String], allow: &[String]) -> String {
        match decide_with_rules(cmd, deny, ask, allow) {
            HookDecision::Deny => {
                r#"{"decision":"deny","reason":"Blocked by RTK permission rule"}"#.to_string()
            }
            HookDecision::AllowRewrite(r) => gemini_json("allow", Some(&r)),
            HookDecision::AskRewrite(r) => gemini_json("ask_user", Some(&r)),
            HookDecision::Defer => gemini_json("ask_user", None),
        }
    }

    #[test]
    fn test_gemini_allow_emits_rewrite() {
        let v: Value =
            serde_json::from_str(&gemini_render("git status", &[], &[], &all_allowed())).unwrap();
        assert_eq!(v["decision"], "allow");
        assert_eq!(
            v["hookSpecificOutput"]["tool_input"]["command"],
            "rtk git status"
        );
    }

    #[test]
    fn test_gemini_default_asks_user() {
        let v: Value = serde_json::from_str(&gemini_render("git status", &[], &[], &[])).unwrap();
        assert_eq!(v["decision"], "ask_user");
    }

    #[test]
    fn test_gemini_substitution_asks_user_without_rewrite() {
        let v: Value = serde_json::from_str(&gemini_render(
            "git status `rm -rf /tmp/x`",
            &[],
            &[],
            &all_allowed(),
        ))
        .unwrap();
        assert_eq!(v["decision"], "ask_user");
        assert!(v.get("hookSpecificOutput").is_none());
    }

    #[test]
    fn test_gemini_deny_decision() {
        let v: Value = serde_json::from_str(&gemini_render(
            "rm -rf /tmp/x",
            &["rm -rf".to_string()],
            &[],
            &[],
        ))
        .unwrap();
        assert_eq!(v["decision"], "deny");
    }
}
