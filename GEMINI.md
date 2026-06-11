# rtk — Gemini Context

rtk (Rust Token Killer) is a high-performance CLI proxy that minimizes LLM token consumption by filtering and compressing command outputs.

## 🎯 Project Overview
- **Purpose:** Minimize token usage for development commands (git, cargo, npm, etc.).
- **Architecture:** Command proxy with specialized filter modules.
- **Stack:** Rust.

## 🛠 Building and Running

### Build Commands
- **Build:** `cargo build`
- **Release Build:** `cargo build --release`
- **Install Locally:** `cargo install --path .`

### Quality & Testing
- **Test:** `cargo test`
- **Lint:** `cargo clippy --all-targets`
- **Format:** `cargo fmt`
- **Check:** `cargo check`

### Pre-commit Gate
```bash
cargo fmt --all && cargo clippy --all-targets && cargo test --all
```

## 📏 Operational Rules
- **Error Handling:** Use `anyhow::Result` everywhere with `.context()`.
- **Safety:** No `unwrap()` in production code.
- **Performance:** Maintain <10ms startup and <5MB memory usage.
- **Decoupling:** Binary must not depend on local repo path once installed.

## 🤝 Workspace Conventions
- **CHANGELOG.md:** Append-only, required per commit.
- **Task Lifecycle:** todo → plan_proposed → plan_approved → in_progress → report_ready → review_requested → review_passed → done.
- **Task Management:** Use `shux` for all task coordination.
- **Handoffs:** Write via `shux handoff-write`.
