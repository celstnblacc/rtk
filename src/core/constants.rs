pub const RTK_DATA_DIR: &str = "rtk";
pub const HISTORY_DB: &str = "history.db";
pub const CONFIG_TOML: &str = "config.toml";
// Live in the real binary (TomlFilterRegistry::load -> REGISTRY ->
// find_matching_filter -> main.rs). `--all-targets` also builds a test binary
// that never links main's call path, so the whole chain looks dead there and
// `[lints.rust] warnings = "deny"` turns it into a hard error. Scope the allow
// to test builds only, so genuinely dead code is still caught in real builds.
#[cfg_attr(test, allow(dead_code))]
pub const FILTERS_TOML: &str = "filters.toml";
pub const TRUSTED_FILTERS_JSON: &str = "trusted_filters.json";
pub const DEFAULT_HISTORY_DAYS: i64 = 90;
