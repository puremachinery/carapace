use std::path::PathBuf;

pub(crate) fn resolve_state_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("CARAPACE_STATE_DIR") {
        return PathBuf::from(dir);
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from(".config"))
        .join("carapace")
}
