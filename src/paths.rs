use std::path::PathBuf;

pub(crate) fn resolve_state_dir() -> PathBuf {
    if let Some(dir) = crate::config::read_process_env("CARAPACE_STATE_DIR") {
        return PathBuf::from(dir);
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from(".config"))
        .join("carapace")
}
