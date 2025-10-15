mod error;

use std::{fs, path::Path};

pub use error::BuildError;
use toml::Value;

/// Reads the `rust-toolchain.toml` file from the workspace root and returns the
/// value of the `channel` key.
pub fn get_toolchain_channel(workspace_root: &Path) -> Result<String, BuildError> {
    let toolchain_file = workspace_root.join("rust-toolchain.toml");
    let content = fs::read_to_string(&toolchain_file)
        .map_err(|e| BuildError::toolchain_file_read(toolchain_file.clone(), e))?;

    let config: Value = toml::from_str(&content)?;

    let channel = config
        .get("toolchain")
        .and_then(|t| t.get("channel"))
        .and_then(|c| c.as_str())
        .ok_or_else(|| BuildError::missing_field("toolchain.channel"))?;

    Ok(channel.to_string())
}
