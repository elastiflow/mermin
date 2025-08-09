use std::{fs, path::Path};

use anyhow::{Context as _, anyhow};
use toml::Value;

/// Reads the `rust-toolchain.toml` file from the workspace root and returns the
/// value of the `channel` key.
pub fn get_toolchain_channel(workspace_root: &Path) -> anyhow::Result<String> {
    let toolchain_file = workspace_root.join("rust-toolchain.toml");
    let content = fs::read_to_string(&toolchain_file)
        .with_context(|| format!("failed to read {}", toolchain_file.display()))?;

    let config: Value = toml::from_str(&content)
        .with_context(|| format!("failed to parse {}", toolchain_file.display()))?;

    let channel = config
        .get("toolchain")
        .and_then(|t| t.get("channel"))
        .and_then(|c| c.as_str())
        .ok_or_else(|| {
            anyhow!(
                "`[toolchain].channel` not found in {}",
                toolchain_file.display()
            )
        })?;

    Ok(channel.to_string())
}
