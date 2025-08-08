use std::{fs, path::Path};

use anyhow::{Context as _, anyhow};
use aya_build::{Toolchain, cargo_metadata};
use toml::Value;

const EBPF_PACKAGE_NAME: &str = "mermin-ebpf";

/// Reads the `rust-toolchain.toml` file from the workspace root and returns the
/// value of the `channel` key.
fn get_toolchain_channel(workspace_root: &Path) -> anyhow::Result<String> {
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

fn main() -> anyhow::Result<()> {
    let meta = cargo_metadata::MetadataCommand::new().exec()?;
    let workspace_root = &meta.workspace_root;

    let channel = get_toolchain_channel(workspace_root.as_ref())?;
    let toolchain = Toolchain::Custom(&channel);

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;

    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| **name == EBPF_PACKAGE_NAME)
        .ok_or_else(|| anyhow!("mermin-ebpf package not found"))?;

    aya_build::build_ebpf([ebpf_package], toolchain)
}
