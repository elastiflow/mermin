use anyhow::{Context as _, anyhow};
use aya_build::cargo_metadata;

const EBPF_PACKAGE_NAME: &str = "mermin-ebpf";

fn main() -> anyhow::Result<()> {
    let toolchain = match option_env!("TOOLCHAIN_VERSION") {
        Some(version) if !version.is_empty() => aya_build::Toolchain::Custom(version),
        _ => aya_build::Toolchain::Nightly,
    };

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
