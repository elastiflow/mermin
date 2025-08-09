use anyhow::{Context as _, anyhow};
use aya_build::{Toolchain, cargo_metadata};
use common_build::get_toolchain_channel;

const EBPF_PACKAGE_NAME: &str = "mermin-ebpf";

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
