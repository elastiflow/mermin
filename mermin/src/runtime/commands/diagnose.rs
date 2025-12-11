//! Diagnostic command handlers
//!
//! Provides subcommands for diagnosing eBPF, network, configuration,
//! kernel compatibility, and permission issues.

use crate::{
    error::Result,
    runtime::{cli::DiagnoseCommand, commands},
};

/// Execute a diagnose subcommand
pub async fn execute(command: &DiagnoseCommand) -> Result<()> {
    match command {
        DiagnoseCommand::Bpf {
            interface,
            pattern,
            skip,
        } => commands::bpf::execute(interface.as_deref(), pattern, skip).await,
    }
}
