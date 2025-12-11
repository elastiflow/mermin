//! Command handlers for CLI subcommands
//!
//! This module provides a clean separation between CLI argument parsing
//! and command execution logic.

pub mod bpf;
pub mod diagnose;

use crate::{error::Result, runtime::cli::CliSubcommand};

/// Execute a CLI subcommand
pub async fn execute(subcommand: &CliSubcommand) -> Result<()> {
    match subcommand {
        CliSubcommand::Diagnose { command } => diagnose::execute(command).await,
    }
}
