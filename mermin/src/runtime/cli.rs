use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use tracing::Level;

use crate::runtime::conf::conf_serde::level;

#[derive(Parser, Debug, Serialize, Deserialize)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Set the path to the configuration file (e.g., "conf.yaml").
    #[arg(short, long, value_name = "FILE", env = "MERMIN_CONFIG_PATH")]
    pub config: Option<PathBuf>,

    /// Automatically reload the configuration file when it changes.
    #[arg(
        short,
        long,
        action = clap::ArgAction::SetTrue,
        env = "MERMIN_CONFIG_AUTO_RELOAD"
    )]
    #[serde(skip_serializing_if = "is_false")]
    pub auto_reload: bool,

    /// Set the application's log level (e.g., "debug", "warn").
    #[arg(short, long, value_name = "LEVEL", env = "MERMIN_LOG_LEVEL")]
    #[serde(with = "level::option", skip_serializing_if = "Option::is_none")]
    pub log_level: Option<Level>,

    #[command(subcommand)]
    pub subcommand: Option<CliSubcommand>,
    // TODO: metrics port, API port, API TLS
}

#[derive(Subcommand, Debug, Clone, Serialize, Deserialize)]
pub enum CliSubcommand {
    /// Test BPF filesystem writeability and program attach/detach operations
    TestBpf {
        /// Network interface to test attach/detach operations on
        #[arg(short, long, default_value = "lo", conflicts_with = "all")]
        interface: Option<String>,
        /// Test all network interfaces (mutually exclusive with --interface)
        #[arg(long, action = clap::ArgAction::SetTrue)]
        all: bool,
        /// Glob pattern to filter interfaces (only valid with --all, can be specified multiple times)
        #[arg(long, requires = "all", action = clap::ArgAction::Append)]
        pattern: Vec<String>,
        /// Glob pattern to exclude interfaces (only valid with --all, can be specified multiple times)
        #[arg(long, requires = "all", action = clap::ArgAction::Append)]
        skip: Vec<String>,
    },
}

fn is_false(v: &bool) -> bool {
    !*v
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::Parser as _;
    use figment::Jail;
    use tracing::Level;

    use super::Cli;

    #[test]
    fn parses_long_flags() {
        Jail::expect_with(|jail| {
            jail.set_env("MERMIN_CONFIG_PATH", "/tmp/mermin.yaml");
            jail.set_env("MERMIN_CONFIG_AUTO_RELOAD", "false");
            jail.set_env("MERMIN_LOG_LEVEL", "debug");

            let args = [
                "mermin",
                "--config",
                "/path/to/conf.yaml",
                "--auto-reload",
                "--log-level",
                "warn",
            ];
            let cli = Cli::parse_from(args);
            assert_eq!(cli.config, Some(PathBuf::from("/path/to/conf.yaml")));
            assert_eq!(cli.auto_reload, true);
            assert_eq!(cli.log_level, Some(Level::WARN));

            Ok(())
        });
    }

    #[test]
    fn parses_from_env_when_no_args() {
        Jail::expect_with(|jail| {
            jail.set_env("MERMIN_CONFIG_PATH", "/tmp/mermin.yaml");
            jail.set_env("MERMIN_CONFIG_AUTO_RELOAD", "true");
            jail.set_env("MERMIN_LOG_LEVEL", "debug");

            let cli = Cli::parse_from(["mermin"]);
            assert_eq!(cli.config, Some(PathBuf::from("/tmp/mermin.yaml")));
            assert_eq!(cli.auto_reload, true);
            assert_eq!(cli.log_level, Some(Level::DEBUG));

            Ok(())
        });
    }

    #[test]
    fn default_log_level_is_info() {
        Jail::expect_with(|_| {
            let cli = Cli::parse_from(["mermin"]);
            assert_eq!(cli.log_level, None);

            Ok(())
        });
    }

    #[test]
    fn default_auto_reload_is_false() {
        Jail::expect_with(|_| {
            let cli = Cli::parse_from(["mermin"]);
            assert_eq!(cli.auto_reload, false);

            Ok(())
        });
    }
}
