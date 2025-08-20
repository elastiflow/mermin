use std::path::PathBuf;

use clap::Parser;
use serde::{Deserialize, Serialize};
use tracing::Level;

use crate::runtime::serde_level;

#[derive(Parser, Debug, Serialize, Deserialize)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Set the path to the configuration file (e.g., "config.yaml").
    #[arg(short, long, value_name = "FILE", env = "MERMIN_CONFIG_PATH")]
    pub config: Option<PathBuf>,

    /// Automatically reload the configuration file when it changes.
    #[arg(
        short,
        long,
        env = "MERMIN_CONFIG_AUTO_RELOAD",
        default_value = "false"
    )]
    pub auto_reload: bool,

    /// Set the application's log level (e.g., "debug", "warn").
    #[arg(
        short,
        long,
        value_name = "LEVEL",
        env = "MERMIN_LOG_LEVEL",
        default_value = "info"
    )]
    #[serde(with = "serde_level")]
    pub log_level: Level,
    // TODO: metrics port, API port, API TLS
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
            assert_eq!(cli.log_level, Level::WARN);

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
            assert_eq!(cli.log_level, Level::DEBUG);

            Ok(())
        });
    }

    #[test]
    fn default_log_level_is_info() {
        Jail::expect_with(|_| {
            let cli = Cli::parse_from(["mermin"]);
            assert_eq!(cli.log_level, Level::INFO);

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
