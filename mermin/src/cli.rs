use std::path::PathBuf;

use clap::Parser;
use figment::providers::Serialized;
use serde::{Deserialize, Serialize};
use tracing::Level;

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
    #[serde(with = "level_serde")]
    pub log_level: Level,
}

mod level_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use tracing::Level;

    pub fn serialize<S>(level: &Level, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(level.as_str())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Level, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<Level>().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::{env, path::PathBuf};

    use clap::Parser as _;
    use serial_test::serial;
    use tracing::Level;

    use super::Cli;

    fn clear_env_vars() {
        // This helper ensures a clean slate before each test.
        // Note: `remove_var` is not unsafe.
        unsafe {
            env::remove_var("MERMIN_CONFIG_PATH");
            env::remove_var("MERMIN_CONFIG_AUTO_RELOAD");
            env::remove_var("MERMIN_LOG_LEVEL");
        }
    }

    #[test]
    #[serial]
    fn parses_long_flags() {
        clear_env_vars();

        unsafe {
            // ensures that CLI args override env vars
            env::set_var("MERMIN_CONFIG_PATH", "/tmp/mermin.yaml");
            env::set_var("MERMIN_CONFIG_AUTO_RELOAD", "false");
            env::set_var("MERMIN_LOG_LEVEL", "debug");
        }

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
    }

    #[test]
    #[serial]
    fn parses_from_env_when_no_args() {
        clear_env_vars();

        unsafe {
            env::set_var("MERMIN_CONFIG_PATH", "/tmp/mermin.yaml");
            env::set_var("MERMIN_CONFIG_AUTO_RELOAD", "true");
            env::set_var("MERMIN_LOG_LEVEL", "debug");
        }

        let cli = Cli::parse_from(["mermin"]);
        assert_eq!(cli.config, Some(PathBuf::from("/tmp/mermin.yaml")));
        assert_eq!(cli.auto_reload, true);
        assert_eq!(cli.log_level, Level::DEBUG);
    }

    #[test]
    #[serial]
    fn default_log_level_is_info() {
        clear_env_vars();
        let cli = Cli::parse_from(["mermin"]);
        assert_eq!(cli.log_level, Level::INFO);
    }

    #[test]
    #[serial]
    fn default_auto_reload_is_false() {
        clear_env_vars();
        let cli = Cli::parse_from(["mermin"]);
        assert_eq!(cli.auto_reload, false);
    }
}
