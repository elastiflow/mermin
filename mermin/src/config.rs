use std::{error::Error, fmt};

use figment::{
    Figment,
    providers::{Env, Format, Serialized, Yaml},
};
use serde::{Deserialize, Serialize};

use crate::cli;

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub interface: String,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            interface: "lo".to_string(),
        }
    }
}

impl Config {
    fn new(cli: cli::Cli) -> Result<Self, ConfigError> {
        let mut figment = Figment::new()
            .merge(Serialized::defaults(&cli))
            .join(Env::prefixed("MERMIN_"));

        let env_config_path = figment.find_value("config_path").ok();
        if cli.config.is_none() && env_config_path.is_none() {
            return Err(ConfigError::NoConfigFile);
        }

        if let Some(config_path) = &cli.config {
            figment = figment.join(Yaml::file(config_path));
        } else if let Some(config_path) = env_config_path {
            let config_path = config_path.as_str().ok_or(ConfigError::InvalidConfigPath)?;
            figment = figment.join(Yaml::file(config_path));
        }

        let config: Config = figment.extract()?;
        Ok(config)
    }
}

#[derive(Debug)]
pub enum ConfigError {
    NoConfigFile,
    InvalidConfigPath,
    Extraction(figment::Error),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::NoConfigFile => write!(f, "no config file provided"),
            ConfigError::InvalidConfigPath => write!(f, "config_path must be a string"),
            ConfigError::Extraction(e) => write!(f, "configuration error: {}", e),
        }
    }
}

impl Error for ConfigError {}

impl From<figment::Error> for ConfigError {
    fn from(e: figment::Error) -> Self {
        ConfigError::Extraction(e)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use clap::Parser;
    use serial_test::serial;
    use tracing::Level;

    use super::Config;
    use crate::cli::Cli;

    fn clear_env_vars() {
        // This helper ensures a clean slate before each test.
        // Note: `remove_var` is not unsafe.
        unsafe {
            env::remove_var("MERMIN_CONFIG_PATH");
        }
    }

    fn unique_temp_path(filename: &str) -> PathBuf {
        let mut p = env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("{}_{}", nanos, filename));
        p
    }

    #[test]
    #[serial]
    fn default_impl_has_lo_interface() {
        let cfg = Config::default();
        assert_eq!(cfg.interface, "lo");
    }

    #[test]
    #[serial]
    fn new_errors_without_config_path() {
        clear_env_vars();
        let cli = Cli {
            config: None,
            auto_reload: false,
            log_level: Level::INFO,
        };
        let err = Config::new(cli).expect_err("expected error without config path");
        let msg = err.to_string();
        assert!(
            msg.contains("no config file provided"),
            "unexpected error: {}",
            msg
        );
    }

    #[test]
    #[serial]
    fn loads_from_cli_yaml_file() {
        clear_env_vars();
        let path = unique_temp_path("mermin_cli.yaml");
        fs::write(&path, b"interface: eth1\n").expect("write temp yaml");

        let cli = Cli {
            config: Some(path.clone()),
            auto_reload: false,
            log_level: Level::INFO,
        };
        let cfg = Config::new(cli).expect("config loads from cli file");
        assert_eq!(cfg.interface, "eth1");

        fs::remove_file(path).expect("remove temp yaml");
    }

    #[test]
    #[serial]
    fn loads_from_env_yaml_file_when_cli_missing() {
        clear_env_vars();
        let path = unique_temp_path("mermin_env.yaml");
        fs::write(&path, b"interface: enx0\n").expect("write temp yaml");
        unsafe {
            env::set_var("MERMIN_CONFIG_PATH", path.to_string_lossy().to_string());
        }

        let cli = Cli::parse_from(["mermin"]);
        let cfg = Config::new(cli).expect("config loads from env file");
        assert_eq!(cfg.interface, "enx0");

        fs::remove_file(path).expect("remove temp yaml");
    }
}
