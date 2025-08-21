use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

use figment::{
    Figment, Provider,
    providers::{Format, Serialized, Yaml},
};
use serde::{Deserialize, Serialize};
use tracing::Level;

use crate::runtime::{
    cli::Cli,
    conf::{conf_serde::level, flow::Flow},
};

pub mod conf_serde;
mod flow;

/// Represents the configuration for the application, containing settings
/// related to interface, logging, reloading, and flow management.
///
/// This struct is serializable and deserializable using Serde, allowing
/// it to be easily read from or written to configuration files in
/// formats like YAML.
#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    /// A vector of strings representing the network interfaces or endpoints
    /// that the application should operate on. These interfaces are read
    /// directly from the configuration file.
    pub interface: Vec<String>,

    /// An optional `PathBuf` field that represents the file path to the
    /// configuration file. This field is annotated with `#[serde(skip)]`,
    /// meaning its value will not be serialized or deserialized. It is
    /// used internally for managing the configuration's source path.
    #[serde(skip)]
    pub config_path: Option<PathBuf>,

    /// A boolean flag indicating whether the application should automatically
    /// reload the configuration whenever changes are detected in the
    /// relevant configuration file. This is typically used to support runtime
    /// configuration updates.
    pub auto_reload: bool,

    /// The logging level for the application, serialized and deserialized
    /// using the custom Serde module named `level`. This allows more
    /// precise handling of log level values, particularly when
    /// deserializing from non-standard formats.
    #[serde(with = "level")]
    pub log_level: Level,

    /// A `Flow` type (defined elsewhere in the codebase) which contains
    /// settings related to the application's runtime flow management.
    /// This field encapsulates additional configuration details specific
    /// to how the application's logic operates.
    pub flow: Flow,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            interface: Vec::from(["eth0".to_string()]),
            config_path: None,
            auto_reload: false,
            log_level: Level::INFO,
            flow: Flow::default(),
        }
    }
}

impl Config {
    /// Creates a new `Config` instance based on the provided CLI arguments, environment variables,
    /// and configuration file. The configuration is determined using the following priority order:
    /// Defaults < Configuration File < Environment Variables < CLI Arguments.
    ///
    /// # Arguments
    /// * `cli` - An instance of `Cli` containing parsed CLI arguments.
    ///
    /// # Returns
    /// * `Result<(Self, Cli), ConfigError>` - Returns an `Ok((Config, Cli))` if successful, or a `ConfigError`
    ///   if there are issues during configuration extraction.
    ///
    /// # Errors
    /// * `ConfigError::NoConfigFile` - Returned if no configuration file is specified or found.
    /// * `ConfigError::InvalidConfigPath` - Returned if the `config_path` from the environment
    ///   variable cannot be converted to a valid string.
    /// * Other `ConfigError` variants - Errors propagated during the extraction of the configuration.
    ///
    /// # Behavior
    /// 1. Initializes a `Figment` instance with default values from `cli` and merges it with
    ///    environment variables prefixed by "MERMIN_".
    /// 2. Attempts to retrieve the `config_path` from the CLI arguments or the environment variable.
    ///    If no path is provided or found, the function returns a `ConfigError::NoConfigFile`.
    /// 3. If a configuration file is specified via CLI or environment variable, it is merged with
    ///    the existing `Figment` configuration.
    /// 4. Extracts the final configuration into a `Config` struct, storing the path to the
    ///    configuration file (if any).
    ///
    /// # Example
    /// ```
    /// use my_crate::{ConfigError, Config};
    /// use my_crate::Cli;
    ///
    /// let cli = Cli::parse(); // Parse CLI arguments
    /// match Config::new(cli) {
    ///     Ok((conf, _cli)) => {
    ///         println!("Configuration loaded successfully: {:?}", conf);
    ///     },
    ///     Err(err) => {
    ///         eprintln!("Failed to load configuration: {}", err);
    ///     },
    /// }
    /// ```
    pub fn new(cli: Cli) -> Result<(Self, Cli), ConfigError> {
        let mut figment = Figment::new().merge(Serialized::defaults(Config::default()));

        println!("Figment: {:?}", figment.data()?);
        println!("CLI Defaults: {:?}", Serialized::defaults(&cli).value);

        let config_path_to_store = if let Some(config_path) = &cli.config {
            validate_config_path(config_path)?;
            figment = figment.merge(Yaml::file(config_path));
            Some(config_path.clone())
        } else {
            None
        };

        println!("Figment: {:?}", figment.data()?);

        figment = figment.merge(Serialized::defaults(&cli));

        println!("Figment: {:?}", figment.data()?);

        let mut config: Config = figment.extract()?;

        println!("DEBUG");
        config.config_path = config_path_to_store;
        Ok((config, cli))
    }

    /// Reloads the configuration from the config file and returns a new instance
    /// of the configuration object.
    ///
    /// This method allows for dynamic reloading of the configuration without
    /// requiring a restart of the application. Any updates to the configuration
    /// file will be applied, creating a new configuration object based on the
    /// file's content.
    ///
    /// Note:
    /// - Command-line arguments (CLI) and environment variables (ENV VARS) will
    ///   not be reloaded since it is assumed that the shell environment remains
    ///   the same. The reload operation will use the current configuration as the
    ///   base and layer the updated configuration file on top of it.
    /// - If no configuration file path has been specified, an error will be returned.
    ///
    /// # Returns
    /// - `Ok(Self)` containing the reloaded configuration object if the reload
    ///   operation succeeds.
    /// - `Err(ConfigError::NoConfigFile)` if no configuration file path is set.
    /// - Returns other variants of `ConfigError` if the configuration fails to
    ///   load or extract properly.
    ///
    /// # Errors
    /// This function returns a `ConfigError` in the following scenarios:
    /// - If there is no configuration file path specified (`ConfigError::NoConfigFile`).
    /// - If the configuration fails to load or parse from the file.
    ///
    /// # Example
    /// ```rust
    /// use conf::Config;
    ///
    /// let conf = Config::default();
    /// match conf.reload() {
    ///     Ok(new_config) => {
    ///         println!("Configuration reloaded successfully.");
    ///     }
    ///     Err(e) => {
    ///         eprintln!("Failed to reload configuration: {:?}", e);
    ///     }
    /// }
    /// ```
    #[allow(dead_code)]
    pub fn reload(&self) -> Result<Self, ConfigError> {
        if let Some(path) = &self.config_path {
            let mut config: Config = Figment::from(Serialized::defaults(self))
                .merge(Yaml::file(path))
                .extract()?;
            config.config_path = self.config_path.clone();

            Ok(config)
        } else {
            Err(ConfigError::NoConfigFile)
        }
    }
}

/// Validates that the given path points to an existing file with a supported extension.
///
/// # Arguments
///
/// * `path` - A reference to a `PathBuf` to validate.
///
/// # Errors
///
/// * `ConfigError::NoConfigFile` - If the path does not exist.
/// * `ConfigError::InvalidConfigPath` - If the path points to a directory.
/// * `ConfigError::InvalidExtension` - If the file extension is not `yaml`, `yml`, or `hcl`.
fn validate_config_path(path: &Path) -> Result<(), ConfigError> {
    // 1. First, check that the path points to a file. The `is_file()` method
    // conveniently returns false if the path doesn't exist or if it's not a file.
    if !path.is_file() {
        // If it's not a file, distinguish between "doesn't exist" and "is a directory".
        if path.exists() {
            // Path exists but is not a file (it's a directory).
            return Err(ConfigError::InvalidConfigPath(
                path.to_string_lossy().into_owned(),
            ));
        } else {
            // Path does not exist at all.
            return Err(ConfigError::NoConfigFile);
        }
    }

    // 2. If it's a file, check the extension.
    match path.extension().and_then(|s| s.to_str()) {
        // Allowed extensions
        Some("yaml") | Some("yml") | Some("hcl") => Ok(()),
        // An unsupported extension was found
        Some(ext) => Err(ConfigError::InvalidExtension(ext.to_string())),
        // No extension was found
        None => Err(ConfigError::InvalidExtension("none".to_string())),
    }
}

#[derive(Debug)]
pub enum ConfigError {
    /// Error: The specified configuration file does not exist.
    NoConfigFile,
    /// Error: The path exists but is not a file (e.g., it's a directory).
    InvalidConfigPath(String),
    /// Error: The file has an unsupported extension.
    InvalidExtension(String),
    /// Error: Failed to extract configuration data. (from your original code)
    Extraction(Box<figment::Error>),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::NoConfigFile => write!(f, "no config file provided"),
            ConfigError::InvalidConfigPath(p) => write!(f, "path '{p}' is not a valid file"),
            ConfigError::InvalidExtension(ext) => {
                write!(
                    f,
                    "invalid file extension '.{ext}' — expected 'yaml', 'yml', or 'hcl'"
                )
            }
            ConfigError::Extraction(e) => write!(f, "configuration error: {e}"),
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ConfigError::Extraction(e) => Some(e),
            _ => None,
        }
    }
}

impl From<figment::Error> for ConfigError {
    fn from(e: figment::Error) -> Self {
        ConfigError::Extraction(Box::from(e))
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use figment::Jail;
    use tracing::Level;

    use super::Config;
    use crate::runtime::cli::Cli;

    #[test]
    fn default_impl_has_eth0_interface() {
        let cfg = Config::default();
        assert_eq!(cfg.interface, Vec::from(["eth0".to_string()]));
        assert_eq!(cfg.config_path, None);
        assert_eq!(cfg.auto_reload, false);
        assert_eq!(cfg.log_level, Level::INFO);
    }

    #[test]
    fn new_succeeds_without_config_path() {
        Jail::expect_with(|_| {
            let cli = Cli::parse_from(["mermin"]);
            let (cfg, _cli) = Config::new(cli).expect("config should load without path");
            assert_eq!(cfg.config_path, None);

            Ok(())
        })
    }

    #[test]
    fn new_errors_with_nonexistent_config_file() {
        Jail::expect_with(|_| {
            let cli = Cli::parse_from(["mermin", "--config", "nonexistent.yaml"]);
            let err = Config::new(cli).expect_err("expected error with nonexistent file");
            let msg = err.to_string();
            assert!(
                msg.contains("no config file provided"),
                "unexpected error: {}",
                msg
            );

            Ok(())
        })
    }

    #[test]
    fn new_errors_with_directory_as_config_path() {
        Jail::expect_with(|jail| {
            let path = "a_directory";
            jail.create_dir(path)?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let err = Config::new(cli).expect_err("expected error with directory path");
            let msg = err.to_string();
            assert!(
                msg.contains("is not a valid file"),
                "unexpected error: {}",
                msg
            );

            Ok(())
        })
    }

    #[test]
    fn new_errors_with_invalid_config_extension() {
        Jail::expect_with(|jail| {
            let path = "mermin.toml";
            jail.create_file(path, "")?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let err = Config::new(cli).expect_err("expected error with invalid extension");
            let msg = err.to_string();
            assert!(
                msg.contains("invalid file extension '.toml'"),
                "unexpected error: {}",
                msg
            );

            Ok(())
        })
    }

    #[test]
    fn loads_from_cli_yaml_file() {
        Jail::expect_with(|jail| {
            let path = "mermin_cli.yaml";
            jail.create_file(
                path,
                r#"
interface:
  - eth1
auto_reload: false
log_level: warn
                "#,
            )?;

            let cli = Cli::parse_from([
                "mermin",
                "--config",
                path.into(),
                "--auto-reload",
                "--log-level",
                "debug",
            ]);
            let (cfg, _cli) = Config::new(cli).expect("config loads from cli file");
            assert_eq!(cfg.interface, Vec::from(["eth1".to_string()]));
            assert_eq!(cfg.auto_reload, true);
            assert_eq!(cfg.log_level, Level::DEBUG);

            Ok(())
        });
    }

    #[test]
    fn loads_from_env_yaml_file_when_cli_missing() {
        Jail::expect_with(|jail| {
            let path = "mermin_env.yaml";
            jail.create_file(
                path,
                r#"
interface: ["eth1"]
auto_reload: true
log_level: debug
                "#,
            )?;
            jail.set_env("MERMIN_CONFIG_PATH", path);

            let cli = Cli::parse_from(["mermin"]);
            let (cfg, _cli) = Config::new(cli).expect("config loads from env file");
            assert_eq!(cfg.interface, Vec::from(["eth1".to_string()]));
            assert_eq!(cfg.auto_reload, true);
            assert_eq!(cfg.log_level, Level::DEBUG);

            Ok(())
        });
    }

    #[test]
    fn reload_updates_config_from_file() {
        Jail::expect_with(|jail| {
            let path = "mermin.yaml";
            jail.create_file(
                path,
                r#"
interface: ["eth1"]
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Config::new(cli).expect("config loads from cli file");
            assert_eq!(cfg.interface, Vec::from(["eth1".to_string()]));
            assert_eq!(cfg.config_path, Some(path.parse().unwrap()));

            // Update the config file
            jail.create_file(
                path,
                r#"
interface: ["eth2", "eth3"]
                "#,
            )?;

            let reloaded_cfg = cfg.reload().expect("config should reload");
            assert_eq!(
                reloaded_cfg.interface,
                Vec::from(["eth2".to_string(), "eth3".to_string()])
            );
            assert_eq!(reloaded_cfg.config_path, Some(path.parse().unwrap()));

            Ok(())
        })
    }

    #[test]
    fn reload_fails_without_config_path() {
        let cfg = Config::default();
        let err = cfg
            .reload()
            .expect_err("expected error when reloading without config path");
        let msg = err.to_string();
        assert!(
            msg.contains("no config file provided"),
            "unexpected error: {}",
            msg
        );
    }
}
