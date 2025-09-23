use std::{
    error::Error,
    fmt,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    time::Duration,
};

use figment::{
    Figment,
    providers::{Format, Serialized, Yaml},
};
use serde::{Deserialize, Serialize};
use tracing::Level;

use crate::{
    otlp::opts::{ExporterConf, SpanOptions},
    runtime::{
        cli::Cli,
        conf::conf_serde::{duration, level},
    },
};

#[derive(Debug, Deserialize, Serialize)]
pub struct ApiConf {
    /// Enable the API server.
    pub enabled: bool,
    /// The network address the API server will listen on.
    pub listen_address: String,
    /// The port the API server will listen on.
    pub port: u16,
}

impl Default for ApiConf {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_address: Ipv4Addr::UNSPECIFIED.to_string(),
            port: 8080,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MetricsConf {
    /// Enable the metrics server.
    pub enabled: bool,
    /// The network address the metrics server will listen on.
    pub listen_address: String,
    /// The port the metrics server will listen on.
    pub port: u16,
}

impl Default for MetricsConf {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_address: Ipv4Addr::UNSPECIFIED.to_string(),
            port: 10250,
        }
    }
}

/// Represents the configuration for the application, containing settings
/// related to interface, logging, reloading, and flow management.
///
/// This struct is serializable and deserializable using Serde, allowing
/// it to be easily read from or written to configuration files in
/// formats like YAML.
#[derive(Debug, Deserialize, Serialize)]
pub struct Conf {
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

    /// Configuration for the API server (health endpoints).
    #[serde(default)]
    pub api: ApiConf,

    /// Configuration for the Metrics server (e.g., for Prometheus scraping).
    #[serde(default)]
    pub metrics: MetricsConf,

    /// Capacity of the channel for packet events between the ring buffer reader and flow workers
    /// - Default: 10000
    /// - Example: Increase for high-traffic environments, decrease for memory-constrained systems
    #[serde(default = "defaults::packet_channel_capacity")]
    pub packet_channel_capacity: usize,

    /// Number of worker tasks for flow processing
    /// - Default: 2
    /// - Example: Increase for high CPU systems, keep at 1-2 for most deployments
    #[serde(default = "defaults::flow_workers")]
    pub packet_worker_count: usize,

    /// Maximum time to wait for graceful shutdown of pipeline components
    /// Increase for environments with slow disk I/O or network operations
    /// - Default: 5s
    #[serde(default = "defaults::shutdown_timeout", with = "duration")]
    pub shutdown_timeout: Duration,

    /// A `Flow` type (defined elsewhere in the codebase) which contains
    /// settings related to the application's runtime flow management.
    /// This field encapsulates additional configuration details specific
    /// to how the application's logic operates.
    pub span: SpanOptions,

    /// Vector of exporters configuration options.
    /// This field holds setting for exporting telemetry data
    /// to multiple destinations.
    pub exporters: Vec<ExporterConf>,
}

impl Default for Conf {
    fn default() -> Self {
        Self {
            interface: Vec::from(["eth0".to_string()]),
            config_path: None,
            auto_reload: false,
            log_level: Level::INFO,
            api: ApiConf::default(),
            metrics: MetricsConf::default(),
            packet_channel_capacity: defaults::packet_channel_capacity(),
            packet_worker_count: defaults::flow_workers(),
            shutdown_timeout: defaults::shutdown_timeout(),
            span: SpanOptions::default(),
            exporters: Vec::new(),
        }
    }
}

mod defaults {
    use std::time::Duration;

    pub fn packet_channel_capacity() -> usize {
        1024
    }

    pub fn flow_workers() -> usize {
        2
    }

    pub fn shutdown_timeout() -> Duration {
        Duration::from_secs(5)
    }
}

impl Conf {
    /// Creates a new `Conf` instance based on the provided CLI arguments, environment variables,
    /// and configuration file. The configuration is determined using the following priority order:
    /// Defaults < Configuration File < Environment Variables < CLI Arguments.
    ///
    /// # Arguments
    /// * `cli` - An instance of `Cli` containing parsed CLI arguments.
    ///
    /// # Returns
    /// * `Result<(Self, Cli), ConfigError>` - Returns an `Ok((Conf, Cli))` if successful, or a `ConfigError`
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
    /// 4. Extracts the final configuration into a `Conf` struct, storing the path to the
    ///    configuration file (if any).
    ///
    /// # Example
    /// ```
    /// use my_crate::{ConfigError, Conf};
    /// use my_crate::Cli;
    ///
    /// let cli = Cli::parse(); // Parse CLI arguments
    /// match Conf::new(cli) {
    ///     Ok((conf, _cli)) => {
    ///         println!("Configuration loaded successfully: {:?}", conf);
    ///     },
    ///     Err(err) => {
    ///         eprintln!("Failed to load configuration: {}", err);
    ///     },
    /// }
    /// ```
    pub fn new(cli: Cli) -> Result<(Self, Cli), ConfigError> {
        let mut figment = Figment::new().merge(Serialized::defaults(Conf::default()));

        let config_path_to_store = if let Some(config_path) = &cli.config {
            validate_config_path(config_path)?;
            figment = figment.merge(Yaml::file(config_path));
            Some(config_path.clone())
        } else {
            None
        };

        figment = figment.merge(Serialized::defaults(&cli));

        let mut conf: Conf = figment.extract()?;

        conf.config_path = config_path_to_store;
        Ok((conf, cli))
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
    /// use conf::Conf;
    ///
    /// let conf = Conf::default();
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
            let mut conf: Conf = Figment::from(Serialized::defaults(self))
                .merge(Yaml::file(path))
                .extract()?;
            conf.config_path = self.config_path.clone();

            Ok(conf)
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

pub mod conf_serde {
    pub mod level {
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

        pub mod option {
            use super::*;

            pub fn serialize<S>(level: &Option<Level>, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                match level {
                    Some(l) => serializer.serialize_str(l.as_str()),
                    None => serializer.serialize_none(),
                }
            }

            pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Level>, D::Error>
            where
                D: Deserializer<'de>,
            {
                let opt = Option::<String>::deserialize(deserializer)?;
                match opt {
                    Some(s) => s
                        .parse::<Level>()
                        .map(Some)
                        .map_err(serde::de::Error::custom),
                    None => Ok(None),
                }
            }
        }
    }

    pub mod duration {
        use std::time::Duration;

        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&humantime::format_duration(*duration).to_string())
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            humantime::parse_duration(&s).map_err(serde::de::Error::custom)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use clap::Parser;
    use figment::Jail;
    use tracing::Level;

    use super::Conf;
    use crate::runtime::cli::Cli;

    #[test]
    fn default_impl_has_eth0_interface() {
        let cfg = Conf::default();
        assert_eq!(cfg.interface, Vec::from(["eth0".to_string()]));
        assert_eq!(cfg.config_path, None);
        assert_eq!(cfg.auto_reload, false);
        assert_eq!(cfg.log_level, Level::INFO);
        assert_eq!(cfg.api.port, 8080);
        assert_eq!(cfg.packet_channel_capacity, 1024);
        assert_eq!(cfg.packet_worker_count, 2);
        assert_eq!(cfg.shutdown_timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_conf_serialization() {
        let cfg = Conf::default();

        // Test that it can be serialized and deserialized
        let serialized = serde_yaml::to_string(&cfg).expect("should serialize");
        let deserialized: Conf = serde_yaml::from_str(&serialized).expect("should deserialize");

        assert_eq!(
            cfg.packet_channel_capacity,
            deserialized.packet_channel_capacity
        );
        assert_eq!(cfg.packet_worker_count, deserialized.packet_worker_count);
    }

    #[test]
    fn new_succeeds_without_config_path() {
        Jail::expect_with(|_| {
            let cli = Cli::parse_from(["mermin"]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load without path");
            assert_eq!(cfg.config_path, None);

            Ok(())
        })
    }

    #[test]
    fn new_errors_with_nonexistent_config_file() {
        Jail::expect_with(|_| {
            let cli = Cli::parse_from(["mermin", "--config", "nonexistent.yaml"]);
            let err = Conf::new(cli).expect_err("expected error with nonexistent file");
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
            let err = Conf::new(cli).expect_err("expected error with directory path");
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
            let err = Conf::new(cli).expect_err("expected error with invalid extension");
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
            let (cfg, _cli) = Conf::new(cli).expect("config loads from cli file");
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
            let (cfg, _cli) = Conf::new(cli).expect("config loads from env file");
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
            let (cfg, _cli) = Conf::new(cli).expect("config loads from cli file");
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
        let cfg = Conf::default();
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

    #[test]
    fn loads_api_and_metrics_config_from_yaml_file() {
        Jail::expect_with(|jail| {
            let path = "mermin_custom_api.yaml";

            jail.create_file(
                path,
                r#"
# Custom configuration for testing
interface:
  - eth1

api:
  listen_address: "127.0.0.1"
  port: 8081

metrics:
  listen_address: "0.0.0.0"
  port: 9090
                "#,
            )?;

            // The rest of the test logic remains the same
            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load from yaml file");

            // Assert that all the custom values from the file were loaded correctly
            assert_eq!(cfg.interface, Vec::from(["eth1".to_string()]));
            assert_eq!(cfg.api.listen_address, "127.0.0.1");
            assert_eq!(cfg.api.port, 8081);
            assert_eq!(cfg.metrics.listen_address, "0.0.0.0");
            assert_eq!(cfg.metrics.port, 9090);

            Ok(())
        });
    }
}
