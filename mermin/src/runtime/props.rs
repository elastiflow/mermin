use std::{
    collections::HashMap,
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
    otlp::opts::{OtlpExporterOptions, StdoutExporterOptions},
    runtime::{
        cli::Cli,
        conf,
        conf::{
            ApiConf, Conf, ConfError, Hcl, MetricsConf, TracePipeline,
            conf_serde::{duration, level},
            defaults, validate_config_path,
        },
        enums::SpanFmt,
    },
    span::opts::SpanOptions,
};

/// Represents the configuration for the application, containing settings
/// related to interface, logging, reloading, and flow management.
///
/// This struct is serializable and deserializable using Serde, allowing
/// it to be easily read from or written to configuration files in
/// formats like YAML.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Properties {
    /// A vector of strings representing the network interfaces or endpoints
    /// that the application should operate on. These interfaces are read
    /// directly from the configuration file.
    pub interface: Vec<String>,

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

    /// A map of fully resolved and ready-to-use trace pipelines.
    pub trace_pipelines: HashMap<String, TracePipeline>,

    /// An optional `PathBuf` field that represents the file path to the
    /// configuration file. This field is annotated with `#[serde(skip)]`,
    /// meaning its value will not be serialized or deserialized. It is
    /// used internally for managing the configuration's source path.
    #[serde(skip)]
    #[allow(dead_code)]
    pub(crate) config_path: Option<PathBuf>,
}

impl Properties {
    /// Merges a configuration file into a Figment instance, automatically
    /// selecting the correct provider based on the file extension.
    fn merge_provider_for_path(figment: Figment, path: &Path) -> Result<Figment, ConfError> {
        match path.extension().and_then(|s| s.to_str()) {
            Some("yaml") | Some("yml") => Ok(figment.merge(Yaml::file(path))),
            Some("hcl") => Ok(figment.merge(Hcl::file(path))),
            Some(ext) => Err(ConfError::InvalidExtension(ext.to_string())),
            None => Err(ConfError::InvalidExtension("none".to_string())),
        }
    }

    pub(crate) fn resolve_trace_pipelines(
        conf: &Conf,
    ) -> Result<HashMap<String, TracePipeline>, ConfError> {
        let mut trace_pipelines = HashMap::new();

        if let Some(agent) = &conf.agent {
            for (name, trace_opts) in agent.traces.clone() {
                let resolved_pipeline = TracePipeline::from_raw(&name, trace_opts, conf)?;
                trace_pipelines.insert(name, resolved_pipeline);
            }
        }

        Ok(trace_pipelines)
    }

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
    pub fn new(cli: Cli) -> Result<(Self, Cli), ConfError> {
        let mut figment = Figment::new().merge(Serialized::defaults(Conf::default()));

        let config_path_to_store = if let Some(config_path) = &cli.config {
            validate_config_path(config_path)?;
            figment = Self::merge_provider_for_path(figment, config_path)?;
            Some(config_path.clone())
        } else {
            None
        };

        figment = figment.merge(Serialized::defaults(&cli));

        let raw_conf: Conf = figment.extract()?;

        let trace_pipelines = Self::resolve_trace_pipelines(&raw_conf)?;

        let conf = Self {
            interface: raw_conf.interface,
            auto_reload: raw_conf.auto_reload,
            log_level: raw_conf.log_level,
            api: raw_conf.api,
            metrics: raw_conf.metrics,
            packet_channel_capacity: raw_conf.packet_channel_capacity,
            packet_worker_count: raw_conf.packet_worker_count,
            shutdown_timeout: raw_conf.shutdown_timeout,
            span: raw_conf.span,
            trace_pipelines,
            config_path: config_path_to_store,
        };

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
    pub fn reload(&self) -> Result<Self, ConfError> {
        let path = self.config_path.as_ref().ok_or(ConfError::NoConfigFile)?;

        // Create a new Figment instance, using the current resolved config
        // as the base. This preserves CLI/env vars. Then merge the file on top.
        let mut figment = Figment::from(Serialized::defaults(&self));
        figment = Self::merge_provider_for_path(figment, path)?;

        let raw_conf: Conf = figment.extract()?;

        let trace_pipelines = Self::resolve_trace_pipelines(&raw_conf)?;

        Ok(Self {
            interface: raw_conf.interface,
            auto_reload: raw_conf.auto_reload,
            log_level: raw_conf.log_level,
            api: raw_conf.api,
            metrics: raw_conf.metrics,
            packet_channel_capacity: raw_conf.packet_channel_capacity,
            packet_worker_count: raw_conf.packet_worker_count,
            shutdown_timeout: raw_conf.shutdown_timeout,
            span: raw_conf.span,
            trace_pipelines,
            config_path: self.config_path.clone(),
        })
    }

    pub fn get_trace_pipeline_span_level(&self) -> SpanFmt {
        let mut span_lvl = SpanFmt::default();
        for pipeline in self.trace_pipelines.values() {
            span_lvl = pipeline.span_level;
        }
        span_lvl
    }

    pub fn get_trace_pipeline_exporters(
        &self,
    ) -> (Vec<OtlpExporterOptions>, Vec<StdoutExporterOptions>) {
        let mut otlp_exporters = Vec::new();
        let mut stdout_exporters = Vec::new();

        for pipeline in self.trace_pipelines.values() {
            for exporter in &pipeline.exporters {
                match exporter {
                    conf::ExportOption::Otlp(opts) => otlp_exporters.push(opts.clone()),
                    conf::ExportOption::Stdout(opts) => stdout_exporters.push(opts.clone()),
                }
            }
        }

        (otlp_exporters, stdout_exporters)
    }
}
