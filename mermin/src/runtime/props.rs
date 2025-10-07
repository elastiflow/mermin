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
    otlp::opts::{ExporterOptions, OtlpExporterOptions, StdoutExporterOptions},
    runtime::{
        cli::Cli,
        conf::{
            ApiConf, Conf, ConfError, ExporterReference, ExporterReferencesParser, Hcl,
            MetricsConf, TraceOptions,
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
    pub interfaces: Vec<String>,

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
    /// agent.traces.<foo>.(exporters, discovery, network)
    pub agent_traces: HashMap<String, TracePipeline>,

    /// Configuration for internal exporters.
    /// This field holds settings for exporting telemetry data
    /// to multiple destinations using the new structure.
    /// traces.<foo>.exporters
    pub internal_traces: InternalTraces,

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

    pub fn resolve_trace_pipelines(
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

    pub fn resolve_internal_exporters(
        conf: &Conf,
    ) -> Result<HashMap<String, InternalExporters>, ConfError> {
        let mut resolved_exporters = HashMap::new();
        dbg!(&conf.exporter);
        if let Some(traces) = &conf.traces {
            for (name, exporter) in traces.pipelines.clone() {
                let internal_exporter = InternalExporters::from_raw(&name, &exporter, conf)?;
                resolved_exporters.insert(name, internal_exporter);
            }
        }

        Ok(resolved_exporters)
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
        let internal_exporters = Self::resolve_internal_exporters(&raw_conf)?;
        let span_level = raw_conf.traces.unwrap().span_level;

        let conf = Self {
            interfaces: raw_conf.interfaces,
            auto_reload: raw_conf.auto_reload,
            log_level: raw_conf.log_level,
            api: raw_conf.api,
            metrics: raw_conf.metrics,
            packet_channel_capacity: raw_conf.packet_channel_capacity,
            packet_worker_count: raw_conf.packet_worker_count,
            shutdown_timeout: raw_conf.shutdown_timeout,
            span: raw_conf.span,
            agent_traces: trace_pipelines,
            internal_traces: InternalTraces {
                pipelines: internal_exporters,
                span_level,
            },
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
        let internal_exporters = Self::resolve_internal_exporters(&raw_conf)?;
        let span_level = raw_conf.traces.unwrap().span_level;

        Ok(Self {
            interfaces: raw_conf.interfaces,
            auto_reload: raw_conf.auto_reload,
            log_level: raw_conf.log_level,
            api: raw_conf.api,
            metrics: raw_conf.metrics,
            packet_channel_capacity: raw_conf.packet_channel_capacity,
            packet_worker_count: raw_conf.packet_worker_count,
            shutdown_timeout: raw_conf.shutdown_timeout,
            span: raw_conf.span,
            agent_traces: trace_pipelines,
            internal_traces: InternalTraces {
                pipelines: internal_exporters,
                span_level,
            },
            config_path: self.config_path.clone(),
        })
    }

    fn extract_exporters_from_pipelines<'a, I, T>(
        pipelines: I,
    ) -> (Vec<OtlpExporterOptions>, Vec<StdoutExporterOptions>)
    where
        I: Iterator<Item = &'a T>,
        T: 'a,
        T: AsRef<[ExportOption]>,
    {
        let mut otlp_exporters = Vec::new();
        let mut stdout_exporters = Vec::new();

        for pipeline in pipelines {
            for exporter in pipeline.as_ref() {
                match exporter {
                    ExportOption::Otlp(opts) => otlp_exporters.push(opts.clone()),
                    ExportOption::Stdout(opts) => stdout_exporters.push(opts.clone()),
                }
            }
        }

        (otlp_exporters, stdout_exporters)
    }

    pub fn get_internal_exporters(&self) -> (Vec<OtlpExporterOptions>, Vec<StdoutExporterOptions>) {
        Self::extract_exporters_from_pipelines(
            self.internal_traces
                .pipelines
                .values()
                .map(|t| &t.exporters),
        )
    }

    pub fn get_agent_exporters(&self) -> (Vec<OtlpExporterOptions>, Vec<StdoutExporterOptions>) {
        Self::extract_exporters_from_pipelines(self.agent_traces.values().map(|p| &p.exporters))
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct InternalTraces {
    #[serde(default)]
    pub span_level: SpanFmt,
    #[serde(flatten)]
    pub pipelines: HashMap<String, InternalExporters>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalExporters {
    pub exporters: Vec<ExportOption>,
}

impl InternalExporters {
    /// Resolves a single trace pipeline from the raw configuration.
    pub fn from_raw(
        pipeline_name: &str,
        trace_opts: &TraceOptions,
        raw_conf: &Conf,
    ) -> Result<Self, ConfError> {
        // Resolve Exporters
        let parsed_refs = trace_opts.exporters.parse().unwrap();
        let exporters = resolve_exporters(parsed_refs, &raw_conf.exporter, pipeline_name)?;

        // Other resolvers to be added here

        Ok(Self { exporters })
    }
}

/// Represents a single, fully resolved trace pipeline with its corresponding configurations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracePipeline {
    pub exporters: Vec<ExportOption>,
}

/// An enum representing a specific, resolved exporter configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportOption {
    Otlp(OtlpExporterOptions),
    Stdout(StdoutExporterOptions),
}

impl TracePipeline {
    /// Resolves a single trace pipeline from the raw configuration.
    pub fn from_raw(
        pipeline_name: &str,
        trace_opts: TraceOptions,
        raw_conf: &Conf,
    ) -> Result<Self, ConfError> {
        // Resolve Exporters
        let parsed_refs = trace_opts.exporters.parse().unwrap();
        let exporters = resolve_exporters(parsed_refs, &raw_conf.exporter, pipeline_name)?;

        // Other resolvers to be added here

        Ok(Self { exporters })
    }
}

fn resolve_exporters(
    refs: Vec<ExporterReference>,
    exporter_opts: &ExporterOptions,
    pipeline_name: &str,
) -> Result<Vec<ExportOption>, ConfError> {
    let mut exporters = Vec::new();
    for exporter_ref in refs {
        match exporter_ref.type_.as_str() {
            "otlp" => {
                let opts = exporter_opts
                    .otlp
                    .as_ref()
                    .and_then(|otlp_map| otlp_map.get(&exporter_ref.name))
                    .cloned()
                    .ok_or_else(|| {
                        ConfError::InvalidReference(format!(
                            "OTLP exporter '{}' not found for pipeline '{}'",
                            exporter_ref.name, pipeline_name
                        ))
                    })?;
                exporters.push(ExportOption::Otlp(opts));
            }
            "stdout" => {
                let opts = exporter_opts
                    .stdout
                    .as_ref()
                    .and_then(|stdout_map| stdout_map.get(&exporter_ref.name))
                    .cloned()
                    .ok_or_else(|| {
                        ConfError::InvalidReference(format!(
                            "Stdout exporter '{}' not found for pipeline '{}'",
                            exporter_ref.name, pipeline_name
                        ))
                    })?;
                exporters.push(ExportOption::Stdout(opts));
            }
            _ => { /* Already handled by .parse() */ }
        }
    }

    Ok(exporters)
}
