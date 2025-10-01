use std::{
    collections::HashMap,
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
use hcl::eval::Context;
use serde::{Deserialize, Serialize};
use tracing::Level;

use crate::{
    otlp::opts::{ExporterOptions, OtlpExporterOptions, StdoutExporterOptions},
    runtime::{
        cli::Cli,
        conf::conf_serde::{duration, level},
        enums::SpanFmt,
    },
    span::opts::SpanOptions,
};

pub struct Hcl;

impl Format for Hcl {
    type Error = hcl::Error;

    // Constant to name the format in error messages.
    const NAME: &'static str = "HCL";

    fn from_str<T: serde::de::DeserializeOwned>(string: &str) -> Result<T, Self::Error> {
        hcl::eval::from_str(string, &Context::new())
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

/// Represents a single, fully resolved trace pipeline with its discovery
/// and exporter configurations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedTracePipeline {
    pub span_level: SpanFmt,
    pub exporters: Vec<ResolvedExporter>,
}

/// An enum representing a specific, resolved exporter configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResolvedExporter {
    Otlp(OtlpExporterOptions),
    Stdout(StdoutExporterOptions),
}

impl ResolvedTracePipeline {
    /// Resolves a single trace pipeline from the raw configuration.
    fn from_raw(
        pipeline_name: &str,
        raw_opts: RawTraceOptions,
        raw_conf: &Conf,
    ) -> Result<Self, ConfigError> {
        // Resolve Exporters
        let mut exporters = Vec::new();
        let parsed_refs = raw_opts.exporters.parse().unwrap();
        for exporter_ref in parsed_refs {
            match exporter_ref.type_.as_str() {
                "otlp" => {
                    let opts = raw_conf
                        .exporter
                        .as_ref()
                        .and_then(|e| e.otlp.as_ref())
                        .and_then(|otlp_map| otlp_map.get(&exporter_ref.name))
                        .cloned()
                        .ok_or_else(|| {
                            ConfigError::InvalidReference(format!(
                                "OTLP exporter '{}' not found for pipeline '{}'",
                                exporter_ref.name, pipeline_name
                            ))
                        })?;
                    exporters.push(ResolvedExporter::Otlp(opts));
                }
                "stdout" => {
                    let opts = raw_conf
                        .exporter
                        .as_ref()
                        .and_then(|e| e.stdout.as_ref())
                        .and_then(|stdout_map| stdout_map.get(&exporter_ref.name))
                        .cloned()
                        .ok_or_else(|| {
                            ConfigError::InvalidReference(format!(
                                "Stdout exporter '{}' not found for pipeline '{}'",
                                exporter_ref.name, pipeline_name
                            ))
                        })?;
                    exporters.push(ResolvedExporter::Stdout(opts));
                }
                _ => { /* Already handled by .parse() */ }
            }
        }

        Ok(Self {
            span_level: raw_opts.span_level,
            exporters,
        })
    }
}

/// Represents the configuration for the application, containing settings
/// related to interface, logging, reloading, and flow management.
///
/// This struct is serializable and deserializable using Serde, allowing
/// it to be easily read from or written to configuration files in
/// formats like YAML.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AppProps {
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
    pub trace_pipelines: HashMap<String, ResolvedTracePipeline>,

    /// An optional `PathBuf` field that represents the file path to the
    /// configuration file. This field is annotated with `#[serde(skip)]`,
    /// meaning its value will not be serialized or deserialized. It is
    /// used internally for managing the configuration's source path.
    #[serde(skip)]
    #[allow(dead_code)]
    config_path: Option<PathBuf>,
}

impl AppProps {
    /// Merges a configuration file into a Figment instance, automatically
    /// selecting the correct provider based on the file extension.
    fn merge_provider_for_path(figment: Figment, path: &Path) -> Result<Figment, ConfigError> {
        match path.extension().and_then(|s| s.to_str()) {
            Some("yaml") | Some("yml") => Ok(figment.merge(Yaml::file(path))),
            Some("hcl") => Ok(figment.merge(Hcl::file(path))),
            Some(ext) => Err(ConfigError::InvalidExtension(ext.to_string())),
            None => Err(ConfigError::InvalidExtension("none".to_string())),
        }
    }

    fn resolve_trace_pipelines(
        raw_conf: &Conf,
    ) -> Result<HashMap<String, ResolvedTracePipeline>, ConfigError> {
        let mut trace_pipelines = HashMap::new();

        if let Some(agent) = &raw_conf.agent {
            for (name, trace_opts) in agent.traces.clone() {
                let resolved_pipeline =
                    ResolvedTracePipeline::from_raw(&name, trace_opts, raw_conf)?;
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
    pub fn new(cli: Cli) -> Result<(Self, Cli), ConfigError> {
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
    pub fn reload(&self) -> Result<Self, ConfigError> {
        let path = self.config_path.as_ref().ok_or(ConfigError::NoConfigFile)?;

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
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
struct Conf {
    interface: Vec<String>,
    auto_reload: bool,
    #[serde(with = "level")]
    log_level: Level,
    api: ApiConf,
    metrics: MetricsConf,
    packet_channel_capacity: usize,
    packet_worker_count: usize,
    #[serde(with = "duration")]
    shutdown_timeout: Duration,
    span: SpanOptions,
    agent: Option<RawAgentOptions>,
    exporter: Option<ExporterOptions>,
}

impl Default for Conf {
    fn default() -> Self {
        Self {
            interface: vec!["eth0".to_string()],
            auto_reload: false,
            log_level: Level::INFO,
            api: ApiConf::default(),
            metrics: MetricsConf::default(),
            packet_channel_capacity: defaults::packet_channel_capacity(),
            packet_worker_count: defaults::flow_workers(),
            shutdown_timeout: defaults::shutdown_timeout(),
            span: SpanOptions::default(),
            agent: None,
            exporter: None,
        }
    }
}

/// A generic enum to handle fields that can either be a reference string
/// or an inlined struct.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
#[allow(dead_code)]
enum ReferenceOrInline<T> {
    Reference(String),
    Inline(T),
}

#[derive(Default, Debug, Deserialize, Serialize, Clone)]
struct RawAgentOptions {
    traces: HashMap<String, RawTraceOptions>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
struct RawTraceOptions {
    /// The level of span events to record. The current default is `FmtSpan::FULL`,
    /// which records all events (enter, exit, close) for all spans. The level can also be
    /// one of the following:
    /// - `SpanFmt::Full`: No span events are recorded.
    /// - `FmtSpan::ENTER`: Only span enter events are recorded.
    /// - `FmtSpan::EXIT`: Only span exit events are recorded.
    /// - `FmtSpan::CLOSE`: Only span close events are recorded.
    /// - `FmtSpan::ACTIVE`: Only span events for spans that are active (i.e., not closed) are recorded.
    pub span_level: SpanFmt,

    /// A list of exporter references to use for tracing. Each entry should match a key
    /// in the `exporter` section of the config.
    pub exporters: ExporterReferences,
}

impl Default for RawTraceOptions {
    fn default() -> Self {
        Self {
            span_level: SpanFmt::Full,
            exporters: ExporterReferences::new(),
        }
    }
}

// Default implementations for the ReferenceOrInline types
impl Default for ReferenceOrInline<K8sOwnerOptions> {
    fn default() -> Self {
        Self::Inline(K8sOwnerOptions::default())
    }
}
impl Default for ReferenceOrInline<K8sSelectorOptions> {
    fn default() -> Self {
        Self::Inline(K8sSelectorOptions::default())
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
    /// A reference string (e.g., "exporter.otlp.main") could not be resolved.
    InvalidReference(String),
    /// An error occurred during deserialization or processing.
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
            ConfigError::InvalidReference(r) => write!(f, "invalid configuration reference: {r}"),
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

    pub mod exporter_protocol {
        use serde::{Deserialize, Deserializer, Serializer};

        use crate::otlp::opts::ExporterProtocol;

        pub fn serialize<S>(protocol: &ExporterProtocol, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&protocol.to_string())
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<ExporterProtocol, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            Ok(ExporterProtocol::from(s))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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

/// Top-level agent configuration specifying which telemetry features are enabled.
///
/// The `AgentOptions` struct defines the agent's telemetry pipeline configuration,
/// mapping logical telemetry types (such as traces) to their respective pipeline settings.
/// This allows the user to declaratively specify, in the configuration file, which
/// exporters should be used for each telemetry type. For example, the `traces` field
/// contains the configuration for the traces pipeline, including the list of exporter
/// references (such as OTLP or stdout exporters) that should be enabled for sending trace data.
///
/// This struct is typically deserialized from the `agent` section of the application's
/// configuration file. Exporter references listed here must correspond to exporter
/// definitions in the `exporter` section of the configuration.
///
/// # Example (YAML)
/// ```yaml
/// agent:
///   traces:
///     main:
///       exporters:
///         - exporter.otlp.main
///         - exporter.stdout.json
///
/// ```
#[derive(Default, Debug, Deserialize, Serialize, Clone)]
pub struct AgentOptions {
    /// Mapping of trace names to trace options.
    /// Example: "main" -> TraceOptions
    pub traces: HashMap<String, TraceOptions>,
}

/// Options for a specific trace configuration.
/// References specific configs by name from config file
#[derive(Default, Debug, Deserialize, Serialize, Clone)]
pub struct TraceOptions {
    /// Reference to a discovery.k8s_owner config.
    pub discovery_owner: String,
    /// Reference to a discovery.k8s_selector config.
    pub discovery_selector: String,
    /// List of exporter references to use for the trace pipeline.
    pub exporters: ExporterReferences,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
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

pub type ExporterReferences = Vec<String>;

pub trait ExporterReferencesParser {
    fn parse(&self) -> Result<Vec<ExporterReference>, String>;
}

impl ExporterReferencesParser for ExporterReferences {
    fn parse(&self) -> Result<Vec<ExporterReference>, String> {
        self.iter().map(|reference| {
            match reference.split('.').collect::<Vec<_>>().as_slice() {
                ["exporter", type_ @ ("otlp" | "stdout"), name] => Ok(ExporterReference {
                    type_: type_.to_string(),
                    name: name.to_string(),
                }),
                ["exporter", invalid_type, _] => Err(format!(
                    "unsupported exporter type: '{invalid_type}' - supported types: otlp, stdout"
                )),
                _ => Err(format!(
                    "invalid format: '{reference}' - expected: 'exporter.<type>.<name>'"
                )),
            }
        }).collect::<Result<Vec<ExporterReference>, String>>()
    }
}

/// Represents a parsed exporter reference from the agent configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct ExporterReference {
    pub type_: String,
    pub name: String,
}

/// Options for discovering Kubernetes resource owners.
/// Controls which resource kinds to include/exclude and the search depth.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct K8sOwnerOptions {
    /// Kinds to exclude from owner discovery (e.g., EndpointSlice).
    pub exclude_kinds: Vec<String>,
    /// Kinds to include in owner discovery (e.g., Service).
    pub include_kinds: Vec<String>,
    /// Maximum depth to traverse owner references.
    pub max_depth: u32,
}

impl Default for K8sOwnerOptions {
    fn default() -> Self {
        Self {
            exclude_kinds: Vec::new(),
            include_kinds: Vec::new(),
            max_depth: 10,
        }
    }
}

/// Options for Kubernetes resource selectors.
/// Defines which objects to match for enrichment.
#[derive(Default, Debug, Deserialize, Serialize, Clone)]
pub struct K8sSelectorOptions {
    /// List of object selectors for matching resources.
    pub k8s_object: Vec<K8sObjectSelector>,
}

/// Selector for a specific Kubernetes object kind.
/// Used to match and enrich resources based on label/field selectors.
#[derive(Default, Debug, Deserialize, Serialize, Clone)]
pub struct K8sObjectSelector {
    /// The kind of Kubernetes object (e.g., NetworkPolicy, Service).
    pub kind: String,
    /// Optional field for matchExpressions (e.g., spec.podSelector.matchExpressions).
    pub selector_match_expressions_field: Option<String>,
    /// Optional field for matchLabels (e.g., spec.podSelector.matchLabels).
    pub selector_match_labels_field: Option<String>,
    /// Target resource kind to associate with (e.g., Pod).
    pub to: String,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use clap::Parser;
    use figment::Jail;
    use tracing::Level;

    use super::{AppProps, Conf, ExporterReference};
    use crate::runtime::cli::Cli;

    fn parse_exporter_reference(reference: &str) -> Result<ExporterReference, String> {
        match reference.split('.').collect::<Vec<_>>().as_slice() {
            ["exporter", type_ @ ("otlp" | "stdout"), name] => Ok(ExporterReference {
                type_: type_.to_string(),
                name: name.to_string(),
            }),
            ["exporter", invalid_type, _] => Err(format!(
                "unsupported exporter type: '{invalid_type}' - supported types: otlp, stdout"
            )),
            _ => Err(format!(
                "invalid format: '{reference}' - expected: 'exporter.<type>.<name>'"
            )),
        }
    }

    fn create_default_app_props() -> AppProps {
        let raw_conf = Conf::default();
        let trace_pipelines = AppProps::resolve_trace_pipelines(&raw_conf)
            .expect("resolving default pipelines should succeed");
        AppProps {
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
            config_path: None,
        }
    }

    #[test]
    fn default_impl_has_eth0_interface() {
        let cfg = create_default_app_props();
        assert_eq!(cfg.interface, Vec::from(["eth0".to_string()]));
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
            let (cfg, _cli) = AppProps::new(cli).expect("config should load without path");
            assert_eq!(cfg.config_path, None);

            Ok(())
        })
    }

    #[test]
    fn new_errors_with_nonexistent_config_file() {
        Jail::expect_with(|_| {
            let cli = Cli::parse_from(["mermin", "--config", "nonexistent.yaml"]);
            let err = AppProps::new(cli).expect_err("expected error with nonexistent file");
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
            let err = AppProps::new(cli).expect_err("expected error with directory path");
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
            let err = AppProps::new(cli).expect_err("expected error with invalid extension");
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
            let (cfg, _cli) = AppProps::new(cli).expect("config loads from cli file");
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
            let (cfg, _cli) = AppProps::new(cli).expect("config loads from env file");
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
            let (cfg, _cli) = AppProps::new(cli).expect("config loads from cli file");
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
        let cfg = create_default_app_props();
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
            let (cfg, _cli) = AppProps::new(cli).expect("config should load from yaml file");

            // Assert that all the custom values from the file were loaded correctly
            assert_eq!(cfg.interface, Vec::from(["eth1".to_string()]));
            assert_eq!(cfg.api.listen_address, "127.0.0.1");
            assert_eq!(cfg.api.port, 8081);
            assert_eq!(cfg.metrics.listen_address, "0.0.0.0");
            assert_eq!(cfg.metrics.port, 9090);

            Ok(())
        });
    }

    #[test]
    fn loads_from_hcl_file() {
        Jail::expect_with(|jail| {
            let path = "mermin.hcl";
            jail.create_file(
                path,
                r#"
interface = ["eth0"]
log_level = "info"
auto_reload = true

api {
    enabled = true
    port = 9090
}

metrics {
    enabled = true
    port = 10250
}
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = AppProps::new(cli).expect("config should load from HCL file");

            assert_eq!(cfg.interface, vec!["eth0"]);
            assert_eq!(cfg.log_level, Level::INFO);
            assert_eq!(cfg.auto_reload, true);
            assert_eq!(cfg.api.port, 9090);
            assert_eq!(cfg.metrics.port, 10250);

            Ok(())
        });
    }

    #[test]
    fn validates_hcl_extension() {
        Jail::expect_with(|jail| {
            let path = "mermin.hcl";
            jail.create_file(path, r#"interface = ["eth0"]"#)?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let result = AppProps::new(cli);
            assert!(result.is_ok(), "HCL extension should be valid");

            Ok(())
        });
    }

    #[test]
    fn reload_updates_config_from_hcl_file() {
        Jail::expect_with(|jail| {
            let path = "mermin_reload.hcl";
            jail.create_file(
                path,
                r#"
interface = ["eth1"]
log_level = "info"
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = AppProps::new(cli).expect("config loads from HCL file");
            assert_eq!(cfg.interface, Vec::from(["eth1".to_string()]));
            assert_eq!(cfg.log_level, Level::INFO);
            assert_eq!(cfg.config_path, Some(path.parse().unwrap()));

            // Update the HCL config file
            jail.create_file(
                path,
                r#"
interface = ["eth2", "eth3"]
log_level = "debug"
                "#,
            )?;

            let reloaded_cfg = cfg.reload().expect("config should reload from HCL");
            assert_eq!(
                reloaded_cfg.interface,
                Vec::from(["eth2".to_string(), "eth3".to_string()])
            );
            assert_eq!(reloaded_cfg.log_level, Level::DEBUG);
            assert_eq!(reloaded_cfg.config_path, Some(path.parse().unwrap()));

            Ok(())
        })
    }

    // MODIFICATION: Corrected the assertion to match the actual error flow.
    #[test]
    fn hcl_parse_error_handling() {
        Jail::expect_with(|jail| {
            let path = "invalid.hcl";
            jail.create_file(
                path,
                r#"
# Invalid HCL syntax
interface = [eth0  # Missing closing bracket and quotes
log_level =
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let err = AppProps::new(cli).expect_err("expected error with invalid HCL");
            let msg = err.to_string();

            // The error originates from the `hcl` crate, is wrapped by `figment`,
            // and finally converted into our `ConfigError::Extraction`. The assertion
            // should reflect this error chain. We check for "configuration error" from our
            // Display impl and a piece of the underlying HCL error message.
            assert!(
                msg.contains("configuration error:")
                    && (msg.contains("expected") || msg.contains("unexpected")),
                "unexpected error: {}",
                msg
            );

            Ok(())
        });
    }

    #[test]
    fn loads_api_and_metrics_config_from_hcl_file() {
        Jail::expect_with(|jail| {
            let path = "mermin_custom_api.hcl";

            jail.create_file(
                path,
                r#"
# Custom configuration for testing
interface = ["eth1"]

api {
    listen_address = "127.0.0.1"
    port = 8081
}

metrics {
    listen_address = "0.0.0.0"
    port = 9090
}
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = AppProps::new(cli).expect("config should load from HCL file");

            // Assert that all the custom values from the file were loaded correctly
            assert_eq!(cfg.interface, Vec::from(["eth1".to_string()]));
            assert_eq!(cfg.api.listen_address, "127.0.0.1");
            assert_eq!(cfg.api.port, 8081);
            assert_eq!(cfg.metrics.listen_address, "0.0.0.0");
            assert_eq!(cfg.metrics.port, 9090);

            Ok(())
        });
    }

    #[test]
    fn test_parse_exporter_reference_valid() {
        let result = parse_exporter_reference("exporter.otlp.main").unwrap();
        assert_eq!(result.type_, "otlp");
        assert_eq!(result.name, "main");

        let result = parse_exporter_reference("exporter.stdout.json").unwrap();
        assert_eq!(result.type_, "stdout");
        assert_eq!(result.name, "json");
    }

    #[test]
    fn test_parse_exporter_reference_invalid_format() {
        let result = parse_exporter_reference("invalid.format");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid format"));

        let result = parse_exporter_reference("exporter.otlp");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid format"));

        let result = parse_exporter_reference("exporter.otlp.main.extra");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid format"));
    }

    #[test]
    fn test_parse_exporter_reference_invalid_prefix() {
        let result = parse_exporter_reference("invalid.otlp.main");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid format"));
    }

    #[test]
    fn test_parse_exporter_reference_unsupported_type() {
        let result = parse_exporter_reference("exporter.invalid.main");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unsupported exporter type"));
    }
}
