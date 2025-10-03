use std::{collections::HashMap, error::Error, fmt, net::Ipv4Addr, path::Path, time::Duration};

use figment::providers::Format;
use hcl::eval::Context;
use serde::{Deserialize, Serialize};
use tracing::Level;

use crate::{
    otlp::opts::ExporterOptions,
    runtime::{
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct Conf {
    pub interface: Vec<String>,
    pub auto_reload: bool,
    #[serde(with = "level")]
    pub log_level: Level,
    pub api: ApiConf,
    pub metrics: MetricsConf,
    pub packet_channel_capacity: usize,
    pub packet_worker_count: usize,
    #[serde(with = "duration")]
    pub shutdown_timeout: Duration,
    pub span: SpanOptions,
    /// Top-level agent configuration specifying which telemetry features are enabled.
    pub agent: Option<AgentOptions>,
    /// Contains the configuration for internal exporters
    pub traces: Option<TracesConfig>,
    /// References to the exporters to use for telemetry
    pub exporter: ExporterOptions,
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
            traces: Some(TracesConfig::default()),
            exporter: ExporterOptions::default(),
        }
    }
}

pub mod defaults {
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

/// A generic enum to handle fields that can either be a reference string
/// or an inlined struct.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
#[allow(dead_code)]
pub enum ReferenceOrInline<T> {
    Reference(String),
    Inline(T),
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

/// Options for all traces configuration
#[derive(Default, Debug, Deserialize, Serialize, Clone)]
pub struct TracesConfig {
    /// The level of span events to record. The current default is `FmtSpan::FULL`,
    /// which records all events (enter, exit, close) for all spans. The level can also be
    /// one of the following:
    /// - `SpanFmt::Full`: No span events are recorded.
    /// - `FmtSpan::ENTER`: Only span enter events are recorded.
    /// - `FmtSpan::EXIT`: Only span exit events are recorded.
    /// - `FmtSpan::CLOSE`: Only span close events are recorded.
    /// - `FmtSpan::ACTIVE`: Only span events for spans that are active (i.e., not closed) are recorded.
    pub span_level: SpanFmt,

    #[serde(flatten)]
    pub pipelines: HashMap<String, TraceOptions>,
}

/// Options for a specific trace configuration.
/// References specific configs by name from config file
#[derive(Default, Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct TraceOptions {
    /// A list of exporter references to use for tracing. Each entry should match a key
    /// in the `exporter` section of the config.
    pub exporters: ExporterReferences,
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
pub fn validate_config_path(path: &Path) -> Result<(), ConfError> {
    // 1. First, check that the path points to a file. The `is_file()` method
    // conveniently returns false if the path doesn't exist or if it's not a file.
    if !path.is_file() {
        // If it's not a file, distinguish between "doesn't exist" and "is a directory".
        if path.exists() {
            // Path exists but is not a file (it's a directory).
            return Err(ConfError::InvalidConfigPath(
                path.to_string_lossy().into_owned(),
            ));
        } else {
            // Path does not exist at all.
            return Err(ConfError::NoConfigFile);
        }
    }

    // 2. If it's a file, check the extension.
    match path.extension().and_then(|s| s.to_str()) {
        // Allowed extensions
        Some("yaml") | Some("yml") | Some("hcl") => Ok(()),
        // An unsupported extension was found
        Some(ext) => Err(ConfError::InvalidExtension(ext.to_string())),
        // No extension was found
        None => Err(ConfError::InvalidExtension("none".to_string())),
    }
}

#[derive(Debug)]
pub enum ConfError {
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

impl fmt::Display for ConfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfError::NoConfigFile => write!(f, "no config file provided"),
            ConfError::InvalidConfigPath(p) => write!(f, "path '{p}' is not a valid file"),
            ConfError::InvalidExtension(ext) => {
                write!(
                    f,
                    "invalid file extension '.{ext}' — expected 'yaml', 'yml', or 'hcl'"
                )
            }
            ConfError::InvalidReference(r) => write!(f, "invalid configuration reference: {r}"),
            ConfError::Extraction(e) => write!(f, "configuration error: {e}"),
        }
    }
}

impl Error for ConfError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ConfError::Extraction(e) => Some(e),
            _ => None,
        }
    }
}

impl From<figment::Error> for ConfError {
    fn from(e: figment::Error) -> Self {
        ConfError::Extraction(Box::from(e))
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use clap::Parser;
    use figment::Jail;
    use tracing::Level;

    use super::{Conf, ExporterReference};
    use crate::runtime::{
        cli::Cli,
        props::{InternalTraces, Properties},
    };

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

    fn create_default_app_props() -> Properties {
        let raw_conf = Conf::default();
        let trace_pipelines = Properties::resolve_trace_pipelines(&raw_conf)
            .expect("resolving default pipelines should succeed");
        let internal_traces = Properties::resolve_internal_exporters(&raw_conf)
            .expect("resolving default internal traces should succeed");
        Properties {
            interface: raw_conf.interface,
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
                span_level: raw_conf.traces.unwrap().span_level,
                pipelines: internal_traces,
            },
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
            let (cfg, _cli) = Properties::new(cli).expect("config should load without path");
            assert_eq!(cfg.config_path, None);

            Ok(())
        })
    }

    #[test]
    fn new_errors_with_nonexistent_config_file() {
        Jail::expect_with(|_| {
            let cli = Cli::parse_from(["mermin", "--config", "nonexistent.yaml"]);
            let err = Properties::new(cli).expect_err("expected error with nonexistent file");
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
            let err = Properties::new(cli).expect_err("expected error with directory path");
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
            let err = Properties::new(cli).expect_err("expected error with invalid extension");
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
            let (cfg, _cli) = Properties::new(cli).expect("config loads from cli file");
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
            let (cfg, _cli) = Properties::new(cli).expect("config loads from env file");
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
            let (cfg, _cli) = Properties::new(cli).expect("config loads from cli file");
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
            let (cfg, _cli) = Properties::new(cli).expect("config should load from yaml file");

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
            let (cfg, _cli) = Properties::new(cli).expect("config should load from HCL file");

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
            let result = Properties::new(cli);
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
            let (cfg, _cli) = Properties::new(cli).expect("config loads from HCL file");
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
            let err = Properties::new(cli).expect_err("expected error with invalid HCL");
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
            let (cfg, _cli) = Properties::new(cli).expect("config should load from HCL file");

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
