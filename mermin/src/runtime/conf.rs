use std::{collections::HashMap, error::Error, fmt, mem::size_of, path::Path, time::Duration};

use figment::providers::Format;
use hcl::{
    Value,
    eval::{Context, FuncArgs, FuncDef, ParamType},
};
use mermin_common::{FlowEvent, FlowStats};
use serde::{Deserialize, Serialize};
use tracing::{Level, debug, info, warn};

use crate::{
    filter::opts::FilteringOptions,
    k8s::{
        attributor::{AttributesOptions, default_attributes},
        opts::K8sInformerOptions,
    },
    otlp::opts::ExportOptions,
    runtime::{
        conf::conf_serde::{duration, level},
        opts::InternalOptions,
    },
    span::{flow::FlowSpan, opts::SpanOptions},
};

/// TCX ordering strategy for kernel >= 6.6
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TcxOrderStrategy {
    /// Attach at the tail of the TCX chain (runs after all existing programs)
    /// Recommended for observability tools - runs after Cilium/CNI programs
    Last,
    /// Attach at the head of the TCX chain (runs before all existing programs)
    /// Use with caution - may interfere with CNI functionality
    First,
}

impl Default for TcxOrderStrategy {
    fn default() -> Self {
        Self::First
    }
}

impl fmt::Display for TcxOrderStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Last => write!(f, "last"),
            Self::First => write!(f, "first"),
        }
    }
}

pub struct Hcl;

fn env_func(args: FuncArgs) -> Result<Value, String> {
    if !(1..=2).contains(&args.len()) {
        return Err(format!(
            "env function expects 1 or 2 arguments, but received {}",
            args.len()
        ));
    }

    let var_name = args[0].as_str().unwrap();
    let default_value = if let Some(default_arg) = args.get(1) {
        default_arg.as_str().unwrap().to_string()
    } else {
        String::new()
    };

    match std::env::var(var_name) {
        Ok(value) => {
            debug!(event.name = "hcl.func.env.call", variable.name = %var_name);
            Ok(Value::String(value))
        }
        Err(_) => {
            if args.len() == 2 {
                warn!(
                    event.name = "hcl.func.env.fallback",
                    variable.name = %var_name,
                    fallback.reason = "environment_variable_not_set",
                    fallback.value = %default_value,
                    "environment variable not found, using provided default value"
                );
            } else {
                warn!(
                    event.name = "hcl.func.env.fallback",
                    variable.name = %var_name,
                    fallback.reason = "environment_variable_not_set",
                    fallback.value = "",
                    "environment variable not found, using empty string as default"
                );
            }
            Ok(Value::String(default_value))
        }
    }
}

impl Format for Hcl {
    type Error = hcl::Error;

    // Constant to name the format in error messages.
    const NAME: &'static str = "HCL";

    fn from_str<T: serde::de::DeserializeOwned>(string: &str) -> Result<T, Self::Error> {
        let mut context = Context::new();

        let env_def = FuncDef::builder()
            .variadic_param(ParamType::String)
            .build(env_func);

        context.declare_func("env", env_def);

        hcl::eval::from_str(string, &context)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct Conf {
    /// Path to the configuration file that was loaded
    ///
    /// This field is not serialized and must be regenerated when loading configuration.
    #[serde(skip)]
    pub config_path: Option<std::path::PathBuf>,
    #[serde(with = "level")]
    pub log_level: Level,
    pub log_color: bool,
    pub auto_reload: bool,
    #[serde(with = "duration")]
    pub shutdown_timeout: Duration,
    /// Contains the configuration for internal exporters (traces, metrics, server)
    pub internal: InternalOptions,
    /// Pipeline tuning configuration
    pub pipeline: PipelineOptions,
    /// Parser configuration for eBPF packet parsing
    pub parser: ParserConf,
    /// Span configuration for flow span producer
    pub span: SpanOptions,
    /// Discovery configuration for network monitoring
    pub discovery: DiscoveryConf,
    /// References to the exporters to use for telemetry
    pub export: ExportOptions,
    /// Configuration for flow interfaces.
    /// This field holds settings for filtering.
    pub filter: Option<HashMap<String, FilteringOptions>>,
    /// Configuration for flow-to-object association.
    ///
    /// By default, this is populated with rules to enable Kubernetes-aware
    /// attribution for pods, services, and nodes for both "source" and
    /// "destination" flows.
    ///
    /// This behavior can be disabled or customized by defining an `attributes`
    /// block in the HCL configuration file. An empty `attributes {}` block
    /// will disable the feature entirely.
    #[serde(default)]
    pub attributes: Option<HashMap<String, HashMap<String, AttributesOptions>>>,
}

impl Default for Conf {
    fn default() -> Self {
        Self {
            config_path: None,
            log_level: Level::INFO,
            log_color: false,
            auto_reload: false,
            shutdown_timeout: defaults::shutdown_timeout(),
            internal: InternalOptions::default(),
            parser: ParserConf::default(),
            span: SpanOptions::default(),
            discovery: DiscoveryConf::default(),
            export: ExportOptions::default(),
            pipeline: PipelineOptions::default(),
            filter: None,
            attributes: None,
        }
    }
}

impl Conf {
    /// Creates a new `Conf` instance based on the provided CLI arguments, environment variables,
    /// and configuration file. The configuration is determined using the following priority order:
    /// Defaults < Configuration File < Environment Variables < CLI Arguments.
    ///
    /// # Arguments
    /// - `cli` - An instance of `Cli` containing parsed CLI arguments.
    ///
    /// # Returns
    /// - `Result<(Self, Cli), ConfigError>` - Returns an `Ok((Conf, Cli))` if successful, or a `ConfigError`
    ///   if there are issues during configuration extraction.
    ///
    /// # Errors
    /// - `ConfigError::NoConfigFile` - Returned if no configuration file is specified or found.
    /// - `ConfigError::InvalidConfigPath` - Returned if the `config_path` from the environment
    ///   variable cannot be converted to a valid string.
    /// - Other `ConfigError` variants - Errors propagated during the extraction of the configuration.
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
    pub fn new(
        cli: crate::runtime::cli::Cli,
    ) -> Result<(Self, crate::runtime::cli::Cli), ConfError> {
        use figment::{Figment, providers::Serialized};

        let mut figment = Figment::new().merge(Serialized::defaults(Conf::default()));

        let config_path_to_store = if let Some(config_path) = &cli.config {
            validate_config_path(config_path)?;
            figment = Self::merge_provider_for_path(figment, config_path)?;
            Some(config_path.clone())
        } else {
            None
        };

        figment = figment.merge(Serialized::defaults(&cli));

        let mut conf: Conf = figment.extract()?;
        conf.attributes = match conf.attributes {
            None => Some(default_attributes()),
            Some(map) if map.is_empty() => None,
            Some(mut user_map) => {
                let defaults = default_attributes();

                for (direction, default_inner_map) in defaults {
                    user_map.entry(direction).or_insert(default_inner_map);
                }
                Some(user_map)
            }
        };
        conf.config_path = config_path_to_store;

        // Validate discovery.instrument configuration
        conf.discovery
            .instrument
            .validate()
            .map_err(|e| ConfError::InvalidConfiguration(format!("discovery.instrument: {e}")))?;

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
    #[allow(dead_code)]
    pub fn reload(&self) -> Result<Self, ConfError> {
        use figment::{Figment, providers::Serialized};

        let path = self.config_path.as_ref().ok_or(ConfError::NoConfigFile)?;

        // Create a new Figment instance, using the current resolved config
        // as the base. This preserves CLI/env vars. Then merge the file on top.
        let mut figment = Figment::from(Serialized::defaults(&self));
        figment = Self::merge_provider_for_path(figment, path)?;

        let mut conf: Conf = figment.extract()?;
        conf.attributes = match conf.attributes {
            None => Some(default_attributes()),
            Some(map) if map.is_empty() => None,
            Some(map) => Some(map),
        };
        conf.config_path = self.config_path.clone();

        // Validate discovery.instrument configuration
        conf.discovery
            .instrument
            .validate()
            .map_err(|e| ConfError::InvalidConfiguration(format!("discovery.instrument: {e}")))?;

        Ok(conf)
    }

    /// Merges a configuration file into a Figment instance, automatically
    /// selecting the correct provider based on the file extension.
    fn merge_provider_for_path(
        figment: figment::Figment,
        path: &Path,
    ) -> Result<figment::Figment, ConfError> {
        match path.extension().and_then(|s| s.to_str()) {
            Some("yaml") | Some("yml") => Ok(figment.merge(figment::providers::Yaml::file(path))),
            Some("hcl") => Ok(figment.merge(Hcl::file(path))),
            Some(ext) => Err(ConfError::InvalidExtension(ext.to_string())),
            None => Err(ConfError::InvalidExtension("none".to_string())),
        }
    }

    /// Display all configuration at debug level using structured logging.
    pub fn display_conf(&self) {
        debug!(
            event.name = "config.loaded",
            config.path = ?self.config_path,
            log.level = ?self.log_level,
            log.color = self.log_color,
            auto.reload = self.auto_reload,
            shutdown.timeout.secs = self.shutdown_timeout.as_secs(),
            "configuration loaded"
        );

        // Filter configuration
        if let Some(ref filters) = self.filter {
            for (filter_name, filter_opts) in filters {
                debug!(
                    event.name = "config.filter.loaded",
                    filter.name = %filter_name,
                    "filter configuration loaded"
                );

                if let Some(ref address) = filter_opts.address
                    && (!address.match_list.is_empty() || !address.not_match_list.is_empty())
                {
                    debug!(
                        event.name = "config.filter.address",
                        filter.name = %filter_name,
                        match = ?address.match_list,
                        not_match = ?address.not_match_list,
                        "address filter configuration"
                    );
                }

                if let Some(ref port) = filter_opts.port
                    && (!port.match_list.is_empty() || !port.not_match_list.is_empty())
                {
                    debug!(
                        event.name = "config.filter.port",
                        filter.name = %filter_name,
                        match = ?port.match_list,
                        not_match = ?port.not_match_list,
                        "port filter configuration"
                    );
                }

                if let Some(ref transport) = filter_opts.transport
                    && (!transport.match_list.is_empty() || !transport.not_match_list.is_empty())
                {
                    debug!(
                        event.name = "config.filter.transport",
                        filter.name = %filter_name,
                        match = ?transport.match_list,
                        not_match = ?transport.not_match_list,
                        "transport filter configuration"
                    );
                }

                if let Some(ref type_) = filter_opts.type_
                    && (!type_.match_list.is_empty() || !type_.not_match_list.is_empty())
                {
                    debug!(
                        event.name = "config.filter.type",
                        filter.name = %filter_name,
                        match = ?type_.match_list,
                        not_match = ?type_.not_match_list,
                        "type filter configuration"
                    );
                }

                if let Some(ref interface_name) = filter_opts.interface_name
                    && (!interface_name.match_list.is_empty()
                        || !interface_name.not_match_list.is_empty())
                {
                    debug!(
                        event.name = "config.filter.interface_name",
                        filter.name = %filter_name,
                        match = ?interface_name.match_list,
                        not_match = ?interface_name.not_match_list,
                        "interface_name filter configuration"
                    );
                }
            }
        } else {
            debug!(
                event.name = "config.filter.none",
                "no filter configuration loaded"
            );
        }

        // Discovery configuration
        debug!(
            event.name = "config.discovery",
            interfaces = ?self.discovery.instrument.interfaces,
            auto.discover = self.discovery.instrument.auto_discover_interfaces,
            tc.priority = self.discovery.instrument.tc_priority,
            tcx.order = %self.discovery.instrument.tcx_order,
            "discovery configuration"
        );

        // Parser configuration
        debug!(
            event.name = "config.parser",
            geneve.port = self.parser.geneve_port,
            vxlan.port = self.parser.vxlan_port,
            wireguard.port = self.parser.wireguard_port,
            "parser configuration"
        );

        // Attributes configuration
        if let Some(ref attributes) = self.attributes {
            debug!(
                event.name = "config.attributes",
                attribute.count = attributes.len(),
                "attributes configuration loaded"
            );
        } else {
            debug!(
                event.name = "config.attributes.none",
                "no attributes configuration"
            );
        }
    }
}

/// Parser configuration for eBPF packet parsing options
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct ParserConf {
    /// Port number for Geneve tunnel detection (IANA default: 6081)
    pub geneve_port: u16,
    /// Port number for VXLAN tunnel detection (IANA default: 4789)
    pub vxlan_port: u16,
    /// Port number for WireGuard tunnel detection (IANA default: 51820)
    pub wireguard_port: u16,
}

impl Default for ParserConf {
    fn default() -> Self {
        Self {
            geneve_port: 6081,
            vxlan_port: 4789,
            wireguard_port: 51820,
        }
    }
}

/// Discovery configuration for network monitoring
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct DiscoveryConf {
    /// Instrumentation configuration
    pub instrument: InstrumentOptions,
    /// Informer discovery configuration
    pub informer: Option<InformerDiscoveryOptions>,
}

/// Instrumentation configuration for network interfaces
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct InstrumentOptions {
    /// Network interfaces to monitor
    pub interfaces: Vec<String>,
    /// Automatically discover and attach to new interfaces matching patterns.
    /// Recommended for ephemeral interfaces like veth* (created/destroyed with pods).
    /// Default: true
    pub auto_discover_interfaces: bool,
    /// TC priority for program attachment (netlink only, kernel < 6.6)
    /// Higher values = lower priority = runs later in TC chain
    /// Default: 1 (runs first - consistent with tcx_order=first)
    /// Range: 1-32767 (values < 30 may run before CNI programs)
    pub tc_priority: u16,
    /// TCX ordering strategy (TCX only, kernel >= 6.6)
    /// Controls where mermin attaches in the TCX program chain
    /// Options: "last" (default, runs after all programs), "first" (runs before all programs)
    /// Default: "last" (recommended for observability - runs after Cilium/CNI)
    pub tcx_order: TcxOrderStrategy,
}

impl Default for InstrumentOptions {
    fn default() -> Self {
        Self {
            // Default strategy: complete visibility without flow duplication
            //
            // Approach:
            // 1. Monitor veth* for same-node pod-to-pod traffic (all bridge-based CNIs)
            // 2. Monitor tunnel/overlay interfaces for inter-node traffic
            //    - These don't overlap with veth (separate packet paths)
            //    - Avoids duplication from monitoring physical interfaces (eth*, ens*)
            //
            // Coverage:
            // - Bridge-based CNIs (Flannel host-gw, Calico BGP, kindnetd): veth* captures all
            // - Overlay CNIs (Flannel VXLAN, Calico IPIP): veth* + tunnel interfaces
            // - Cilium: lxc*/cilium_* interfaces with native eBPF integration
            // - Cloud CNIs (GKE, AWS, Azure): provider-specific interfaces
            //
            // Note: Does NOT monitor physical interfaces (eth*, ens*) by default to avoid:
            // - Flow duplication (seeing same packet on veth AND eth)
            // - Missing same-node traffic (never hits physical interface)
            interfaces: vec![
                "veth*".to_string(),    // All bridge-based CNI same-node traffic
                "tunl*".to_string(),    // Calico IPIP tunnels (IPv4 inter-node)
                "ip6tnl*".to_string(),  // IPv6 tunnels (Calico IPv6, dual-stack)
                "vxlan*".to_string(),   // Flannel/generic VXLAN (inter-node)
                "flannel*".to_string(), // Flannel interfaces
                "cali*".to_string(),    // Calico workload interfaces
                "cilium_*".to_string(), // Cilium overlay interfaces
                "lxc*".to_string(),     // Cilium pod interfaces
                "gke*".to_string(),     // GKE-specific interfaces
                "eni*".to_string(),     // AWS VPC CNI interfaces
                "azure*".to_string(),   // Azure CNI interfaces
                "ovn-k8s*".to_string(), // OVN-Kubernetes interfaces
            ],
            auto_discover_interfaces: true,
            tc_priority: 1,
            tcx_order: TcxOrderStrategy::default(),
        }
    }
}

impl InstrumentOptions {
    /// Validate tc_priority and tcx_order settings
    pub fn validate(&self) -> Result<(), String> {
        const MIN_PRIORITY: u16 = 1;
        const MAX_PRIORITY: u16 = 32767;

        if self.tc_priority < MIN_PRIORITY {
            return Err(format!(
                "tc_priority {} is too low (min: {})",
                self.tc_priority, MIN_PRIORITY
            ));
        }

        if self.tc_priority > MAX_PRIORITY {
            return Err(format!(
                "tc_priority {} exceeds netlink limit (max: {})",
                self.tc_priority, MAX_PRIORITY
            ));
        }

        Ok(())
    }
}

/// Informer discovery configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct InformerDiscoveryOptions {
    /// Kubernetes informer configuration
    pub k8s: Option<K8sInformerOptions>,
}

pub mod defaults {
    use std::time::Duration;

    pub fn shutdown_timeout() -> Duration {
        Duration::from_secs(5)
    }
}

/// Validates that the given path points to an existing file with a supported extension.
///
/// # Arguments
///
/// - `path` - A reference to a `PathBuf` to validate.
///
/// # Errors
///
/// - `ConfigError::NoConfigFile` - If the path does not exist.
/// - `ConfigError::InvalidConfigPath` - If the path points to a directory.
/// - `ConfigError::InvalidExtension` - If the file extension is not `yaml`, `yml`, or `hcl`.
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
    /// Error: Configuration validation failed.
    InvalidConfiguration(String),
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
            ConfError::InvalidConfiguration(msg) => {
                write!(f, "configuration validation failed: {msg}")
            }
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

/// Serde helper modules for configuration types.
pub mod conf_serde {
    /// Serde helpers for tracing::Level
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

        /// Serde helpers for Option<Level>
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
                Ok(match opt {
                    Some(s) => Some(s.parse::<Level>().map_err(serde::de::Error::custom)?),
                    None => None,
                })
            }
        }
    }

    /// Serde helpers for humantime Duration (e.g., "5m", "30s", "1h")
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

    /// Serde helpers for StdoutFmt
    pub mod stdout_fmt {
        use serde::{Deserialize, Deserializer, Serializer};

        use crate::otlp::opts::StdoutFmt;

        pub fn serialize<S>(
            stdout_fmt: &Option<StdoutFmt>,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match stdout_fmt {
                Some(fmt) => serializer.serialize_str(fmt.as_str()),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<StdoutFmt>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let opt = Option::<String>::deserialize(deserializer)?;
            Ok(match opt {
                Some(s) => {
                    if s.is_empty() {
                        return Err(serde::de::Error::custom(
                            "stdout format cannot be an empty string",
                        ));
                    }
                    Some(s.parse::<StdoutFmt>().map_err(serde::de::Error::custom)?)
                }
                None => None,
            })
        }
    }

    /// Serde helpers for ExporterProtocol
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

/// Flow capture configuration for eBPF-level flow tracking
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct FlowCapture {
    /// Max capacity (upper bound) for the FLOW_STATS eBPF map (default: 100,000).
    ///
    /// The eBPF map is created with this fixed `max_entries` at load time and does not
    /// resize at runtime. Once the map is full, new entry insert attempts are dropped.
    ///
    /// Controls memory usage of the eBPF FLOW_STATS.
    /// Memory: flows × ~310 bytes (FlowStats: 192 + FlowKey: 58 + BPF overhead: ~58)
    ///
    /// Sizing guide based on typical cluster FPS (flows per second) per node:
    /// - General/Mixed (50-200 FPS):         50,000 (~12 MB) - dev/testing, 2.5-50x headroom
    /// - Service Mesh (100-300 FPS):        100,000 (~23 MB) - default ✓, 33-100x headroom
    /// - Public Ingress (1K-5K FPS):        100,000-500,000 (~23-116 MB) - scale based on traffic
    /// - Extreme Ingress (>5K FPS):         500,000-1,000,000 (~116-232 MB) - edge/CDN scale
    ///
    /// Formula: concurrent_flows = flows_per_sec × avg_flow_lifetime_seconds
    /// Example: 200 FPS (service mesh) × 10s timeout = 2,000 concurrent flows
    ///          → 100K default provides 50x headroom for bursts
    ///          1,000 FPS (low-end public ingress) × 10s = 10,000 concurrent flows
    ///          → 100K default provides 10x headroom (adequate, consider 200K-500K for 3K+ FPS)
    pub flow_stats_capacity: u32,

    /// Max capacity (fixed size) of the FLOW_EVENTS ring buffer in entries (default: 1024)
    ///
    /// The ring buffer is created at this fixed size during eBPF program load and does not
    /// resize at runtime.
    ///
    /// Controls the capacity of the FLOW_EVENTS ring buffer used to pass new flow events
    /// from eBPF to userspace. The ring buffer provides burst tolerance while worker
    /// channels absorb backpressure.
    ///
    /// **Memory**: This buffer size is allocated PER NODE (not per CPU).
    /// Each entry is 234 bytes (FlowEvent size), so default 1024 entries = ~240 KB.
    ///
    /// **Sizing guide** based on new flows per second (FPS):
    /// - General/Mixed (50-500 FPS):       1024 entries (~240 KB) - default ✓
    /// - High Traffic (500-2K FPS):        2048 entries (~480 KB) - 2x buffer
    /// - Very High Traffic (2K-5K FPS):    4096 entries (~960 KB) - 4x buffer
    /// - Extreme Traffic (>5K FPS):        8192+ entries (~1.9 MB+) - scale as needed
    ///
    /// **Formula**: buffer_capacity_entries = (fps × burst_duration_seconds)
    /// - Example: 1,000 FPS × 2s burst = 2,000 entries → use 2048
    ///
    /// **Tuning**: If you see "ring buffer full - dropping flow event" errors,
    /// increase this value. The aya loader automatically aligns to page size.
    pub flow_events_capacity: u32,
}

impl Default for FlowCapture {
    fn default() -> Self {
        Self {
            flow_stats_capacity: 100_000,
            flow_events_capacity: 1024,
        }
    }
}

impl FlowCapture {
    /// Convert flow_events_capacity (entries) to bytes for eBPF ring buffer initialization
    pub fn flow_events_capacity_bytes(&self) -> u32 {
        self.flow_events_capacity * size_of::<FlowEvent>() as u32
    }
}

/// Flow producer configuration for userspace flow processing
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct FlowProducer {
    /// Number of flow worker threads for packet processing (default: 4)
    ///
    /// Each worker processes events from its own queue with capacity `worker_queue_capacity`.
    pub workers: usize,

    /// Capacity for each worker thread's queue (default: 2048)
    ///
    /// Determines how many raw eBPF events can be buffered per worker.
    /// Total worker buffer memory = workers * worker_queue_capacity * event_size.
    pub worker_queue_capacity: usize,

    /// Worker polling interval (default: 5s)
    /// Pollers check for record intervals and timeouts at this frequency.
    /// Lower values = more responsive but higher CPU. Higher values = less overhead.
    /// At 10K flows/sec with 100K active flows and 32 pollers: ~600 checks/sec per poller.
    #[serde(with = "duration")]
    pub flow_store_poll_interval: Duration,

    /// Explicit capacity for the flow span channel (default: 16384)
    /// Buffer between workers and K8s decorator.
    /// With defaults: 16,384 slots (~1.6s buffer at 10K/s, handles export delays).
    pub flow_span_queue_capacity: usize,
}

impl Default for FlowProducer {
    fn default() -> Self {
        Self {
            workers: 4,
            worker_queue_capacity: 2048,
            flow_store_poll_interval: Duration::from_secs(5),
            flow_span_queue_capacity: 16384,
        }
    }
}

/// Kubernetes decorator configuration
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct K8sDecorator {
    /// Number of dedicated threads for K8s decorator (default: 4)
    /// Creates a dedicated multi-threaded Tokio runtime for Kubernetes metadata decoration.
    /// Each thread handles ~8K flows/sec, so 4 threads = 32K flows/sec capacity (3x headroom for 10K target).
    /// Increase for large clusters: 8 threads for 50K flows/sec, 12 threads for 100K flows/sec.
    pub threads: usize,

    /// Capacity for the decorated span channel (default: 32768)
    /// Buffer between K8s decorator and OTLP exporter.
    /// With defaults: 32,768 slots (~3.2s buffer at 10K/s, prevents backpressure).
    pub decorated_span_queue_capacity: usize,
}

impl Default for K8sDecorator {
    fn default() -> Self {
        Self {
            threads: 4,
            decorated_span_queue_capacity: 32768,
        }
    }
}

/// Pipeline tuning configuration for flow processing optimization
///
/// Defaults are tuned for typical enterprise deployments (1K-5K flows/sec):
/// - `flow_capture.flow_stats_capacity = 100000` (max capacity / upper bound, supports ~10K flows/sec with 10x headroom)
/// - `flow_producer.worker_queue_capacity = 2048` (buffer per worker)
/// - `flow_producer.workers = 4` (parallel flow processing across cores)
/// - `k8s_decorator.threads = 4` (handles typical K8s clusters efficiently)
/// - `flow_producer.flow_store_poll_interval = 5s` (responsive timeout checking with low CPU overhead)
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct PipelineOptions {
    /// Flow capture configuration for eBPF-level flow tracking
    pub flow_capture: FlowCapture,

    /// Flow producer configuration for userspace flow processing
    pub flow_producer: FlowProducer,

    /// Kubernetes decorator configuration
    pub k8s_decorator: K8sDecorator,
    // TODO: Implement adaptive sampling (ring buffer consumer in mermin-ebpf/src/main.rs)
    // Enable adaptive sampling under backpressure (default: true)
    // **NOT IMPLEMENTED:** Should drop low-priority flows when worker channels are full.
    // pub sampling_enabled: bool,

    // TODO: Implement minimum sampling rate enforcement
    // Minimum sampling rate to maintain (default: 0.1 = 10%)
    // **NOT IMPLEMENTED:** Ensure at least 10% of flows pass through even under extreme load.
    // pub sampling_min_rate: f32,

    // TODO: Implement backpressure threshold warnings
    // Drop rate threshold for backpressure warnings (default: 0.01 = 1%)
    // **NOT IMPLEMENTED:** Should emit warnings when drop rate exceeds this threshold.
    // pub backpressure_warning_threshold: f32,
}

impl PipelineOptions {
    pub fn validate_memory_usage(&self) {
        if let Some(limit) = std::env::var("POD_RESOURCES_LIMITS_MEM")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|&v| v > 0)
        {
            self.validate_memory_usage_against_limit(limit);
        } else {
            debug!(
                event.name = "config.memory_check.skipped",
                reason = "memory_limit_not_found",
                "could not determine memory limit (POD_RESOURCES_LIMITS_MEM not set or set to 0), skipping validation"
            );
        }
    }

    fn validate_memory_usage_against_limit(&self, limit_bytes: u64) -> bool {
        const MB: u64 = 1024 * 1024;

        let flow_event_size = size_of::<FlowEvent>() as u64;
        let flow_stats_size = size_of::<FlowStats>() as u64;

        // FlowSpan with baseline info
        let span_undecorated_size = size_of::<FlowSpan>() as u64 + 256;

        // Flow span with k8s metadata
        let span_decorated_size = size_of::<FlowSpan>() as u64 + 2048;

        let capture_bytes = {
            let stats_map = self.flow_capture.flow_stats_capacity as u64 * 300;
            let ring_buf = self.flow_capture.flow_events_capacity as u64 * flow_event_size;
            stats_map + ring_buf
        };

        let producer_bytes = {
            let worker_buffers = (self.flow_producer.workers
                * self.flow_producer.worker_queue_capacity) as u64
                * flow_event_size;
            // Hash map overhead estimate (1.5x)
            let flow_store =
                (self.flow_capture.flow_stats_capacity as u64 * flow_stats_size * 3) / 2;

            let output_queue =
                self.flow_producer.flow_span_queue_capacity as u64 * span_undecorated_size;

            worker_buffers + flow_store + output_queue
        };

        let decorator_bytes = {
            // Informer cache size estimate:
            //
            // Apply a factor estimate of 512 bytes per flow-slot.
            // - 100k flows -> Est. 50 MB Cache (Matches a ~5,000-pod cluster)
            // - 10k flows -> Est. 5 MB Cache (Matches a ~500-pod cluster)
            let informer_cache_baseline = self.flow_capture.flow_stats_capacity as u64 * 512;

            let output_queue =
                self.k8s_decorator.decorated_span_queue_capacity as u64 * span_decorated_size;

            informer_cache_baseline + output_queue
        };

        let estimated_usage = capture_bytes + producer_bytes + decorator_bytes;

        // 80% threshold
        let threshold_bytes = (limit_bytes as f64 * 0.80) as u64;

        if estimated_usage > threshold_bytes {
            warn!(
                event.name = "config.memory_warning",
                estimated_usage_mb = estimated_usage / MB,
                limit_mb = limit_bytes / MB,
                ebpf_mb = capture_bytes / MB,
                producer_mb = producer_bytes / MB,
                decorator_mb = decorator_bytes / MB,
                "Pipeline memory projection ({:.1} MB) exceeds safe threshold of container limit ({:.1} MB). \
                 Mermin is at risk of OOM Kill during traffic bursts. \
                 Action: Increase memory limit or tune config.",
                estimated_usage as f64 / MB as f64,
                limit_bytes as f64 / MB as f64,
            );
            false
        } else {
            info!(
                event.name = "config.memory_check",
                estimated_usage_mb = estimated_usage / MB,
                limit_mb = limit_bytes / MB,
                utilization_pct = (estimated_usage as f64 / limit_bytes as f64) * 100.0,
                "Memory configuration is valid."
            );
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use clap::Parser;
    use figment::Jail;
    use tracing::Level;

    use super::{Conf, InstrumentOptions, ParserConf, PipelineOptions};
    use crate::{
        metrics::opts::MetricsOptions,
        otlp::opts::{ExportOptions, ExporterProtocol},
        runtime::{
            cli::Cli,
            conf::TcxOrderStrategy,
            opts::{InternalOptions, ServerConf},
        },
        span::opts::SpanOptions,
    };

    #[test]
    fn default_conf_has_expected_values() {
        let cfg = Conf::default();

        assert_eq!(
            cfg.log_level,
            Level::INFO,
            "default log level should be INFO"
        );
        assert_eq!(
            cfg.auto_reload, false,
            "auto_reload should be disabled by default"
        );
        assert_eq!(
            cfg.shutdown_timeout,
            Duration::from_secs(5),
            "shutdown_timeout should be 5s"
        );
        assert_eq!(
            cfg.pipeline.flow_producer.worker_queue_capacity, 2048,
            "worker_queue_capacity should be 2048"
        );
        assert_eq!(
            cfg.pipeline.flow_producer.flow_span_queue_capacity, 16384,
            "default flow_span_queue_capacity should be 16384"
        );
        assert_eq!(
            cfg.pipeline.k8s_decorator.decorated_span_queue_capacity, 32768,
            "default decorated_span_queue_capacity should be 32768"
        );

        assert_eq!(
            cfg.discovery.instrument.interfaces,
            vec![
                "veth*".to_string(),
                "tunl*".to_string(),
                "ip6tnl*".to_string(),
                "vxlan*".to_string(),
                "flannel*".to_string(),
                "cali*".to_string(),
                "cilium_*".to_string(),
                "lxc*".to_string(),
                "gke*".to_string(),
                "eni*".to_string(),
                "azure*".to_string(),
                "ovn-k8s*".to_string()
            ],
            "default interfaces should be common physical interface patterns"
        );

        assert_eq!(
            cfg.internal.server.enabled, true,
            "server should be enabled by default"
        );
        assert_eq!(
            cfg.internal.server.listen_address, "0.0.0.0",
            "server should listen on all interfaces by default"
        );
        assert_eq!(cfg.internal.server.port, 8080, "server port should be 8080");

        assert_eq!(
            cfg.internal.metrics.enabled, true,
            "metrics should be enabled by default"
        );
        assert_eq!(
            cfg.internal.metrics.listen_address, "0.0.0.0",
            "metrics should listen on all interfaces by default"
        );
        assert_eq!(
            cfg.internal.metrics.port, 10250,
            "metrics port should be 10250"
        );

        assert_eq!(
            cfg.parser.geneve_port, 6081,
            "Geneve port should be 6081 (IANA default)"
        );
        assert_eq!(
            cfg.parser.vxlan_port, 4789,
            "VXLAN port should be 4789 (IANA default)"
        );
        assert_eq!(
            cfg.parser.wireguard_port, 51820,
            "WireGuard port should be 51820 (IANA default)"
        );

        assert_eq!(
            cfg.config_path, None,
            "config_path should be None for default config"
        );

        assert_eq!(
            cfg.span.max_record_interval,
            Duration::from_secs(60),
            "default max_record_interval should be 60s"
        );
        assert_eq!(
            cfg.span.generic_timeout,
            Duration::from_secs(30),
            "default generic_timeout should be 30s"
        );
        assert_eq!(
            cfg.span.icmp_timeout,
            Duration::from_secs(10),
            "default icmp_timeout should be 10s"
        );
        assert_eq!(
            cfg.span.tcp_timeout,
            Duration::from_secs(20),
            "default tcp_timeout should be 20s"
        );
        assert_eq!(
            cfg.span.tcp_fin_timeout,
            Duration::from_secs(5),
            "default tcp_fin_timeout should be 5s"
        );
        assert_eq!(
            cfg.span.tcp_rst_timeout,
            Duration::from_secs(5),
            "default tcp_rst_timeout should be 5s"
        );
        assert_eq!(
            cfg.span.udp_timeout,
            Duration::from_secs(60),
            "default udp_timeout should be 60s"
        );
        assert_eq!(
            cfg.span.trace_id_timeout,
            Duration::from_secs(86400),
            "default trace_id_timeout should be 24h (86400s)"
        );

        assert!(
            cfg.export.traces.otlp.is_none(),
            "default export (via ::default()) should not have OTLP configured"
        );
        assert!(
            cfg.export.traces.stdout.is_none(),
            "default export should not have stdout enabled"
        );

        assert!(
            matches!(
                cfg.internal.traces.span_fmt,
                crate::runtime::opts::SpanFmt::Full
            ),
            "default internal span_fmt should be Full"
        );
        assert!(
            !cfg.log_color,
            "default log_color should be false (colors disabled)"
        );
        assert!(
            cfg.internal.traces.stdout.is_none(),
            "default internal traces stdout should be None"
        );
        assert!(
            cfg.internal.traces.otlp.is_none(),
            "default internal traces otlp should be None"
        );
    }

    #[test]
    fn test_conf_serialization() {
        let cfg = Conf::default();

        let serialized = serde_yaml::to_string(&cfg).expect("should serialize");
        let deserialized: Conf = serde_yaml::from_str(&serialized).expect("should deserialize");

        assert_eq!(
            cfg.pipeline.flow_producer.worker_queue_capacity,
            deserialized.pipeline.flow_producer.worker_queue_capacity
        );
        assert_eq!(
            cfg.pipeline.flow_producer.flow_span_queue_capacity,
            deserialized.pipeline.flow_producer.flow_span_queue_capacity
        );
        assert_eq!(
            cfg.pipeline.k8s_decorator.decorated_span_queue_capacity,
            deserialized
                .pipeline
                .k8s_decorator
                .decorated_span_queue_capacity
        );
        assert_eq!(
            cfg.pipeline.flow_producer.workers,
            deserialized.pipeline.flow_producer.workers
        );
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
discovery:
  instrument:
    interfaces:
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
            assert_eq!(
                cfg.discovery.instrument.interfaces,
                Vec::from(["eth1".to_string()])
            );
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
discovery:
  instrument:
    interfaces: ["eth1"]
auto_reload: true
log_level: debug
                "#,
            )?;
            jail.set_env("MERMIN_CONFIG_PATH", path);

            let cli = Cli::parse_from(["mermin"]);
            let (cfg, _cli) = Conf::new(cli).expect("config loads from env file");
            assert_eq!(
                cfg.discovery.instrument.interfaces,
                Vec::from(["eth1".to_string()])
            );
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
discovery:
  instrument:
    interfaces: ["eth1"]
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config loads from cli file");
            assert_eq!(
                cfg.discovery.instrument.interfaces,
                Vec::from(["eth1".to_string()])
            );
            assert_eq!(cfg.config_path, Some(path.parse().unwrap()));

            // Update the config file
            jail.create_file(
                path,
                r#"
discovery:
  instrument:
    interfaces: ["eth2", "eth3"]
                "#,
            )?;

            let reloaded_cfg = cfg.reload().expect("config should reload");
            assert_eq!(
                reloaded_cfg.discovery.instrument.interfaces,
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
    fn loads_server_and_metrics_config_from_yaml_file() {
        Jail::expect_with(|jail| {
            let path = "mermin_custom_api.yaml";

            jail.create_file(
                path,
                r#"
# Custom configuration for testing
discovery:
  instrument:
    interfaces:
      - eth1

internal:
  server:
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
            assert_eq!(
                cfg.discovery.instrument.interfaces,
                Vec::from(["eth1".to_string()])
            );
            assert_eq!(cfg.internal.server.listen_address, "127.0.0.1");
            assert_eq!(cfg.internal.server.port, 8081);
            assert_eq!(cfg.internal.metrics.listen_address, "0.0.0.0");
            assert_eq!(cfg.internal.metrics.port, 9090);

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
discovery "instrument" {
    interfaces = ["eth0"]
}

log_level = "info"
auto_reload = true

internal {
    server {
        enabled = true
        port = 9090
    }
    metrics {
        enabled = true
        port = 10250
    }
}
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load from HCL file");

            assert_eq!(cfg.discovery.instrument.interfaces, vec!["eth0"]);
            assert_eq!(cfg.log_level, Level::INFO);
            assert_eq!(cfg.auto_reload, true);
            assert_eq!(cfg.internal.server.port, 9090);
            assert_eq!(cfg.internal.metrics.port, 10250);

            Ok(())
        });
    }

    #[test]
    fn validates_hcl_extension() {
        Jail::expect_with(|jail| {
            let path = "mermin.hcl";
            jail.create_file(path, r#"discovery "instrument" { interfaces = ["eth0"] }"#)?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let result = Conf::new(cli);
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
discovery "instrument" {
    interfaces = ["eth1"]
}
log_level = "info"
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config loads from HCL file");
            assert_eq!(
                cfg.discovery.instrument.interfaces,
                Vec::from(["eth1".to_string()])
            );
            assert_eq!(cfg.log_level, Level::INFO);
            assert_eq!(cfg.config_path, Some(path.parse().unwrap()));

            // Update the HCL config file
            jail.create_file(
                path,
                r#"
discovery "instrument" {
    interfaces = ["eth2", "eth3"]
}
log_level = "debug"
                "#,
            )?;

            let reloaded_cfg = cfg.reload().expect("config should reload from HCL");
            assert_eq!(
                reloaded_cfg.discovery.instrument.interfaces,
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
interfaces = [eth0  # Missing closing bracket and quotes
log_level =
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let err = Conf::new(cli).expect_err("expected error with invalid HCL");
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
    fn loads_server_and_metrics_config_from_hcl_file() {
        Jail::expect_with(|jail| {
            let path = "mermin_custom_server.hcl";

            jail.create_file(
                path,
                r#"
# Custom configuration for testing
discovery "instrument" {
    interfaces = ["eth1"]
}

internal {
    server {
        listen_address = "127.0.0.1"
        port = 8081
    }
    metrics {
        listen_address = "0.0.0.0"
        port = 9090
    }
}
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load from HCL file");

            // Assert that all the custom values from the file were loaded correctly
            assert_eq!(
                cfg.discovery.instrument.interfaces,
                Vec::from(["eth1".to_string()])
            );
            assert_eq!(cfg.internal.server.listen_address, "127.0.0.1");
            assert_eq!(cfg.internal.server.port, 8081);
            assert_eq!(cfg.internal.metrics.listen_address, "0.0.0.0");
            assert_eq!(cfg.internal.metrics.port, 9090);

            Ok(())
        });
    }

    #[test]
    fn override_all_core_settings_via_yaml() {
        Jail::expect_with(|jail| {
            let path = "override_core.yaml";
            jail.create_file(
                path,
                r#"
log_level: error
auto_reload: true
shutdown_timeout: 30s
pipeline:
  flow_producer:
    worker_queue_capacity: 512
    workers: 8
discovery:
  instrument:
    interfaces:
      - eth1
      - eth2
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert_eq!(cfg.log_level, Level::ERROR);
            assert_eq!(cfg.auto_reload, true);
            assert_eq!(cfg.shutdown_timeout, Duration::from_secs(30));
            assert_eq!(cfg.pipeline.flow_producer.worker_queue_capacity, 512);
            assert_eq!(cfg.pipeline.flow_producer.flow_span_queue_capacity, 16384);
            assert_eq!(
                cfg.pipeline.k8s_decorator.decorated_span_queue_capacity,
                32768
            );
            assert_eq!(cfg.pipeline.flow_producer.workers, 8);
            assert_eq!(cfg.discovery.instrument.interfaces, vec!["eth1", "eth2"]);

            Ok(())
        });
    }

    #[test]
    fn override_all_core_settings_via_hcl() {
        Jail::expect_with(|jail| {
            let path = "override_core.hcl";
            jail.create_file(
                path,
                r#"
log_level = "error"
auto_reload = true
shutdown_timeout = "30s"
pipeline {
  flow_producer {
    workers = 8
    worker_queue_capacity = 512
  }
}
discovery "instrument" {
    interfaces = ["eth1", "eth2"]
}
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert_eq!(cfg.log_level, Level::ERROR);
            assert_eq!(cfg.auto_reload, true);
            assert_eq!(cfg.shutdown_timeout, Duration::from_secs(30));
            assert_eq!(cfg.pipeline.flow_producer.worker_queue_capacity, 512);
            assert_eq!(cfg.pipeline.flow_producer.flow_span_queue_capacity, 16384);
            assert_eq!(
                cfg.pipeline.k8s_decorator.decorated_span_queue_capacity,
                32768
            );
            assert_eq!(cfg.pipeline.flow_producer.workers, 8);
            assert_eq!(cfg.discovery.instrument.interfaces, vec!["eth1", "eth2"]);

            Ok(())
        });
    }

    #[test]
    fn override_server_settings_via_yaml() {
        Jail::expect_with(|jail| {
            let path = "override_server.yaml";
            jail.create_file(
                path,
                r#"
internal:
  server:
    enabled: false
    listen_address: "127.0.0.1"
    port: 9000
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert_eq!(cfg.internal.server.enabled, false);
            assert_eq!(cfg.internal.server.listen_address, "127.0.0.1");
            assert_eq!(cfg.internal.server.port, 9000);

            Ok(())
        });
    }

    #[test]
    fn override_server_settings_via_hcl() {
        Jail::expect_with(|jail| {
            let path = "override_server.hcl";
            jail.create_file(
                path,
                r#"
internal "server" {
    enabled = false
    listen_address = "127.0.0.1"
    port = 9000
}
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert_eq!(cfg.internal.server.enabled, false);
            assert_eq!(cfg.internal.server.listen_address, "127.0.0.1");
            assert_eq!(cfg.internal.server.port, 9000);

            Ok(())
        });
    }

    #[test]
    fn override_metrics_settings_via_yaml() {
        Jail::expect_with(|jail| {
            let path = "override_metrics.yaml";
            jail.create_file(
                path,
                r#"
internal:
  metrics:
    enabled: false
    listen_address: "192.168.1.1"
    port: 9999
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert_eq!(cfg.internal.metrics.enabled, false);
            assert_eq!(cfg.internal.metrics.listen_address, "192.168.1.1");
            assert_eq!(cfg.internal.metrics.port, 9999);

            Ok(())
        });
    }

    #[test]
    fn override_metrics_settings_via_hcl() {
        Jail::expect_with(|jail| {
            let path = "override_metrics.hcl";
            jail.create_file(
                path,
                r#"
internal {
    metrics {
        enabled = false
        listen_address = "192.168.1.1"
        port = 9999
    }
}
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert_eq!(cfg.internal.metrics.enabled, false);
            assert_eq!(cfg.internal.metrics.listen_address, "192.168.1.1");
            assert_eq!(cfg.internal.metrics.port, 9999);

            Ok(())
        });
    }

    #[test]
    fn override_metrics_settings_via_hcl_labeled_block() {
        Jail::expect_with(|jail| {
            let path = "override_metrics_labeled.hcl";
            jail.create_file(
                path,
                r#"
internal "metrics" {
    enabled = false
    listen_address = "192.168.1.1"
    port = 9999
}
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert_eq!(cfg.internal.metrics.enabled, false);
            assert_eq!(cfg.internal.metrics.listen_address, "192.168.1.1");
            assert_eq!(cfg.internal.metrics.port, 9999);

            Ok(())
        });
    }

    #[test]
    fn override_parser_settings_via_yaml() {
        Jail::expect_with(|jail| {
            let path = "override_parser.yaml";
            jail.create_file(
                path,
                r#"
parser:
  geneve_port: 7000
  vxlan_port: 8000
  wireguard_port: 9000
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert_eq!(cfg.parser.geneve_port, 7000);
            assert_eq!(cfg.parser.vxlan_port, 8000);
            assert_eq!(cfg.parser.wireguard_port, 9000);

            Ok(())
        });
    }

    #[test]
    fn override_parser_settings_via_hcl() {
        Jail::expect_with(|jail| {
            let path = "override_parser.hcl";
            jail.create_file(
                path,
                r#"
parser {
    geneve_port = 7000
    vxlan_port = 8000
    wireguard_port = 9000
}
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert_eq!(cfg.parser.geneve_port, 7000);
            assert_eq!(cfg.parser.vxlan_port, 8000);
            assert_eq!(cfg.parser.wireguard_port, 9000);

            Ok(())
        });
    }

    #[test]
    fn cli_args_override_file_config() {
        Jail::expect_with(|jail| {
            let path = "cli_override.yaml";
            jail.create_file(
                path,
                r#"
log_level: info
auto_reload: false
                "#,
            )?;

            let cli = Cli::parse_from([
                "mermin",
                "--config",
                path.into(),
                "--log-level",
                "warn",
                "--auto-reload",
            ]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            // CLI args should override file config
            assert_eq!(cfg.log_level, Level::WARN);
            assert_eq!(cfg.auto_reload, true);

            Ok(())
        });
    }

    #[test]
    fn partial_override_preserves_defaults() {
        Jail::expect_with(|jail| {
            let path = "partial.yaml";
            jail.create_file(
                path,
                r#"
# Only override interfaces, everything else should remain default
discovery:
  instrument:
    interfaces:
      - custom0
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            // Overridden value
            assert_eq!(cfg.discovery.instrument.interfaces, vec!["custom0"]);

            // Default values should be preserved
            assert_eq!(cfg.log_level, Level::INFO);
            assert_eq!(cfg.auto_reload, false);
            assert_eq!(cfg.shutdown_timeout, Duration::from_secs(5));
            assert_eq!(cfg.pipeline.flow_producer.worker_queue_capacity, 2048);
            assert_eq!(cfg.pipeline.flow_producer.flow_span_queue_capacity, 16384);
            assert_eq!(
                cfg.pipeline.k8s_decorator.decorated_span_queue_capacity,
                32768
            );
            assert_eq!(cfg.pipeline.flow_producer.workers, 4);
            assert_eq!(cfg.internal.server.port, 8080);
            assert_eq!(cfg.internal.metrics.port, 10250);
            assert!(matches!(
                cfg.internal.traces.span_fmt,
                crate::runtime::opts::SpanFmt::Full
            ));
            assert!(cfg.internal.traces.stdout.is_none());
            assert!(cfg.internal.traces.otlp.is_none());
            assert_eq!(cfg.parser.geneve_port, 6081);
            assert_eq!(cfg.span.max_record_interval, Duration::from_secs(60));
            assert_eq!(cfg.span.generic_timeout, Duration::from_secs(30));
            assert_eq!(cfg.span.icmp_timeout, Duration::from_secs(10));
            assert_eq!(cfg.span.tcp_timeout, Duration::from_secs(20));
            assert_eq!(cfg.span.tcp_fin_timeout, Duration::from_secs(5));
            assert_eq!(cfg.span.tcp_rst_timeout, Duration::from_secs(5));
            assert_eq!(cfg.span.udp_timeout, Duration::from_secs(60));
            assert_eq!(cfg.span.trace_id_timeout, Duration::from_secs(86400));
            assert!(cfg.export.traces.stdout.is_none());
            // OTLP should not be configured unless explicitly set
            assert!(cfg.export.traces.otlp.is_none());

            Ok(())
        });
    }

    #[test]
    fn test_duration_format_variations() {
        Jail::expect_with(|jail| {
            let path = "duration_formats.yaml";
            jail.create_file(
                path,
                r#"
shutdown_timeout: 2min
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert_eq!(cfg.shutdown_timeout, Duration::from_secs(120));

            Ok(())
        });
    }

    #[test]
    fn test_log_level_variations() {
        for (level_str, expected) in [
            ("trace", Level::TRACE),
            ("debug", Level::DEBUG),
            ("info", Level::INFO),
            ("warn", Level::WARN),
            ("error", Level::ERROR),
        ] {
            Jail::expect_with(|jail| {
                let path = "log_level.yaml";
                jail.create_file(path, &format!("log_level: {}", level_str))?;

                let cli = Cli::parse_from(["mermin", "--config", path.into()]);
                let (cfg, _cli) = Conf::new(cli).expect("config should load");

                assert_eq!(cfg.log_level, expected, "failed for level: {}", level_str);

                Ok(())
            });
        }
    }

    #[test]
    fn default_parser_conf_has_expected_values() {
        let parser = ParserConf::default();

        assert_eq!(
            parser.geneve_port, 6081,
            "Geneve default port should be 6081"
        );
        assert_eq!(parser.vxlan_port, 4789, "VXLAN default port should be 4789");
        assert_eq!(
            parser.wireguard_port, 51820,
            "WireGuard default port should be 51820"
        );
    }

    #[test]
    fn default_server_conf_has_expected_values() {
        let server = ServerConf::default();

        assert_eq!(server.enabled, true, "server should be enabled by default");
        assert_eq!(
            server.listen_address, "0.0.0.0",
            "server should listen on all interfaces"
        );
        assert_eq!(server.port, 8080, "server default port should be 8080");
    }

    #[test]
    fn default_metrics_conf_has_expected_values() {
        let metrics = MetricsOptions::default();

        assert_eq!(
            metrics.enabled, true,
            "metrics should be enabled by default"
        );
        assert_eq!(
            metrics.listen_address, "0.0.0.0",
            "metrics should listen on all interfaces"
        );
        assert_eq!(metrics.port, 10250, "metrics default port should be 10250");
    }

    #[test]
    fn default_span_options_has_expected_values() {
        let span = SpanOptions::default();

        assert_eq!(
            span.max_record_interval,
            Duration::from_secs(60),
            "max_record_interval should be 60s"
        );
        assert_eq!(
            span.generic_timeout,
            Duration::from_secs(30),
            "generic_timeout should be 30s"
        );
        assert_eq!(
            span.icmp_timeout,
            Duration::from_secs(10),
            "icmp_timeout should be 10s"
        );
        assert_eq!(
            span.tcp_timeout,
            Duration::from_secs(20),
            "tcp_timeout should be 20s"
        );
        assert_eq!(
            span.tcp_fin_timeout,
            Duration::from_secs(5),
            "tcp_fin_timeout should be 5s"
        );
        assert_eq!(
            span.tcp_rst_timeout,
            Duration::from_secs(5),
            "tcp_rst_timeout should be 5s"
        );
        assert_eq!(
            span.udp_timeout,
            Duration::from_secs(60),
            "udp_timeout should be 60s"
        );
        assert_eq!(
            span.trace_id_timeout,
            Duration::from_secs(86400),
            "trace_id_timeout should be 24h (86400s)"
        );
    }

    #[test]
    fn default_export_options_has_expected_values() {
        let export = ExportOptions::default();

        // When calling ::default() directly (not via deserialization),
        // both otlp and stdout are None since serde defaults only apply during deserialization
        assert!(
            export.traces.otlp.is_none(),
            "default export (via ::default()) should not have OTLP configured"
        );
        assert!(
            export.traces.stdout.is_none(),
            "default export should not have stdout enabled"
        );
    }

    #[test]
    fn minimal_config_uses_defaults() {
        // Test that when loading from a minimal config file,
        // unspecified fields get their default values
        Jail::expect_with(|jail| {
            let path = "minimal_config.yaml";
            jail.create_file(
                path,
                r#"
# Minimal config - unspecified fields should get defaults
discovery:
  instrument:
    interfaces:
      - eth0
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            // Verify that defaults are applied for unspecified fields
            // Note: export.traces.otlp is None by default (not configured unless explicitly set)
            assert!(
                cfg.export.traces.otlp.is_none(),
                "export OTLP should not be configured unless explicitly set in config"
            );
            assert!(
                cfg.export.traces.stdout.is_none(),
                "export stdout should not be enabled unless explicitly set"
            );

            // Other defaults should be applied
            assert_eq!(cfg.log_level, Level::INFO);
            assert_eq!(cfg.pipeline.flow_producer.worker_queue_capacity, 2048);
            assert_eq!(cfg.pipeline.flow_producer.flow_span_queue_capacity, 16384);
            assert_eq!(
                cfg.pipeline.k8s_decorator.decorated_span_queue_capacity,
                32768
            );

            // Verify all span defaults
            assert_eq!(cfg.span.max_record_interval, Duration::from_secs(60));
            assert_eq!(cfg.span.generic_timeout, Duration::from_secs(30));
            assert_eq!(cfg.span.icmp_timeout, Duration::from_secs(10));
            assert_eq!(cfg.span.tcp_timeout, Duration::from_secs(20));
            assert_eq!(cfg.span.tcp_fin_timeout, Duration::from_secs(5));
            assert_eq!(cfg.span.tcp_rst_timeout, Duration::from_secs(5));
            assert_eq!(cfg.span.udp_timeout, Duration::from_secs(60));
            assert_eq!(cfg.span.trace_id_timeout, Duration::from_secs(86400));

            Ok(())
        });
    }

    #[test]
    fn export_both_stdout_and_otlp_can_be_set() {
        // Both exporters can be configured simultaneously if desired
        Jail::expect_with(|jail| {
            let path = "export_both.yaml";
            jail.create_file(
                path,
                r#"
export:
  traces:
    stdout:
      format: "text_indent"
    otlp:
      endpoint: "http://collector:4317"
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert!(cfg.export.traces.stdout.is_some());
            assert!(cfg.export.traces.otlp.is_some());
            if let Some(otlp) = &cfg.export.traces.otlp {
                assert_eq!(otlp.endpoint, "http://collector:4317");
            }

            Ok(())
        });
    }

    #[test]
    fn export_empty_block_has_no_exporters() {
        // Empty export.traces block means no exporters configured
        Jail::expect_with(|jail| {
            let path = "export_empty.yaml";
            jail.create_file(
                path,
                r#"
export:
  traces: {}
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            // Empty export block should result in no exporters configured
            assert!(cfg.export.traces.otlp.is_none());
            assert!(cfg.export.traces.stdout.is_none());

            Ok(())
        });
    }

    #[test]
    fn default_internal_options_has_expected_values() {
        let internal = InternalOptions::default();

        // Check default trace options
        assert!(
            matches!(
                internal.traces.span_fmt,
                crate::runtime::opts::SpanFmt::Full
            ),
            "default internal trace span_fmt should be Full"
        );
        assert!(
            internal.traces.stdout.is_none(),
            "default internal traces should not have stdout enabled"
        );
        assert!(
            internal.traces.otlp.is_none(),
            "default internal traces should not have OTLP exporter"
        );
    }

    #[test]
    fn override_span_settings_via_yaml() {
        Jail::expect_with(|jail| {
            let path = "override_span.yaml";
            jail.create_file(
                path,
                r#"
span:
  max_record_interval: 120s
  generic_timeout: 45s
  icmp_timeout: 15s
  tcp_timeout: 30s
  tcp_fin_timeout: 10s
  tcp_rst_timeout: 10s
  udp_timeout: 90s
  trace_id_timeout: 12h
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert_eq!(cfg.span.max_record_interval, Duration::from_secs(120));
            assert_eq!(cfg.span.generic_timeout, Duration::from_secs(45));
            assert_eq!(cfg.span.icmp_timeout, Duration::from_secs(15));
            assert_eq!(cfg.span.tcp_timeout, Duration::from_secs(30));
            assert_eq!(cfg.span.tcp_fin_timeout, Duration::from_secs(10));
            assert_eq!(cfg.span.tcp_rst_timeout, Duration::from_secs(10));
            assert_eq!(cfg.span.udp_timeout, Duration::from_secs(90));
            assert_eq!(cfg.span.trace_id_timeout, Duration::from_secs(43200)); // 12 hours

            Ok(())
        });
    }

    #[test]
    fn override_span_settings_via_hcl() {
        Jail::expect_with(|jail| {
            let path = "override_span.hcl";
            jail.create_file(
                path,
                r#"
span {
    max_record_interval = "120s"
    generic_timeout = "45s"
    icmp_timeout = "15s"
    tcp_timeout = "30s"
    tcp_fin_timeout = "10s"
    tcp_rst_timeout = "10s"
    udp_timeout = "90s"
    trace_id_timeout = "12h"
}
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert_eq!(cfg.span.max_record_interval, Duration::from_secs(120));
            assert_eq!(cfg.span.generic_timeout, Duration::from_secs(45));
            assert_eq!(cfg.span.icmp_timeout, Duration::from_secs(15));
            assert_eq!(cfg.span.tcp_timeout, Duration::from_secs(30));
            assert_eq!(cfg.span.tcp_fin_timeout, Duration::from_secs(10));
            assert_eq!(cfg.span.tcp_rst_timeout, Duration::from_secs(10));
            assert_eq!(cfg.span.udp_timeout, Duration::from_secs(90));
            assert_eq!(cfg.span.trace_id_timeout, Duration::from_secs(43200)); // 12 hours

            Ok(())
        });
    }

    #[test]
    fn override_export_otlp_settings_via_yaml() {
        Jail::expect_with(|jail| {
            let path = "override_export.yaml";
            jail.create_file(
                path,
                r#"
export:
  traces:
    otlp:
      endpoint: "http://custom:9999"
      protocol: "http_binary"
      timeout: 30s
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert!(cfg.export.traces.otlp.is_some());
            if let Some(otlp) = &cfg.export.traces.otlp {
                assert_eq!(otlp.endpoint, "http://custom:9999");
                assert!(matches!(otlp.protocol, ExporterProtocol::HttpBinary));
                assert_eq!(otlp.timeout, Duration::from_secs(30));
            }

            Ok(())
        });
    }

    #[test]
    fn override_export_otlp_settings_via_hcl() {
        Jail::expect_with(|jail| {
            let path = "override_export.hcl";
            jail.create_file(
                path,
                r#"
export {
    traces {
        otlp {
            endpoint = "http://custom:9999"
            protocol = "http_binary"
            timeout = "30s"
        }
    }
}
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert!(cfg.export.traces.otlp.is_some());
            if let Some(otlp) = &cfg.export.traces.otlp {
                assert_eq!(otlp.endpoint, "http://custom:9999");
                assert!(matches!(otlp.protocol, ExporterProtocol::HttpBinary));
                assert_eq!(otlp.timeout, Duration::from_secs(30));
            }

            Ok(())
        });
    }

    #[test]
    fn override_export_stdout_via_yaml() {
        Jail::expect_with(|jail| {
            let path = "override_export_stdout.yaml";
            jail.create_file(
                path,
                r#"
export:
  traces:
    stdout:
      format: "text_indent"
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert!(cfg.export.traces.stdout.is_some());
            if let Some(stdout) = &cfg.export.traces.stdout {
                assert_eq!(stdout.format.as_ref().unwrap().as_str(), "text_indent");
            }

            Ok(())
        });
    }

    #[test]
    fn export_stdout_empty_format_rejected() {
        // Empty string for stdout format should be rejected
        Jail::expect_with(|jail| {
            let path = "export_stdout_empty.yaml";
            jail.create_file(
                path,
                r#"
export:
  traces:
    stdout:
      format: ""
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let result = Conf::new(cli);

            assert!(result.is_err(), "Empty stdout format should be rejected");
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("stdout format cannot be an empty string"),
                "Error message should mention empty string: {}",
                err
            );

            Ok(())
        });
    }

    #[test]
    fn override_export_stdout_via_hcl() {
        Jail::expect_with(|jail| {
            let path = "override_export_stdout.hcl";
            jail.create_file(
                path,
                r#"
export {
    traces {
        stdout = {
            format = "text_indent"
        }
    }
}
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert!(cfg.export.traces.stdout.is_some());
            if let Some(stdout) = &cfg.export.traces.stdout {
                assert_eq!(stdout.format.as_ref().unwrap().as_str(), "text_indent");
            }

            Ok(())
        });
    }

    #[test]
    fn export_stdout_empty_format_rejected_hcl() {
        Jail::expect_with(|jail| {
            let path = "export_stdout_empty.hcl";
            jail.create_file(
                path,
                r#"
export {
    traces {
        stdout = {
            format = ""
        }
    }
}
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let result = Conf::new(cli);

            assert!(result.is_err(), "Empty stdout format should be rejected");
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("stdout format cannot be an empty string"),
                "Error message should mention empty string: {}",
                err
            );

            Ok(())
        });
    }

    #[test]
    fn override_internal_traces_via_yaml() {
        Jail::expect_with(|jail| {
            let path = "override_internal.yaml";
            jail.create_file(
                path,
                r#"
internal:
  traces:
    span_fmt: "full"
    stdout:
      format: "text_indent"
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert!(matches!(
                cfg.internal.traces.span_fmt,
                crate::runtime::opts::SpanFmt::Full
            ));
            assert!(cfg.internal.traces.stdout.is_some());
            if let Some(stdout) = &cfg.internal.traces.stdout {
                assert_eq!(stdout.format.as_ref().unwrap().as_str(), "text_indent");
            }

            Ok(())
        });
    }

    #[test]
    fn override_internal_traces_via_hcl() {
        Jail::expect_with(|jail| {
            let path = "override_internal.hcl";
            jail.create_file(
                path,
                r#"
internal {
    traces {
        span_fmt = "full"
        stdout = {
            format = "text_indent"
        }
    }
}
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert!(matches!(
                cfg.internal.traces.span_fmt,
                crate::runtime::opts::SpanFmt::Full
            ));
            assert!(cfg.internal.traces.stdout.is_some());
            if let Some(stdout) = &cfg.internal.traces.stdout {
                assert_eq!(stdout.format.as_ref().unwrap().as_str(), "text_indent");
            }

            Ok(())
        });
    }

    #[test]
    fn loads_owner_relations_config_from_hcl_file() {
        Jail::expect_with(|jail| {
            let path = "owner_relations.hcl";
            jail.create_file(
                path,
                r#"
discovery "informer" "k8s" {
    owner_relations = {
        max_depth = 3
        include_kinds = ["Deployment", "StatefulSet"]
        exclude_kinds = ["ReplicaSet"]
    }
}
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load from HCL file");

            assert!(
                cfg.discovery.informer.is_some(),
                "informer config should be present"
            );

            let k8s_conf = cfg
                .discovery
                .informer
                .as_ref()
                .and_then(|informer| informer.k8s.as_ref())
                .expect("k8s informer config should be present");

            assert!(
                k8s_conf.owner_relations.is_some(),
                "owner_relations should be present"
            );

            let owner_relations = k8s_conf.owner_relations.as_ref().unwrap();
            assert_eq!(owner_relations.max_depth, 3, "max_depth should be 3");
            assert_eq!(
                owner_relations.include_kinds,
                vec!["Deployment", "StatefulSet"],
                "include_kinds should match"
            );
            assert_eq!(
                owner_relations.exclude_kinds,
                vec!["ReplicaSet"],
                "exclude_kinds should match"
            );

            Ok(())
        });
    }

    #[test]
    fn loads_owner_relations_config_from_yaml_file() {
        Jail::expect_with(|jail| {
            let path = "owner_relations.yaml";
            jail.create_file(
                path,
                r#"
discovery:
  informer:
    k8s:
      owner_relations:
        max_depth: 3
        include_kinds:
          - Deployment
          - StatefulSet
        exclude_kinds:
          - ReplicaSet
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load from YAML file");

            assert!(
                cfg.discovery.informer.is_some(),
                "informer config should be present"
            );

            let k8s_conf = cfg
                .discovery
                .informer
                .as_ref()
                .and_then(|informer| informer.k8s.as_ref())
                .expect("k8s informer config should be present");

            assert!(
                k8s_conf.owner_relations.is_some(),
                "owner_relations should be present"
            );

            let owner_relations = k8s_conf.owner_relations.as_ref().unwrap();
            assert_eq!(owner_relations.max_depth, 3, "max_depth should be 3");
            assert_eq!(
                owner_relations.include_kinds,
                vec!["Deployment", "StatefulSet"],
                "include_kinds should match"
            );
            assert_eq!(
                owner_relations.exclude_kinds,
                vec!["ReplicaSet"],
                "exclude_kinds should match"
            );

            Ok(())
        });
    }

    #[test]
    fn owner_relations_config_with_defaults() {
        Jail::expect_with(|jail| {
            let path = "owner_relations_defaults.yaml";
            jail.create_file(
                path,
                r#"
discovery:
  informer:
    k8s:
      owner_relations: {}
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load with default values");

            let k8s_conf = cfg
                .discovery
                .informer
                .as_ref()
                .and_then(|informer| informer.k8s.as_ref())
                .expect("k8s informer config should be present");

            let owner_relations = k8s_conf.owner_relations.as_ref().unwrap();
            assert_eq!(
                owner_relations.max_depth, 5,
                "default max_depth should be 5"
            );
            assert!(
                owner_relations.include_kinds.is_empty(),
                "default include_kinds should be empty"
            );
            assert!(
                owner_relations.exclude_kinds.is_empty(),
                "default exclude_kinds should be empty"
            );

            Ok(())
        });
    }

    #[test]
    fn config_without_owner_relations() {
        Jail::expect_with(|jail| {
            let path = "no_owner_relations.yaml";
            jail.create_file(
                path,
                r#"
discovery:
  instrument:
    interfaces:
      - eth0
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load without owner_relations");

            let k8s_conf = cfg
                .discovery
                .informer
                .as_ref()
                .and_then(|informer| informer.k8s.as_ref());

            assert!(
                k8s_conf.is_none(),
                "k8s config should not be present when not specified"
            );

            Ok(())
        });
    }

    #[test]
    fn owner_relations_conf_default_values() {
        use crate::k8s::owner_relations::OwnerRelationsRules;

        let conf = OwnerRelationsRules::default();
        assert_eq!(conf.max_depth, 5, "Default max_depth should be 5");
        assert!(
            conf.include_kinds.is_empty(),
            "Default include_kinds should be empty"
        );
        assert!(
            conf.exclude_kinds.is_empty(),
            "Default exclude_kinds should be empty"
        );
    }

    #[test]
    fn loads_selector_relations_config_from_hcl_file() {
        Jail::expect_with(|jail| {
            let path = "selector_relations.hcl";
            jail.create_file(
                path,
                r#"
discovery "informer" "k8s" {
    selector_relations = [
        {
            kind = "NetworkPolicy"
            to = "Pod"
            selector_match_labels_field = "spec.podSelector.matchLabels"
            selector_match_expressions_field = "spec.podSelector.matchExpressions"
        },
        {
            kind = "Service"
            to = "Pod"
            selector_match_labels_field = "spec.selector"
        }
    ]
}
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load from HCL file");

            assert!(
                cfg.discovery.informer.is_some(),
                "informer config should be present"
            );

            let k8s_conf = cfg
                .discovery
                .informer
                .as_ref()
                .and_then(|informer| informer.k8s.as_ref())
                .expect("k8s informer config should be present");

            assert!(
                k8s_conf.selector_relations.is_some(),
                "selector_relations should be present"
            );

            let selector_relations = k8s_conf.selector_relations.as_ref().unwrap();
            assert_eq!(
                selector_relations.len(),
                2,
                "should have 2 selector relation rules"
            );

            let networkpolicy_rule = &selector_relations[0];
            assert_eq!(networkpolicy_rule.kind, "NetworkPolicy");
            assert_eq!(networkpolicy_rule.to, "Pod");
            assert_eq!(
                networkpolicy_rule.selector_match_labels_field.as_deref(),
                Some("spec.podSelector.matchLabels")
            );
            assert_eq!(
                networkpolicy_rule
                    .selector_match_expressions_field
                    .as_deref(),
                Some("spec.podSelector.matchExpressions")
            );

            let service_rule = &selector_relations[1];
            assert_eq!(service_rule.kind, "Service");
            assert_eq!(service_rule.to, "Pod");
            assert_eq!(
                service_rule.selector_match_labels_field.as_deref(),
                Some("spec.selector")
            );
            assert!(service_rule.selector_match_expressions_field.is_none());

            Ok(())
        });
    }

    #[test]
    fn loads_selector_relations_config_from_yaml_file() {
        Jail::expect_with(|jail| {
            let path = "selector_relations.yaml";
            jail.create_file(
                path,
                r#"
discovery:
  informer:
    k8s:
      selector_relations:
        - kind: NetworkPolicy
          to: Pod
          selector_match_labels_field: "spec.podSelector.matchLabels"
          selector_match_expressions_field: "spec.podSelector.matchExpressions"
        - kind: Service
          to: Pod
          selector_match_labels_field: "spec.selector"
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load from YAML file");

            assert!(
                cfg.discovery.informer.is_some(),
                "informer config should be present"
            );

            let k8s_conf = cfg
                .discovery
                .informer
                .as_ref()
                .and_then(|informer| informer.k8s.as_ref())
                .expect("k8s informer config should be present");

            assert!(
                k8s_conf.selector_relations.is_some(),
                "selector_relations should be present"
            );

            let selector_relations = k8s_conf.selector_relations.as_ref().unwrap();
            assert_eq!(
                selector_relations.len(),
                2,
                "should have 2 selector relation rules"
            );

            let networkpolicy_rule = &selector_relations[0];
            assert_eq!(networkpolicy_rule.kind, "NetworkPolicy");
            assert_eq!(networkpolicy_rule.to, "Pod");

            let service_rule = &selector_relations[1];
            assert_eq!(service_rule.kind, "Service");
            assert_eq!(service_rule.to, "Pod");

            Ok(())
        });
    }

    #[test]
    fn config_without_selector_relations() {
        Jail::expect_with(|jail| {
            let path = "no_selector_relations.yaml";
            jail.create_file(
                path,
                r#"
discovery:
  instrument:
    interfaces:
      - eth0
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) =
                Conf::new(cli).expect("config should load without selector_relations");

            let k8s_conf = cfg
                .discovery
                .informer
                .as_ref()
                .and_then(|informer| informer.k8s.as_ref());

            assert!(
                k8s_conf.is_none(),
                "k8s config should not be present when not specified"
            );

            Ok(())
        });
    }

    #[test]
    fn selector_relations_with_empty_list() {
        Jail::expect_with(|jail| {
            let path = "empty_selector_relations.yaml";
            jail.create_file(
                path,
                r#"
discovery:
  informer:
    k8s:
      selector_relations: []
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load with empty list");

            let k8s_conf = cfg
                .discovery
                .informer
                .as_ref()
                .and_then(|informer| informer.k8s.as_ref())
                .expect("k8s informer config should be present");

            let selector_relations = k8s_conf.selector_relations.as_ref().unwrap();
            assert_eq!(
                selector_relations.len(),
                0,
                "selector_relations should be empty"
            );

            Ok(())
        });
    }

    #[test]
    fn test_tc_priority_validation_valid_range() {
        let conf = InstrumentOptions {
            tc_priority: 50,
            ..Default::default()
        };
        assert!(conf.validate().is_ok());
    }

    #[test]
    fn test_tc_priority_validation_min_boundary() {
        let conf = InstrumentOptions {
            tc_priority: 1,
            ..Default::default()
        };
        assert!(conf.validate().is_ok());
    }

    #[test]
    fn test_tc_priority_validation_max_boundary() {
        let conf = InstrumentOptions {
            tc_priority: 32767,
            ..Default::default()
        };
        assert!(conf.validate().is_ok());
    }

    #[test]
    fn test_tc_priority_validation_below_min() {
        let conf = InstrumentOptions {
            tc_priority: 0,
            ..Default::default()
        };
        let result = conf.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too low"));
    }

    #[test]
    fn test_tc_priority_validation_above_max() {
        let conf = InstrumentOptions {
            tc_priority: 32768,
            ..Default::default()
        };
        let result = conf.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds netlink limit"));
    }

    #[test]
    fn test_tc_priority_validation_safe_range() {
        // Test that values in safe range don't error
        for priority in [30, 50, 100, 1000, 32767] {
            let conf = InstrumentOptions {
                tc_priority: priority,
                ..Default::default()
            };
            assert!(conf.validate().is_ok(), "Failed for priority {}", priority);
        }
    }

    #[test]
    fn test_tc_priority_default_is_valid() {
        let conf = InstrumentOptions::default();
        assert!(conf.validate().is_ok());
        assert_eq!(conf.tc_priority, 1);
    }

    #[test]
    fn test_tcx_order_default_is_first() {
        let conf = InstrumentOptions::default();
        assert!(conf.validate().is_ok());
        assert_eq!(conf.tcx_order, TcxOrderStrategy::First);
    }

    #[test]
    fn test_tc_priority_boundary_values() {
        // Test edge cases around the boundaries
        let valid_priorities = [1, 2, 29, 30, 31, 49, 50, 51, 32766, 32767];
        for priority in valid_priorities {
            let conf = InstrumentOptions {
                tc_priority: priority,
                ..Default::default()
            };
            assert!(
                conf.validate().is_ok(),
                "Priority {} should be valid",
                priority
            );
        }

        // Test invalid values
        let invalid_priorities = [0u16, 32768u16, 65535u16];
        for priority in invalid_priorities {
            let conf = InstrumentOptions {
                tc_priority: priority,
                ..Default::default()
            };
            assert!(
                conf.validate().is_err(),
                "Priority {} should be invalid",
                priority
            );
        }
    }

    #[test]
    fn test_trace_id_timeout_duration_formats() {
        // Test various duration formats for trace_id_timeout
        Jail::expect_with(|jail| {
            let path = "trace_timeout.yaml";
            jail.create_file(
                path,
                r#"
span:
  trace_id_timeout: 2h
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");
            assert_eq!(cfg.span.trace_id_timeout, Duration::from_secs(7200)); // 2 hours

            Ok(())
        });

        Jail::expect_with(|jail| {
            let path = "trace_timeout2.yaml";
            jail.create_file(
                path,
                r#"
span:
  trace_id_timeout: 30m
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");
            assert_eq!(cfg.span.trace_id_timeout, Duration::from_secs(1800)); // 30 minutes

            Ok(())
        });

        Jail::expect_with(|jail| {
            let path = "trace_timeout3.hcl";
            jail.create_file(
                path,
                r#"
span {
    trace_id_timeout = "7d"
}
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");
            assert_eq!(cfg.span.trace_id_timeout, Duration::from_secs(604800)); // 7 days

            Ok(())
        });
    }

    #[test]
    fn test_trace_id_timeout_defaults_when_not_specified() {
        // Verify trace_id_timeout gets default value when not in config
        Jail::expect_with(|jail| {
            let path = "minimal_span.yaml";
            jail.create_file(
                path,
                r#"
span:
  tcp_timeout: 25s
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            // Should use default 24h even though not specified
            assert_eq!(cfg.span.trace_id_timeout, Duration::from_secs(86400));
            // But custom tcp_timeout should be applied
            assert_eq!(cfg.span.tcp_timeout, Duration::from_secs(25));

            Ok(())
        });
    }

    #[test]
    fn test_env_function_in_hcl() {
        Jail::expect_with(|jail| unsafe {
            std::env::set_var("TEST_ENV_VAR", "test_value");
            std::env::set_var("ANOTHER_TEST_VAR", "another_value");

            let path = "env_test.hcl";
            jail.create_file(
                path,
                r#"
# Test env function with various scenarios
discovery "instrument" {
    interfaces = [env("TEST_ENV_VAR")]
}

# Test env with default value
log_level = env("MISSING_VAR", "info")

# Test env without default (should use empty string)
auto_reload = env("MISSING_BOOL_VAR") == ""

# Test interpolation syntax
internal {
    server {
        listen_address = "prefix-${env("ANOTHER_TEST_VAR")}-suffix"
        port = 8080
    }
    # Test env with existing variable and default (should use env value)
    metrics {
        listen_address = env("ANOTHER_TEST_VAR", "fallback")
        port = 9090
    }
}
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load with env function");

            // Verify env function results
            assert_eq!(cfg.discovery.instrument.interfaces, vec!["test_value"]);
            assert_eq!(cfg.log_level, Level::INFO);
            assert_eq!(cfg.auto_reload, true);
            assert_eq!(
                cfg.internal.server.listen_address,
                "prefix-another_value-suffix"
            );
            assert_eq!(cfg.internal.metrics.listen_address, "another_value");

            std::env::remove_var("TEST_ENV_VAR");
            std::env::remove_var("ANOTHER_TEST_VAR");

            Ok(())
        });
    }

    #[test]
    fn test_pipeline_capacities_override() {
        Jail::expect_with(|jail| {
            let path = "pipeline_cap.yaml";
            jail.create_file(
                path,
                r#"
    pipeline:
      flow_producer:
        flow_span_queue_capacity: 1024
      k8s_decorator:
        decorated_span_queue_capacity: 2048
                    "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert_eq!(cfg.pipeline.flow_producer.flow_span_queue_capacity, 1024);
            assert_eq!(
                cfg.pipeline.k8s_decorator.decorated_span_queue_capacity,
                2048
            );

            Ok(())
        });
    }

    #[test]
    fn test_memory_usage_validation_logic() {
        //  Estimated memory usage: 312.6 MB with defaults
        let opts = PipelineOptions::default();

        assert!(
            opts.validate_memory_usage_against_limit(1_073_741_824),
            "Should be safe with 1GB memory"
        );

        assert!(
            !opts.validate_memory_usage_against_limit(268_435_456),
            "Should warn with 256MB memory (estimated usage exceeds 80% threshold)"
        );

        assert!(
            opts.validate_memory_usage_against_limit(536_870_912),
            "Should be safe with 512MB memory"
        );
    }
}
