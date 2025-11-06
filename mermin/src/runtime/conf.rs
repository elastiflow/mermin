use std::{collections::HashMap, error::Error, fmt, net::Ipv4Addr, path::Path, time::Duration};

use figment::providers::Format;
use hcl::eval::Context;
use pnet::datalink;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::{Level, info, warn};

use crate::{
    k8s::owner_relations::OwnerRelationsOptions,
    netns::NetnsSwitch,
    otlp::opts::ExportOptions,
    runtime::{
        conf::conf_serde::{duration, level},
        opts::InternalOptions,
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
    /// Path to the configuration file that was loaded
    ///
    /// This field is not serialized and must be regenerated when loading configuration.
    #[serde(skip)]
    pub config_path: Option<std::path::PathBuf>,
    /// Resolved interfaces after expanding globs and regexes against host interfaces.
    ///
    /// This field is populated during `Conf::new()` and `Conf::reload()` by expanding
    /// the patterns in `discovery.instrument.interfaces` against available network
    /// interfaces on the host. The resolution happens once per config load/reload cycle.
    ///
    /// This field is not serialized and must be regenerated when loading configuration.
    #[serde(skip)]
    pub resolved_interfaces: Vec<String>,
    #[serde(with = "level")]
    pub log_level: Level,
    pub auto_reload: bool,
    #[serde(with = "duration")]
    pub shutdown_timeout: Duration,
    pub packet_channel_capacity: usize,
    pub packet_worker_count: usize,
    /// Contains the configuration for internal exporters
    pub internal: InternalOptions,
    pub api: ApiConf,
    pub metrics: MetricsConf,
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
    #[serde(default)]
    pub attributes: HashMap<String, HashMap<String, AttributesConf>>,
}

impl Default for Conf {
    fn default() -> Self {
        Self {
            config_path: None,
            resolved_interfaces: Vec::new(),
            log_level: Level::INFO,
            auto_reload: false,
            shutdown_timeout: defaults::shutdown_timeout(),
            packet_channel_capacity: defaults::packet_channel_capacity(),
            packet_worker_count: defaults::flow_workers(),
            internal: InternalOptions::default(),
            api: ApiConf::default(),
            metrics: MetricsConf::default(),
            parser: ParserConf::default(),
            span: SpanOptions::default(),
            discovery: DiscoveryConf::default(),
            export: ExportOptions::default(),
            filter: None,
            attributes: HashMap::new(),
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

        let resolved_interfaces = conf.resolve_interfaces();
        conf.config_path = config_path_to_store;
        conf.resolved_interfaces = resolved_interfaces;

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

        let resolved_interfaces = conf.resolve_interfaces();
        conf.config_path = self.config_path.clone();
        conf.resolved_interfaces = resolved_interfaces;

        Ok(conf)
    }

    /// Expand interface patterns (supports '*' and '?') into concrete interface names.
    ///
    /// This method lists interfaces from the host network namespace when running in
    /// a Kubernetes pod. Requires hostPID: true and CAP_SYS_ADMIN capability.
    ///
    /// # Panics (production only)
    ///
    /// In non-test builds, panics if namespace switching fails to ensure proper
    /// configuration. This is intentional to fail fast if:
    /// - hostPID: true is not set in pod spec
    /// - CAP_SYS_ADMIN capability is not granted
    /// - /proc/1/ns/net is not accessible
    ///
    /// In test builds, gracefully falls back to current namespace.
    pub fn resolve_interfaces(&self) -> Vec<String> {
        let available: Vec<String> = {
            #[cfg(not(test))]
            {
                // Production: fail fast if namespace switching doesn't work
                let netns_switch = NetnsSwitch::new().expect(
                    "failed to initialize network namespace switching - ensure hostPID: true is set and CAP_SYS_ADMIN capability is granted",
                );

                let available: Vec<String> = netns_switch
                    .in_host_namespace(Some("interface_discovery"), || {
                        Ok(datalink::interfaces()
                            .into_iter()
                            .map(|i| i.name)
                            .collect::<Vec<String>>())
                    })
                    .expect("failed to list interfaces from host network namespace");

                info!(
                    event.name = "config.interfaces_available",
                    interface_count = available.len(),
                    interfaces = ?available,
                    namespace = "host",
                    "available interfaces in host network namespace"
                );

                available
            }

            #[cfg(test)]
            {
                // Tests: gracefully fall back to current namespace
                match NetnsSwitch::new() {
                    Ok(netns_switch) => {
                        match netns_switch.in_host_namespace(Some("interface_discovery"), || {
                            Ok(datalink::interfaces()
                                .into_iter()
                                .map(|i| i.name)
                                .collect::<Vec<String>>())
                        }) {
                            Ok(interfaces) => {
                                info!(
                                    event.name = "config.interfaces_available",
                                    interface_count = interfaces.len(),
                                    interfaces = ?interfaces,
                                    namespace = "host",
                                    "[TEST] available interfaces in host network namespace"
                                );
                                interfaces
                            }
                            Err(_) => {
                                let interfaces =
                                    datalink::interfaces().into_iter().map(|i| i.name).collect();
                                interfaces
                            }
                        }
                    }
                    Err(_) => {
                        // Expected in tests - use current namespace
                        let interfaces = datalink::interfaces()
                            .into_iter()
                            .map(|i| i.name)
                            .collect::<Vec<String>>();
                        info!(
                            event.name = "config.interfaces_available",
                            interface_count = interfaces.len(),
                            interfaces = ?interfaces,
                            namespace = "current",
                            "[TEST] available interfaces in current network namespace"
                        );
                        interfaces
                    }
                }
            }
        };

        let patterns = if self.discovery.instrument.interfaces.is_empty() {
            info!(
                event.name = "config.interfaces_empty",
                "no interfaces configured, using default patterns"
            );
            &InstrumentConf::default().interfaces
        } else {
            &self.discovery.instrument.interfaces
        };

        let resolved = Self::resolve_interfaces_from(patterns, &available);

        info!(
            event.name = "config.interfaces_resolved",
            interface_count = resolved.len(),
            interfaces = ?resolved,
            patterns = ?patterns,
            "resolved interfaces from patterns"
        );

        resolved
    }

    /// Resolves interface patterns into concrete interface names.
    ///
    /// Supports three pattern types:
    /// 1. **Literal matches**: `"eth0"` matches exactly `"eth0"`
    /// 2. **Glob patterns**: `"eth*"` matches `"eth0"`, `"eth1"`, etc. using `*` and `?` wildcards
    /// 3. **Regex patterns**: `"/^eth\d+$/"` matches `"eth0"`, `"eth1"` using full regex syntax
    ///
    /// Duplicate interfaces are automatically deduplicated while preserving
    /// order of first occurrence. Patterns that match no interfaces will
    /// generate a warning log but won't cause an error.
    ///
    /// # Arguments
    ///
    /// - `patterns` - List of interface patterns to match against
    /// - `available` - List of available interface names on the host
    ///
    /// # Returns
    ///
    /// Vector of unique interface names that matched any of the patterns,
    /// in order of first match occurrence.
    fn resolve_interfaces_from(patterns: &[String], available: &[String]) -> Vec<String> {
        use std::collections::HashSet;
        let mut resolved = Vec::new();
        let mut seen = HashSet::new();

        for pattern in patterns {
            let matches = Self::find_matches(pattern, available);

            if matches.is_empty() {
                Self::warn_no_match(pattern);
            }

            for interface in matches {
                if seen.insert(interface) {
                    resolved.push(interface.to_string());
                }
            }
        }

        resolved
    }

    /// Finds all interfaces matching a given pattern.
    ///
    /// Determines the pattern type (regex, glob, or literal) and applies
    /// the appropriate matching algorithm.
    ///
    /// # Arguments
    ///
    /// - `pattern` - The pattern to match (literal, glob, or regex)
    /// - `available` - List of available interface names
    ///
    /// # Returns
    ///
    /// Vector of interface names that match the pattern
    fn find_matches<'a>(pattern: &str, available: &'a [String]) -> Vec<&'a str> {
        if let Some(re) = Self::parse_regex(pattern) {
            available
                .iter()
                .filter(|name| re.is_match(name))
                .map(String::as_str)
                .collect()
        } else if Self::is_glob(pattern) {
            available
                .iter()
                .filter(|name| Self::glob_match(pattern, name))
                .map(String::as_str)
                .collect()
        } else {
            available
                .iter()
                .filter(|name| name.as_str() == pattern)
                .map(String::as_str)
                .collect()
        }
    }

    fn warn_no_match(pattern: &str) {
        if Self::parse_regex(pattern).is_some() {
            warn!(
                event.name = "config.interface_not_found",
                config.interface.pattern = %pattern,
                "no interfaces matched configured regex pattern"
            );
        } else if Self::is_glob(pattern) {
            warn!(
                event.name = "config.interface_not_found",
                config.interface.pattern = %pattern,
                "no interfaces matched configured glob pattern"
            );
        } else {
            warn!(
                event.name = "config.interface_not_found",
                config.interface.name = %pattern,
                "configured interface was not found on the host"
            );
        }
    }

    /// Determines if a pattern string should be treated as a glob pattern.
    ///
    /// Returns `true` if the pattern contains wildcard characters (`*` or `?`).
    #[inline]
    fn is_glob(s: &str) -> bool {
        s.contains('*') || s.contains('?')
    }

    /// Matches a glob pattern against text using `*` and `?` wildcards.
    ///
    /// - `*` matches zero or more bytes
    /// - `?` matches exactly one byte
    ///
    /// **Important**: This function operates at the byte level, not the character level.
    /// For ASCII text, one byte equals one character. For UTF-8 encoded text (e.g., Unicode),
    /// a single character may be multiple bytes, so `?` will not match a single Unicode
    /// character unless it's ASCII.
    ///
    /// Uses a backtracking algorithm with byte-level operations for efficiency.
    /// The algorithm tracks the position of the last `*` encountered to enable
    /// backtracking when a mismatch occurs.
    ///
    /// # Arguments
    ///
    /// - `pattern` - The glob pattern to match
    /// - `text` - The text to match against
    ///
    /// # Returns
    ///
    /// `true` if the text matches the pattern, `false` otherwise
    fn glob_match(pattern: &str, text: &str) -> bool {
        // Sentinel value indicating no '*' wildcard has been encountered yet
        const NO_STAR_SEEN: usize = usize::MAX;

        let (pattern_bytes, text_bytes) = (pattern.as_bytes(), text.as_bytes());
        let (mut pattern_index, mut text_index) = (0, 0);
        let (mut last_star_pattern_index, mut last_star_text_index) = (NO_STAR_SEEN, 0);

        while text_index < text_bytes.len() {
            if pattern_index < pattern_bytes.len()
                && (pattern_bytes[pattern_index] == b'?'
                    || pattern_bytes[pattern_index] == text_bytes[text_index])
            {
                // Direct match or '?' wildcard - advance both indices
                pattern_index += 1;
                text_index += 1;
            } else if pattern_index < pattern_bytes.len() && pattern_bytes[pattern_index] == b'*' {
                // Found '*' - record position for potential backtracking
                last_star_pattern_index = pattern_index;
                last_star_text_index = text_index;
                pattern_index += 1;
            } else if last_star_pattern_index != NO_STAR_SEEN {
                // Mismatch but we have a previous '*' - backtrack and try matching more text with '*'
                pattern_index = last_star_pattern_index + 1;
                last_star_text_index += 1;
                text_index = last_star_text_index;
            } else {
                // Mismatch with no '*' to backtrack to
                return false;
            }
        }

        // Consume any trailing '*' patterns which match empty string
        while pattern_index < pattern_bytes.len() && pattern_bytes[pattern_index] == b'*' {
            pattern_index += 1;
        }
        // Pattern matches if we've consumed all pattern characters
        pattern_index == pattern_bytes.len()
    }

    /// Parses a regex pattern from the format `/pattern/`.
    ///
    /// Returns `Some(Regex)` if the pattern is valid regex syntax surrounded by '/',
    /// otherwise returns `None`.
    ///
    /// # Security Note
    ///
    /// To prevent ReDoS (Regular Expression Denial of Service) attacks, this function
    /// enforces a maximum pattern length. Overly complex regex patterns are rejected
    /// with a warning log.
    ///
    /// # Pattern Format
    ///
    /// The pattern must be in the format `/regex_pattern/` where:
    /// - Starts with `/`
    /// - Ends with `/`
    /// - Contains valid regex syntax between the slashes
    ///
    /// # Examples
    ///
    /// - `/^eth\d+$/` - Valid regex pattern matching eth followed by digits
    /// - `/^(en|eth)[0-9]+$/` - Valid regex with alternation
    /// - `eth0` - Not a regex (no slashes), returns `None`
    /// - `/[unclosed/` - Invalid regex syntax, returns `None`
    #[inline]
    fn parse_regex(pattern: &str) -> Option<Regex> {
        // Maximum regex pattern length to prevent ReDoS attacks
        const MAX_REGEX_LENGTH: usize = 256;

        // Regex form: /.../ with at least two slashes and no trailing flags for now
        let stripped = pattern.strip_prefix('/')?;
        let end = stripped.rfind('/')?;
        let regex_pattern = &stripped[..end];

        // Prevent overly complex regex patterns that could cause DoS
        if regex_pattern.len() > MAX_REGEX_LENGTH {
            warn!(
                event.name = "config.regex_too_long",
                pattern_length = regex_pattern.len(),
                max_length = MAX_REGEX_LENGTH,
                "regex pattern exceeds maximum length and will be ignored"
            );
            return None;
        }

        Regex::new(regex_pattern).ok()
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
    pub instrument: InstrumentConf,
    /// Informer discovery configuration
    pub informer: Option<InformerDiscoveryConf>,
}

/// Instrumentation configuration for network interfaces
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct InstrumentConf {
    /// Network interfaces to monitor
    pub interfaces: Vec<String>,
}

impl Default for InstrumentConf {
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
                "cni*".to_string(),     // Flannel interfaces
                "cali*".to_string(),    // Calico workload interfaces
                "cilium_*".to_string(), // Cilium overlay interfaces
                "lxc*".to_string(),     // Cilium pod interfaces
                "gke*".to_string(),     // GKE-specific interfaces
                "eni*".to_string(),     // AWS VPC CNI interfaces
                "azure*".to_string(),   // Azure CNI interfaces
                "ovn-k8s*".to_string(), // OVN-Kubernetes interfaces
            ],
        }
    }
}

/// Informer discovery configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct InformerDiscoveryConf {
    /// Kubernetes informer configuration
    pub k8s: Option<K8sInformerConf>,
}

/// Kubernetes informer configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct K8sInformerConf {
    /// Owner relations configuration
    pub owner_relations: Option<OwnerRelationsOptions>,
    /// Selector-based resource relations configuration
    ///
    /// If None or an empty list, selector-based matching is disabled.
    /// Rules are required for selector matching to function.
    pub selector_relations: Option<Vec<SelectorRelationRule>>,
}

/// Configuration for a single selector-based resource relation rule
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SelectorRelationRule {
    /// The kind of resource that contains the selector (e.g., "NetworkPolicy", "Service")
    /// Case insensitive
    pub kind: String,
    /// The kind of resource to match against (e.g., "Pod")
    /// Case insensitive
    pub to: String,
    /// JSON path to the matchLabels field in the source resource
    /// Example: "spec.podSelector.matchLabels" or "spec.selector"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector_match_labels_field: Option<String>,
    /// JSON path to the matchExpressions field in the source resource
    /// Example: "spec.podSelector.matchExpressions"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector_match_expressions_field: Option<String>,
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
                Ok(match opt {
                    Some(s) => Some(s.parse::<Level>().map_err(serde::de::Error::custom)?),
                    None => None,
                })
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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
/// Defines the configuration for associating network flows with Kubernetes objects.
pub struct AttributesConf {
    /// Defines metadata to extract from all Kubernetes objects.
    pub extract: ExtractConf,
    /// Defines rules for mapping flow attributes to Kubernetes object attributes.
    pub association: AssociationBlock,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
/// Configuration for metadata extraction from Kubernetes objects.
pub struct ExtractConf {
    /// A list of metadata fields to extract.
    pub metadata: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
/// Defines association rules for different Kubernetes object kinds.
pub struct AssociationBlock {
    #[serde(default)]
    pub pod: Option<ObjectAssociationRule>,
    #[serde(default)]
    pub node: Option<ObjectAssociationRule>,
    #[serde(default)]
    pub service: Option<ObjectAssociationRule>,
    #[serde(default)]
    pub networkpolicy: Option<ObjectAssociationRule>,
    #[serde(default)]
    pub endpoint: Option<ObjectAssociationRule>,
    #[serde(default)]
    pub endpointslice: Option<ObjectAssociationRule>,
    #[serde(default)]
    pub ingress: Option<ObjectAssociationRule>,
    #[serde(default)]
    pub gateway: Option<ObjectAssociationRule>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
/// Represents the association rules for a specific Kubernetes object kind.
pub struct ObjectAssociationRule {
    /// A list of sources to match against for association.
    pub sources: Vec<AssociationSource>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
/// Defines a single association rule mapping a flow attribute to Kubernetes object fields.
pub struct AssociationSource {
    /// The origin of the attribute (e.g., "flow").
    pub from: String,
    /// The specific attribute name (e.g., "source.ip").
    pub name: String,
    /// A list of Kubernetes object fields to match against.
    pub to: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FilteringOptions {
    pub address: Option<FilteringPair>,
    pub port: Option<FilteringPair>,
    pub transport: Option<FilteringPair>,
    #[serde(rename = "type")]
    pub type_: Option<FilteringPair>,
    pub interface_name: Option<FilteringPair>,
    pub interface_index: Option<FilteringPair>,
    pub interface_mac: Option<FilteringPair>,
    pub connection_state: Option<FilteringPair>,
    pub ip_dscp_name: Option<FilteringPair>,
    pub ip_ecn_name: Option<FilteringPair>,
    pub ip_ttl: Option<FilteringPair>,
    pub ip_flow_label: Option<FilteringPair>,
    pub icmp_type_name: Option<FilteringPair>,
    pub icmp_code_name: Option<FilteringPair>,
    pub tcp_flags: Option<FilteringPair>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FilteringPair {
    #[serde(default, rename = "match")]
    pub match_glob: String,
    #[serde(default, rename = "not_match")]
    pub not_match_glob: String,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use clap::Parser;
    use figment::Jail;
    use tracing::Level;

    use super::{ApiConf, Conf, MetricsConf, ParserConf};
    use crate::{
        otlp::opts::{ExportOptions, ExporterProtocol},
        runtime::{cli::Cli, opts::InternalOptions},
        span::opts::SpanOptions,
    };

    #[test]
    fn resolve_interfaces_supports_globs_and_literals() {
        let available = vec![
            "eth0".to_string(),
            "eth1".to_string(),
            "en0".to_string(),
            "en0p1".to_string(),
            "en0p2".to_string(),
            "lo".to_string(),
        ];

        let patterns = vec![
            "eth*".to_string(),
            "en0p*".to_string(),
            "en?".to_string(),
            "lo".to_string(),
            "doesnotexist".to_string(),
            "eth*".to_string(),
        ];

        let resolved = Conf::resolve_interfaces_from(&patterns, &available);

        assert_eq!(
            resolved,
            vec![
                "eth0".to_string(),
                "eth1".to_string(),
                "en0p1".to_string(),
                "en0p2".to_string(),
                "en0".to_string(),
                "lo".to_string(),
            ]
        );
    }

    #[test]
    fn resolve_interfaces_supports_regex() {
        let available = vec![
            "eth0".to_string(),
            "eth1".to_string(),
            "en0".to_string(),
            "en0p1".to_string(),
            "en0p2".to_string(),
            "lo".to_string(),
        ];

        let patterns = vec!["/^en0p\\d+$/".to_string(), "/^eth[01]$/".to_string()];

        let resolved = Conf::resolve_interfaces_from(&patterns, &available);
        assert_eq!(
            resolved,
            vec![
                "en0p1".to_string(),
                "en0p2".to_string(),
                "eth0".to_string(),
                "eth1".to_string(),
            ]
        );
    }

    #[test]
    fn empty_interfaces_falls_back_to_defaults() {
        let available = vec![
            "eth0".to_string(),
            "eth1".to_string(),
            "ens0".to_string(),
            "en0".to_string(),
            "cni0".to_string(),
            "flannel0".to_string(),
            "cali0".to_string(),
            "tunl0".to_string(),
            "cilium_0".to_string(),
            "lxc0".to_string(),
            "gke0".to_string(),
            "eni0".to_string(),
            "vlan0".to_string(),
            "br0".to_string(),
            "tun0".to_string(),
            "ovn-k8s0".to_string(),
            "br-0".to_string(),
            "lo".to_string(),
            "ip6tnl0".to_string(),
        ];

        let patterns: Vec<String> = vec![];
        let resolved = Conf::resolve_interfaces_from(&patterns, &available);

        assert_eq!(resolved, Vec::<String>::new());

        let mut conf = Conf::default();
        conf.discovery.instrument.interfaces = vec![];

        let default_patterns = super::InstrumentConf::default().interfaces;
        let resolved_with_defaults = Conf::resolve_interfaces_from(&default_patterns, &available);

        assert_eq!(
            resolved_with_defaults,
            vec![
                "tunl0".to_string(),
                "ip6tnl0".to_string(),
                "flannel0".to_string(),
                "cali0".to_string(),
                "cilium_0".to_string(),
                "lxc0".to_string(),
                "gke0".to_string(),
                "eni0".to_string(),
                "ovn-k8s0".to_string(),
            ]
        );
    }

    #[test]
    fn cni_bridge_patterns_match_correctly() {
        let gke_interfaces = vec![
            "eth0".to_string(),
            "gke52aa5df9a5f".to_string(),
            "gkeaac0ffd348e".to_string(),
            "cilium_net".to_string(),
            "cilium_host".to_string(),
            "lxc12345".to_string(),
        ];
        let gke_patterns = vec![
            "gke*".to_string(),
            "cilium_*".to_string(),
            "lxc*".to_string(),
        ];
        let resolved = Conf::resolve_interfaces_from(&gke_patterns, &gke_interfaces);
        assert_eq!(
            resolved,
            vec![
                "gke52aa5df9a5f".to_string(),
                "gkeaac0ffd348e".to_string(),
                "cilium_net".to_string(),
                "cilium_host".to_string(),
                "lxc12345".to_string(),
            ],
            "GKE Cilium pattern should match gke*, cilium_*, lxc*"
        );

        let eks_interfaces = vec![
            "eth0".to_string(),
            "eni1a2b3c4d".to_string(),
            "eni9f8e7d6c".to_string(),
            "vlan.eth.1".to_string(),
        ];
        let eks_patterns = vec!["eni*".to_string(), "vlan*".to_string()];
        let resolved = Conf::resolve_interfaces_from(&eks_patterns, &eks_interfaces);
        assert_eq!(
            resolved,
            vec![
                "eni1a2b3c4d".to_string(),
                "eni9f8e7d6c".to_string(),
                "vlan.eth.1".to_string(),
            ],
            "EKS pattern should match eni*, vlan*"
        );

        let flannel_interfaces = vec![
            "eth0".to_string(),
            "cni0".to_string(),
            "flannel.1".to_string(),
            "veth123abc".to_string(),
        ];
        let flannel_patterns = vec!["cni*".to_string(), "flannel*".to_string()];
        let resolved = Conf::resolve_interfaces_from(&flannel_patterns, &flannel_interfaces);
        assert_eq!(
            resolved,
            vec!["cni0".to_string(), "flannel.1".to_string()],
            "Flannel pattern should match cni*, flannel*"
        );

        let calico_interfaces = vec![
            "eth0".to_string(),
            "cali123abc".to_string(),
            "cali456def".to_string(),
            "tunl0".to_string(),
            "vxlan.calico".to_string(),
        ];
        let calico_patterns = vec![
            "cali*".to_string(),
            "tunl*".to_string(),
            "vxlan*".to_string(),
        ];
        let resolved = Conf::resolve_interfaces_from(&calico_patterns, &calico_interfaces);
        assert_eq!(
            resolved,
            vec![
                "cali123abc".to_string(),
                "cali456def".to_string(),
                "tunl0".to_string(),
                "vxlan.calico".to_string(),
            ],
            "Calico pattern should match cali*, tunl*, vxlan*"
        );

        let ovn_interfaces = vec![
            "eth0".to_string(),
            "ovn-k8s-mp0".to_string(),
            "br-int".to_string(),
            "br-ex".to_string(),
        ];
        let ovn_patterns = vec!["ovn-k8s*".to_string(), "br-*".to_string()];
        let resolved = Conf::resolve_interfaces_from(&ovn_patterns, &ovn_interfaces);
        assert_eq!(
            resolved,
            vec![
                "ovn-k8s-mp0".to_string(),
                "br-int".to_string(),
                "br-ex".to_string(),
            ],
            "OpenShift OVN pattern should match ovn-k8s*, br-*"
        );
    }

    #[test]
    fn wildcard_matches_all_interfaces() {
        let available = vec![
            "eth0".to_string(),
            "cni0".to_string(),
            "docker0".to_string(),
            "veth123".to_string(),
            "lo".to_string(),
        ];

        let patterns = vec!["*".to_string()];
        let resolved = Conf::resolve_interfaces_from(&patterns, &available);

        assert_eq!(
            resolved, available,
            "Wildcard * should match all interfaces"
        );
    }

    #[test]
    fn wildcard_matches_all_cni_interfaces() {
        let available = vec![
            "cni0".to_string(),
            "flannel.1".to_string(),
            "cali123abc".to_string(),
            "tunl0".to_string(),
            "cilium_net".to_string(),
            "lxc12345".to_string(),
            "gke52aa5df9a5f".to_string(),
            "eni1a2b3c4d".to_string(),
            "vlan.eth.1".to_string(),
            "br-int".to_string(),
            "tun0".to_string(),
            "ovn-k8s-mp0".to_string(),
            "br-ex".to_string(),
        ];

        let pattern = "*";
        let resolved = Conf::find_matches(pattern, &available);

        let resolved_owned: Vec<String> = resolved.iter().map(|s| s.to_string()).collect();

        assert_eq!(
            resolved_owned, available,
            "Wildcard * should match all CNI/Kubernetes interfaces"
        );
    }

    #[test]
    fn default_patterns_work_across_environments() {
        let cloud_interfaces = vec![
            "cni0".to_string(),
            "gke123".to_string(),
            "cilium_net".to_string(),
        ];
        let defaults = super::InstrumentConf::default().interfaces;
        let resolved = Conf::resolve_interfaces_from(&defaults, &cloud_interfaces);
        assert!(
            resolved.contains(&"gke123".to_string())
                && resolved.contains(&"cilium_net".to_string()),
            "Default patterns should match cni*, gke*, cilium_* in cloud"
        );

        let onprem_interfaces = vec!["eth0".to_string(), "lo".to_string(), "docker0".to_string()];
        let resolved = Conf::resolve_interfaces_from(&defaults, &onprem_interfaces);
        assert!(
            !resolved.contains(&"cni0".to_string()),
            "Default patterns should not match cni* on on-prem"
        );
    }

    #[test]
    fn patterns_are_deduplicated() {
        let available = vec!["eth0".to_string(), "eth1".to_string(), "ens0".to_string()];

        let patterns = vec![
            "eth*".to_string(),
            "eth0".to_string(),
            "eth*".to_string(),
            "e*".to_string(),
        ];

        let resolved = Conf::resolve_interfaces_from(&patterns, &available);

        assert_eq!(
            resolved,
            vec!["eth0".to_string(), "eth1".to_string(), "ens0".to_string()],
            "Interfaces should be deduplicated"
        );
    }

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
            cfg.packet_channel_capacity, 1024,
            "packet_channel_capacity should be 1024"
        );
        assert_eq!(
            cfg.packet_worker_count, 2,
            "packet_worker_count should be 2"
        );

        assert_eq!(
            cfg.discovery.instrument.interfaces,
            vec![
                "veth*".to_string(),
                "tunl*".to_string(),
                "ip6tnl*".to_string(),
                "vxlan*".to_string(),
                "flannel*".to_string(),
                "cni*".to_string(),
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
            cfg.resolved_interfaces,
            Vec::<String>::new(),
            "resolved_interfaces should be empty initially"
        );

        assert_eq!(cfg.api.enabled, true, "API should be enabled by default");
        assert_eq!(
            cfg.api.listen_address, "0.0.0.0",
            "API should listen on all interfaces by default"
        );
        assert_eq!(cfg.api.port, 8080, "API port should be 8080");

        assert_eq!(
            cfg.metrics.enabled, true,
            "metrics should be enabled by default"
        );
        assert_eq!(
            cfg.metrics.listen_address, "0.0.0.0",
            "metrics should listen on all interfaces by default"
        );
        assert_eq!(cfg.metrics.port, 10250, "metrics port should be 10250");

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
    fn loads_api_and_metrics_config_from_yaml_file() {
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
            assert_eq!(
                cfg.discovery.instrument.interfaces,
                Vec::from(["eth1".to_string()])
            );
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
discovery "instrument" {
    interfaces = ["eth0"]
}

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
            let (cfg, _cli) = Conf::new(cli).expect("config should load from HCL file");

            assert_eq!(cfg.discovery.instrument.interfaces, vec!["eth0"]);
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
    fn loads_api_and_metrics_config_from_hcl_file() {
        Jail::expect_with(|jail| {
            let path = "mermin_custom_api.hcl";

            jail.create_file(
                path,
                r#"
# Custom configuration for testing
discovery "instrument" {
    interfaces = ["eth1"]
}

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
            let (cfg, _cli) = Conf::new(cli).expect("config should load from HCL file");

            // Assert that all the custom values from the file were loaded correctly
            assert_eq!(
                cfg.discovery.instrument.interfaces,
                Vec::from(["eth1".to_string()])
            );
            assert_eq!(cfg.api.listen_address, "127.0.0.1");
            assert_eq!(cfg.api.port, 8081);
            assert_eq!(cfg.metrics.listen_address, "0.0.0.0");
            assert_eq!(cfg.metrics.port, 9090);

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
packet_channel_capacity: 2048
packet_worker_count: 8
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
            assert_eq!(cfg.packet_channel_capacity, 2048);
            assert_eq!(cfg.packet_worker_count, 8);
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
packet_channel_capacity = 2048
packet_worker_count = 8
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
            assert_eq!(cfg.packet_channel_capacity, 2048);
            assert_eq!(cfg.packet_worker_count, 8);
            assert_eq!(cfg.discovery.instrument.interfaces, vec!["eth1", "eth2"]);

            Ok(())
        });
    }

    #[test]
    fn override_api_settings_via_yaml() {
        Jail::expect_with(|jail| {
            let path = "override_api.yaml";
            jail.create_file(
                path,
                r#"
api:
  enabled: false
  listen_address: "127.0.0.1"
  port: 9000
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert_eq!(cfg.api.enabled, false);
            assert_eq!(cfg.api.listen_address, "127.0.0.1");
            assert_eq!(cfg.api.port, 9000);

            Ok(())
        });
    }

    #[test]
    fn override_api_settings_via_hcl() {
        Jail::expect_with(|jail| {
            let path = "override_api.hcl";
            jail.create_file(
                path,
                r#"
api {
    enabled = false
    listen_address = "127.0.0.1"
    port = 9000
}
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert_eq!(cfg.api.enabled, false);
            assert_eq!(cfg.api.listen_address, "127.0.0.1");
            assert_eq!(cfg.api.port, 9000);

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
metrics:
  enabled: false
  listen_address: "192.168.1.1"
  port: 9999
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert_eq!(cfg.metrics.enabled, false);
            assert_eq!(cfg.metrics.listen_address, "192.168.1.1");
            assert_eq!(cfg.metrics.port, 9999);

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
metrics {
    enabled = false
    listen_address = "192.168.1.1"
    port = 9999
}
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert_eq!(cfg.metrics.enabled, false);
            assert_eq!(cfg.metrics.listen_address, "192.168.1.1");
            assert_eq!(cfg.metrics.port, 9999);

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
            assert_eq!(cfg.packet_channel_capacity, 1024);
            assert_eq!(cfg.packet_worker_count, 2);
            assert_eq!(cfg.api.port, 8080);
            assert_eq!(cfg.metrics.port, 10250);
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
    fn default_api_conf_has_expected_values() {
        let api = ApiConf::default();

        assert_eq!(api.enabled, true, "API should be enabled by default");
        assert_eq!(
            api.listen_address, "0.0.0.0",
            "API should listen on all interfaces"
        );
        assert_eq!(api.port, 8080, "API default port should be 8080");
    }

    #[test]
    fn default_metrics_conf_has_expected_values() {
        let metrics = MetricsConf::default();

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
            assert_eq!(cfg.packet_channel_capacity, 1024);

            // Verify all span defaults
            assert_eq!(cfg.span.max_record_interval, Duration::from_secs(60));
            assert_eq!(cfg.span.generic_timeout, Duration::from_secs(30));
            assert_eq!(cfg.span.icmp_timeout, Duration::from_secs(10));
            assert_eq!(cfg.span.tcp_timeout, Duration::from_secs(20));
            assert_eq!(cfg.span.tcp_fin_timeout, Duration::from_secs(5));
            assert_eq!(cfg.span.tcp_rst_timeout, Duration::from_secs(5));
            assert_eq!(cfg.span.udp_timeout, Duration::from_secs(60));

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
        use crate::k8s::owner_relations::OwnerRelationsOptions;

        let conf = OwnerRelationsOptions::default();
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
    fn resolve_interfaces_empty_patterns() {
        let available = vec!["eth0".to_string(), "eth1".to_string()];
        let patterns = vec![];
        let resolved = Conf::resolve_interfaces_from(&patterns, &available);
        assert_eq!(
            resolved,
            Vec::<String>::new(),
            "empty pattern list should resolve to empty result"
        );
    }

    #[test]
    fn resolve_interfaces_empty_available() {
        let available = vec![];
        let patterns = vec!["eth*".to_string(), "en0".to_string()];
        let resolved = Conf::resolve_interfaces_from(&patterns, &available);
        assert_eq!(
            resolved,
            Vec::<String>::new(),
            "empty available list should resolve to empty result"
        );
    }

    #[test]
    fn resolve_interfaces_malformed_regex() {
        let available = vec!["eth0".to_string(), "eth1".to_string()];
        let patterns = vec!["/[unclosed/".to_string()];
        let resolved = Conf::resolve_interfaces_from(&patterns, &available);
        assert_eq!(
            resolved,
            Vec::<String>::new(),
            "malformed regex should resolve to empty result"
        );
    }

    #[test]
    fn resolve_interfaces_regex_without_closing_slash() {
        let available = vec!["eth0".to_string()];
        let patterns = vec!["/^eth0".to_string()];
        let resolved = Conf::resolve_interfaces_from(&patterns, &available);
        assert_eq!(
            resolved,
            Vec::<String>::new(),
            "regex without closing slash should resolve to empty result"
        );
    }

    #[test]
    fn resolve_interfaces_very_long_regex_pattern() {
        let available = vec!["eth0".to_string()];
        // Create a regex pattern longer than MAX_REGEX_LENGTH (256)
        let long_pattern = format!("/^({})+$/", "a".repeat(300));
        let patterns = vec![long_pattern];
        let resolved = Conf::resolve_interfaces_from(&patterns, &available);
        assert_eq!(
            resolved,
            Vec::<String>::new(),
            "overly long regex should be rejected"
        );
    }

    #[test]
    fn glob_match_single_star() {
        assert!(
            Conf::glob_match("*", "anything"),
            "single * should match anything"
        );
        assert!(
            Conf::glob_match("*", ""),
            "single * should match empty string"
        );
        assert!(
            Conf::glob_match("*", "multiple words"),
            "single * should match text with spaces"
        );
    }

    #[test]
    fn glob_match_multiple_consecutive_stars() {
        assert!(
            Conf::glob_match("**", "anything"),
            "** should match anything"
        );
        assert!(Conf::glob_match("***", "text"), "*** should match text");
        assert!(Conf::glob_match("a**b", "ab"), "a**b should match ab");
        assert!(Conf::glob_match("a**b", "axxxb"), "a**b should match axxxb");
    }

    #[test]
    fn glob_match_single_question_mark() {
        assert!(
            Conf::glob_match("?", "a"),
            "single ? should match single char"
        );
        assert!(
            !Conf::glob_match("?", ""),
            "single ? should not match empty string"
        );
        assert!(
            !Conf::glob_match("?", "ab"),
            "single ? should not match two chars"
        );
    }

    #[test]
    fn glob_match_multiple_question_marks() {
        assert!(Conf::glob_match("???", "abc"), "??? should match 3 chars");
        assert!(
            !Conf::glob_match("???", "ab"),
            "??? should not match 2 chars"
        );
        assert!(
            !Conf::glob_match("???", "abcd"),
            "??? should not match 4 chars"
        );
    }

    #[test]
    fn glob_match_trailing_star() {
        assert!(Conf::glob_match("eth*", "eth"), "eth* should match eth");
        assert!(Conf::glob_match("eth*", "eth0"), "eth* should match eth0");
        assert!(
            Conf::glob_match("eth*", "eth123"),
            "eth* should match eth123"
        );
    }

    #[test]
    fn glob_match_leading_star() {
        assert!(Conf::glob_match("*eth0", "eth0"), "*eth0 should match eth0");
        assert!(
            Conf::glob_match("*eth0", "myeth0"),
            "*eth0 should match myeth0"
        );
        assert!(
            !Conf::glob_match("*eth0", "eth0x"),
            "*eth0 should not match eth0x"
        );
    }

    #[test]
    fn glob_match_middle_star() {
        assert!(Conf::glob_match("a*b", "ab"), "a*b should match ab");
        assert!(Conf::glob_match("a*b", "aXb"), "a*b should match aXb");
        assert!(Conf::glob_match("a*b", "aXXXb"), "a*b should match aXXXb");
        assert!(!Conf::glob_match("a*b", "axc"), "a*b should not match axc");
    }

    #[test]
    fn glob_match_complex_patterns() {
        assert!(
            Conf::glob_match("en?p*", "en0p1"),
            "en?p* should match en0p1"
        );
        assert!(
            Conf::glob_match("en?p*", "en0p123"),
            "en?p* should match en0p123"
        );
        assert!(
            !Conf::glob_match("en?p*", "enp1"),
            "en?p* should not match enp1 (missing char for ?)"
        );
        assert!(
            !Conf::glob_match("en?p*", "en00p1"),
            "en?p* should not match en00p1 (too many chars for ?)"
        );
    }

    #[test]
    fn glob_match_unicode_support() {
        // The `*` wildcard works fine with Unicode since it matches zero or more bytes
        assert!(
            Conf::glob_match("eth*", "eth日本"),
            "* wildcard should handle unicode in text"
        );
        assert!(
            Conf::glob_match("*", "日本語"),
            "* should match unicode string"
        );

        // The `?` wildcard matches one BYTE, not one Unicode character.
        // "日" is 3 bytes in UTF-8 (0xE6 0x97 0xA5), so we need 3 `?` wildcards
        assert!(
            !Conf::glob_match("?", "日"),
            "single ? should NOT match multi-byte unicode char (only matches 1 byte)"
        );
        assert!(
            Conf::glob_match("???", "日"),
            "three ? wildcards should match 3-byte UTF-8 character"
        );

        // ASCII characters work fine with `?` since they're single-byte
        assert!(
            Conf::glob_match("?", "a"),
            "? should match single ASCII character (1 byte)"
        );
    }

    #[test]
    fn glob_match_empty_pattern_and_text() {
        assert!(
            Conf::glob_match("", ""),
            "empty pattern should match empty text"
        );
        assert!(
            !Conf::glob_match("", "a"),
            "empty pattern should not match non-empty text"
        );
        assert!(Conf::glob_match("*", ""), "* should match empty text");
    }

    #[test]
    fn resolve_interfaces_unicode_interface_names() {
        // While unlikely in practice, the system should handle it gracefully
        // The `*` wildcard works fine with Unicode since it matches at byte level
        let available = vec!["eth0".to_string(), "interface日本".to_string()];
        let patterns = vec!["interface*".to_string()];
        let resolved = Conf::resolve_interfaces_from(&patterns, &available);
        assert_eq!(
            resolved,
            vec!["interface日本".to_string()],
            "* wildcard should match interface names with Unicode characters"
        );
    }

    #[test]
    fn resolve_interfaces_preserves_first_match_order() {
        let available = vec![
            "eth0".to_string(),
            "eth1".to_string(),
            "en0".to_string(),
            "wlan0".to_string(),
        ];
        let patterns = vec![
            "wlan*".to_string(), // matches wlan0
            "eth*".to_string(),  // matches eth0, eth1
            "en*".to_string(),   // matches en0
        ];
        let resolved = Conf::resolve_interfaces_from(&patterns, &available);
        assert_eq!(
            resolved,
            vec![
                "wlan0".to_string(),
                "eth0".to_string(),
                "eth1".to_string(),
                "en0".to_string(),
            ],
            "should preserve order of first match"
        );
    }

    #[test]
    fn resolve_interfaces_mixed_pattern_types() {
        let available = vec![
            "eth0".to_string(),
            "eth1".to_string(),
            "en0".to_string(),
            "en0p1".to_string(),
            "en0p2".to_string(),
            "wlan0".to_string(),
        ];
        let patterns = vec![
            "wlan0".to_string(),      // literal
            "/^eth\\d$/".to_string(), // regex
            "en0p?".to_string(),      // glob
        ];
        let resolved = Conf::resolve_interfaces_from(&patterns, &available);
        assert_eq!(
            resolved,
            vec![
                "wlan0".to_string(),
                "eth0".to_string(),
                "eth1".to_string(),
                "en0p1".to_string(),
                "en0p2".to_string(),
            ],
            "should handle mixed literal, regex, and glob patterns"
        );
    }

    #[test]
    fn parse_regex_handles_special_characters() {
        assert!(Conf::parse_regex("/^eth[0-9]+$/").is_some());
        assert!(Conf::parse_regex("/^(eth|en)\\d+$/").is_some());
        assert!(Conf::parse_regex("/^eth.*$/").is_some());

        assert!(
            Conf::parse_regex("/^eth[0-9$/").is_none(),
            "unclosed bracket should fail"
        );
        assert!(
            Conf::parse_regex("/^eth(/").is_none(),
            "unclosed paren should fail"
        );
    }

    #[test]
    fn parse_regex_rejects_patterns_without_slashes() {
        assert!(Conf::parse_regex("eth0").is_none());
        assert!(Conf::parse_regex("^eth.*$").is_none());
        assert!(Conf::parse_regex("").is_none());
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
}
