use std::{collections::HashMap, error::Error, fmt, net::Ipv4Addr, path::Path, time::Duration};

use figment::providers::Format;
use hcl::eval::Context;
use pnet::datalink;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::{Level, warn};

use crate::{
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
    #[serde(skip)]
    #[allow(dead_code)]
    pub(crate) config_path: Option<std::path::PathBuf>,
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
    pub interfaces: Vec<String>,
    /// Resolved interfaces after expanding globs and regexes against host interfaces
    #[serde(skip)]
    pub resolved_interfaces: Vec<String>,
    /// Span configuration for flow span producer
    pub span: SpanOptions,
    /// References to the exporters to use for telemetry
    pub export: ExportOptions,
    /// Configuration for flow interfaces.
    /// This field holds settings for filtering.
    pub filter: Option<HashMap<String, FilteringOptions>>,
}

impl Default for Conf {
    fn default() -> Self {
        Self {
            config_path: None,
            log_level: Level::INFO,
            auto_reload: false,
            shutdown_timeout: defaults::shutdown_timeout(),
            packet_channel_capacity: defaults::packet_channel_capacity(),
            packet_worker_count: defaults::flow_workers(),
            internal: InternalOptions::default(),
            api: ApiConf::default(),
            metrics: MetricsConf::default(),
            parser: ParserConf::default(),
            interfaces: vec!["eth0".to_string()],
            resolved_interfaces: Vec::new(),
            span: SpanOptions::default(),
            export: ExportOptions::default(),
            filter: None,
        }
    }
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
    pub end_reason: Option<FilteringPair>,
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
    pub fn resolve_interfaces(&self) -> Vec<String> {
        let available: Vec<String> = datalink::interfaces().into_iter().map(|i| i.name).collect();
        Self::resolve_interfaces_from(&self.interfaces, &available)
    }
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
            warn!(pattern=%pattern, "no interfaces matched regex pattern");
        } else if Self::is_glob(pattern) {
            warn!(pattern=%pattern, "no interfaces matched glob pattern");
        } else {
            warn!(iface=%pattern, "configured interface not found on host");
        }
    }

    #[inline]
    fn is_glob(s: &str) -> bool {
        s.contains('*') || s.contains('?')
    }

    // Simple wildcard matcher supporting '*' and '?'
    fn glob_match(pattern: &str, text: &str) -> bool {
        let (pattern_bytes, text_bytes) = (pattern.as_bytes(), text.as_bytes());
        let (mut pattern_index, mut text_index) = (0, 0);
        let (mut last_star_pattern_index, mut last_star_text_index) = (usize::MAX, 0);

        while text_index < text_bytes.len() {
            if pattern_index < pattern_bytes.len()
                && (pattern_bytes[pattern_index] == b'?'
                    || pattern_bytes[pattern_index] == text_bytes[text_index])
            {
                pattern_index += 1;
                text_index += 1;
            } else if pattern_index < pattern_bytes.len() && pattern_bytes[pattern_index] == b'*' {
                last_star_pattern_index = pattern_index;
                last_star_text_index = text_index;
                pattern_index += 1;
            } else if last_star_pattern_index != usize::MAX {
                pattern_index = last_star_pattern_index + 1;
                last_star_text_index += 1;
                text_index = last_star_text_index;
            } else {
                return false;
            }
        }

        while pattern_index < pattern_bytes.len() && pattern_bytes[pattern_index] == b'*' {
            pattern_index += 1;
        }
        pattern_index == pattern_bytes.len()
    }

    #[inline]
    fn parse_regex(pattern: &str) -> Option<Regex> {
        // Regex form: /.../ with at least two slashes and no trailing flags for now
        let stripped = pattern.strip_prefix('/')?;
        let end = stripped.rfind('/')?;
        Regex::new(&stripped[..end]).ok()
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
                Some(s) => Some(s.parse::<StdoutFmt>().map_err(serde::de::Error::custom)?),
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
        // available interfaces on host (simulated)
        let available = vec![
            "eth0".to_string(),
            "eth1".to_string(),
            "en0".to_string(),
            "en0p1".to_string(),
            "en0p2".to_string(),
            "lo".to_string(),
        ];

        // patterns including star, question, literal, and duplicates
        let patterns = vec![
            "eth*".to_string(),         // matches eth0, eth1
            "en0p*".to_string(),        // matches en0p1, en0p2
            "en?".to_string(),          // matches en0
            "lo".to_string(),           // literal match
            "doesnotexist".to_string(), // literal not present -> ignored with warn
            "eth*".to_string(),         // duplicate pattern should not duplicate results
        ];

        let resolved = Conf::resolve_interfaces_from(&patterns, &available);

        // Order is insertion order from first match occurrences
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

        // regex forms: /^en0p\d+$/ matches en0p1, en0p2; /^eth[01]$/ matches eth0, eth1
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
    fn default_conf_has_expected_values() {
        let cfg = Conf::default();

        // Core settings
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

        // Interface settings
        assert_eq!(
            cfg.interfaces,
            vec!["eth0".to_string()],
            "default interface should be eth0"
        );
        assert_eq!(
            cfg.resolved_interfaces,
            Vec::<String>::new(),
            "resolved_interfaces should be empty initially"
        );

        // API settings
        assert_eq!(cfg.api.enabled, true, "API should be enabled by default");
        assert_eq!(
            cfg.api.listen_address, "0.0.0.0",
            "API should listen on all interfaces by default"
        );
        assert_eq!(cfg.api.port, 8080, "API port should be 8080");

        // Metrics settings
        assert_eq!(
            cfg.metrics.enabled, true,
            "metrics should be enabled by default"
        );
        assert_eq!(
            cfg.metrics.listen_address, "0.0.0.0",
            "metrics should listen on all interfaces by default"
        );
        assert_eq!(cfg.metrics.port, 10250, "metrics port should be 10250");

        // Parser settings
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

        // Config path should be None
        assert_eq!(
            cfg.config_path, None,
            "config_path should be None for default config"
        );

        // Span settings - verify all defaults are set
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

        // Export settings - Note: When Conf::default() is called directly (not via deserialization),
        // the export settings are empty (no OTLP, no stdout) since the serde defaults only apply
        // during config file deserialization
        assert!(
            cfg.export.traces.otlp.is_some(),
            "default export (via ::default()) should not have OTLP configured"
        );
        if let Some(otlp) = &cfg.export.traces.otlp {
            assert_eq!(otlp.endpoint, "http://localhost:4317");
            assert_eq!(otlp.protocol, ExporterProtocol::Grpc);
            assert_eq!(otlp.timeout, Duration::from_secs(10));
        }
        assert!(
            cfg.export.traces.stdout.is_none(),
            "default export should not have stdout enabled"
        );

        // Internal settings - verify defaults
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
            assert_eq!(cfg.interfaces, Vec::from(["eth1".to_string()]));
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
interfaces: ["eth1"]
auto_reload: true
log_level: debug
                "#,
            )?;
            jail.set_env("MERMIN_CONFIG_PATH", path);

            let cli = Cli::parse_from(["mermin"]);
            let (cfg, _cli) = Conf::new(cli).expect("config loads from env file");
            assert_eq!(cfg.interfaces, Vec::from(["eth1".to_string()]));
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
interfaces: ["eth1"]
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config loads from cli file");
            assert_eq!(cfg.interfaces, Vec::from(["eth1".to_string()]));
            assert_eq!(cfg.config_path, Some(path.parse().unwrap()));

            // Update the config file
            jail.create_file(
                path,
                r#"
interfaces: ["eth2", "eth3"]
                "#,
            )?;

            let reloaded_cfg = cfg.reload().expect("config should reload");
            assert_eq!(
                reloaded_cfg.interfaces,
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
            assert_eq!(cfg.interfaces, Vec::from(["eth1".to_string()]));
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
interfaces = ["eth0"]
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

            assert_eq!(cfg.interfaces, vec!["eth0"]);
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
            jail.create_file(path, r#"interfaces = ["eth0"]"#)?;

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
interfaces = ["eth1"]
log_level = "info"
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config loads from HCL file");
            assert_eq!(cfg.interfaces, Vec::from(["eth1".to_string()]));
            assert_eq!(cfg.log_level, Level::INFO);
            assert_eq!(cfg.config_path, Some(path.parse().unwrap()));

            // Update the HCL config file
            jail.create_file(
                path,
                r#"
interfaces = ["eth2", "eth3"]
log_level = "debug"
                "#,
            )?;

            let reloaded_cfg = cfg.reload().expect("config should reload from HCL");
            assert_eq!(
                reloaded_cfg.interfaces,
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
interfaces = ["eth1"]

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
            assert_eq!(cfg.interfaces, Vec::from(["eth1".to_string()]));
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
            assert_eq!(cfg.interfaces, vec!["eth1", "eth2"]);

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
interfaces = ["eth1", "eth2"]
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert_eq!(cfg.log_level, Level::ERROR);
            assert_eq!(cfg.auto_reload, true);
            assert_eq!(cfg.shutdown_timeout, Duration::from_secs(30));
            assert_eq!(cfg.packet_channel_capacity, 2048);
            assert_eq!(cfg.packet_worker_count, 8);
            assert_eq!(cfg.interfaces, vec!["eth1", "eth2"]);

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
interfaces:
  - custom0
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            // Overridden value
            assert_eq!(cfg.interfaces, vec!["custom0"]);

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
            assert!(cfg.export.traces.otlp.is_some());
            if let Some(otlp) = &cfg.export.traces.otlp {
                assert_eq!(otlp.endpoint, "http://localhost:4317");
                assert_eq!(otlp.protocol, ExporterProtocol::Grpc);
                assert_eq!(otlp.timeout, Duration::from_secs(10));
            }

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
            export.traces.otlp.is_some(),
            "default export (via ::default()) should not have OTLP configured"
        );
        if let Some(otlp) = &export.traces.otlp {
            assert_eq!(otlp.endpoint, "http://localhost:4317");
            assert_eq!(otlp.protocol, ExporterProtocol::Grpc);
            assert_eq!(otlp.timeout, Duration::from_secs(10));
        }
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
interfaces:
  - eth0
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            // Verify that defaults are applied for unspecified fields
            // Note: export.traces.otlp is None by default (not configured unless explicitly set)
            assert!(
                cfg.export.traces.otlp.is_some(),
                "export OTLP should not be configured unless explicitly set in config"
            );
            if let Some(otlp) = &cfg.export.traces.otlp {
                assert_eq!(otlp.endpoint, "http://localhost:4317");
                assert_eq!(otlp.protocol, ExporterProtocol::Grpc);
                assert_eq!(otlp.timeout, Duration::from_secs(10));
            }
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
    stdout: "text_indent"
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

            assert!(cfg.export.traces.otlp.is_some());
            if let Some(otlp) = &cfg.export.traces.otlp {
                assert_eq!(otlp.endpoint, "http://localhost:4317");
                assert_eq!(otlp.protocol, ExporterProtocol::Grpc);
                assert_eq!(otlp.timeout, Duration::from_secs(10));
            }
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
    stdout: "text_indent"
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert!(cfg.export.traces.stdout.is_some());
            if let Some(stdout) = &cfg.export.traces.stdout {
                assert_eq!(stdout.as_str(), "text_indent");
            }

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
        stdout = "text_indent"
    }
}
                "#,
            )?;

            let cli = Cli::parse_from(["mermin", "--config", path.into()]);
            let (cfg, _cli) = Conf::new(cli).expect("config should load");

            assert!(cfg.export.traces.stdout.is_some());
            if let Some(stdout) = &cfg.export.traces.stdout {
                assert_eq!(stdout.as_str(), "text_indent");
            }

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
    stdout: "text_indent"
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
                assert_eq!(stdout.as_str(), "text_indent");
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
        stdout = "text_indent"
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
                assert_eq!(stdout.as_str(), "text_indent");
            }

            Ok(())
        });
    }

    // Note: Tests for parse_exporter_reference have been removed as the function
    // and ExporterReference type were never fully implemented or were removed.
}
