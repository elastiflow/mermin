use std::{collections::HashMap, time::Duration};

use base64::{Engine as _, engine::general_purpose};
use opentelemetry_otlp::Protocol;
use serde::{Deserialize, Serialize};

use crate::runtime::conf::conf_serde::{duration, exporter_protocol, stdout_fmt};

/// Configuration options for the Mermin traces exporter.
///
/// This struct defines the top-level exporter configuration, allowing the user to specify
/// multiple exporter backends (such as OTLP and stdout) and their individual settings.
/// Each exporter type (e.g., OTLP, stdout) is represented as an optional map, where the key
/// is a unique exporter name (as referenced in the agent configuration), and the value is
/// the configuration for that specific exporter instance.
///
/// Exporters are responsible for sending telemetry data (such as traces and metrics)
/// to external systems. The configuration enables flexible selection and customization
/// of exporters, supporting scenarios where multiple exporters of the same type may be
/// defined and enabled independently.
///
/// # Example (YAML)
/// ```yaml
/// export:
///   traces:
///     otlp:
///       endpoint: http://example.com:4317
///       protocol: grpc
///     stdout: text_indent
/// ```
///
/// # Fields
/// - `traces`: Trace exporter configuration options.
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct ExportOptions {
    #[serde(default = "defaults::traces")]
    pub traces: TracesExportOptions,
}

/// Configuration options for trace exporters.
///
/// # Fields
/// - `otlp`: Optional OTLP exporter configuration.
/// - `stdout`: Optional stdout exporter format.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TracesExportOptions {
    /// Defines the format for a stdout exporter.
    #[serde(with = "stdout_fmt")]
    pub stdout: Option<StdoutFmt>,

    /// OTLP (OpenTelemetry Protocol) exporter configurations.
    pub otlp: Option<OtlpExporterOptions>,
}

impl Default for TracesExportOptions {
    fn default() -> Self {
        Self {
            stdout: None,
            otlp: defaults::otlp(),
        }
    }
}

/// StdoutFmt enum defines the format for a stdout exporter,
/// which outputs telemetry data (such as traces or metrics) directly to
/// the standard output (stdout) of the running process. This is useful
/// for debugging, development, or environments where logs are collected
/// from container or process output.
///
/// Note: Only "text_indent" is supported.
#[derive(Debug, Clone, Copy)]
pub enum StdoutFmt {
    // Text,
    TextIndent,
    // Json,
    // JsonIndent,
}

impl StdoutFmt {
    pub fn as_str(&self) -> &'static str {
        match self {
            // StdoutFmt::Text => "text",
            StdoutFmt::TextIndent => "text_indent",
            // StdoutFmt::Json => "json",
            // StdoutFmt::JsonIndent => "json_indent",
        }
    }
}

impl From<String> for StdoutFmt {
    fn from(value: String) -> Self {
        match value.to_lowercase().as_str() {
            // "text" => StdoutFmt::Text,
            "text_indent" => StdoutFmt::TextIndent,
            // "json" => StdoutFmt::Json,
            // "json_indent" => StdoutFmt::JsonIndent,
            _ => StdoutFmt::TextIndent, // Default to Text
        }
    }
}

impl std::str::FromStr for StdoutFmt {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(s.to_string()))
    }
}

/// Configuration options for an individual OTLP (OpenTelemetry Protocol) exporter instance.
///
/// This struct defines all the necessary parameters to configure an OTLP exporter,
/// which is responsible for sending telemetry data (such as traces and metrics)
/// to a remote OTLP-compatible backend (e.g., OpenTelemetry Collector, observability platforms).
///
/// Each OTLP exporter is uniquely identified by a name in the configuration file,
/// and its settings are provided via this struct. The fields allow for specifying
/// the network address and port of the OTLP endpoint, as well as optional authentication
/// and TLS (Transport Layer Security) settings.
///
/// # Example (HCL)
/// ```hcl
/// export "traces" {
///   otlp = {
///     endpoint = "http://otelcol:4317"
///     protocol = "grpc"
///     timeout = "10s"
///     max_batch_size = 512
///     max_batch_interval = "5s"
///     max_queue_size = 2048
///     max_concurrent_exports = 1
///     max_export_timeout = "30s"
///     auth = {
///       basic = {
///         user = "USERNAME"
///         pass = "PASSWORD"
///       }
///     }
///     tls = {
///       insecure = false
///       ca_cert = "/etc/certs/ca.crt"
///       client_cert = "/etc/certs/cert.crt"
///       client_key = "/etc/certs/cert.key"
///     }
///   }
/// }
/// ```
///
/// # Fields
/// - `endpoint`: The full OTLP endpoint URL (e.g., "http://localhost:4317")
/// - `protocol`: The OTLP protocol to use (grpc or http_binary)
/// - `timeout`: Request timeout duration
/// - `auth`: Optional authentication configuration (e.g., basic auth)
/// - `tls`: Optional TLS configuration for secure communication
/// - `max_batch_size`: Maximum number of spans to batch before export (default: 512)
/// - `max_batch_interval`: Maximum time to wait before exporting a batch (default: 5s)
/// - `max_queue_size`: Maximum queue size to buffer spans for delayed processing (default: 2048)
/// - `max_concurrent_exports`: Maximum number of concurrent exports (default: 1, experimental)
/// - `max_export_timeout`: Maximum duration to export a batch of data (default: 30s, experimental)
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OtlpExporterOptions {
    #[serde(default = "defaults::endpoint")]
    pub endpoint: String,
    #[serde(default = "defaults::protocol", with = "exporter_protocol")]
    pub protocol: ExporterProtocol,
    #[serde(default = "defaults::timeout", with = "duration")]
    pub timeout: Duration,
    #[serde(default = "defaults::max_batch_size")]
    pub max_batch_size: usize,
    #[serde(default = "defaults::max_batch_interval", with = "duration")]
    pub max_batch_interval: Duration,
    #[serde(default = "defaults::max_queue_size")]
    pub max_queue_size: usize,
    #[serde(default = "defaults::max_concurrent_exports")]
    pub max_concurrent_exports: usize,
    #[serde(default = "defaults::max_export_timeout", with = "duration")]
    pub max_export_timeout: Duration,
    pub auth: Option<AuthOptions>,
    pub tls: Option<TlsOptions>,
}

impl OtlpExporterOptions {
    /// Builds the full endpoint URL for the OTLP exporter.
    pub fn build_endpoint(&self) -> String {
        self.endpoint.clone()
    }
}

/// Authentication configuration for exporters.
///
/// This struct encapsulates the authentication options that can be used when connecting
/// to telemetry backends (such as OTLP collectors). It is designed to be extensible for
/// supporting multiple authentication mechanisms. Currently, it supports basic authentication
/// via the `basic` field, which allows specifying a username and password (with support for
/// environment variable substitution).
///
/// # Fields
/// - `basic`: Optional basic authentication configuration. If present, the exporter will use
///   HTTP Basic Auth with the provided credentials.
///
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuthOptions {
    pub basic: Option<BasicAuthOptions>,
    // TODO: Add support for bearer, api_key, oauth2, mtls, etc. - ENG-120
}

/// Configuration for HTTP Basic Authentication credentials.
///
/// This struct defines the username and password used for HTTP Basic Auth
/// when connecting to telemetry backends (such as OTLP exporters).
/// The fields support direct string values or, optionally, environment variable
/// substitution (e.g., `env("MY_PASSWORD_ENV_VAR")`) for secure secret management.
///
/// # Fields
/// - `user`: The username for authentication. Can be a plain string or an environment variable reference.
/// - `pass`: The password for authentication. Can be a plain string or an environment variable reference.
///
/// # Example (YAML)
/// ```yaml
/// auth:
///   basic:
///     user: foo
///     pass: env("MY_PASSWORD_ENV_VAR")
/// ```
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BasicAuthOptions {
    pub user: String,
    pub pass: String, // TODO: Support environment variable substitution like env("USER_SPECIFIED_ENV_VAR_TRITON_PASS") - ENG-120
}

/// TLS (Transport Layer Security) configuration for secure exporter connections.
///
/// This struct defines the options for enabling and customizing TLS when connecting
/// to telemetry backends (such as OTLP collectors).
///
/// # Automatic TLS Behavior
///
/// - **https:// endpoints**: TLS is automatically enabled using system root certificates
///   when an endpoint uses the `https://` scheme, even without an explicit `tls` configuration.
/// - **http:// endpoints**: No TLS is used unless explicitly configured via this struct.
///
/// # Certificate Verification
///
/// By default, TLS connections validate server certificates against system root certificates.
/// You can customize this behavior:
///
/// - **Custom CA**: Provide a `ca_cert` path to use a custom certificate authority
///   instead of system root certificates (useful for private CAs and self-signed certificates).
/// - **Mutual TLS**: Provide both `client_cert` and `client_key` for mutual TLS authentication.
/// - **Insecure Mode**: Set `insecure: true` to disable certificate verification entirely.
///
/// # Self-Signed Certificates
///
/// For self-signed certificates in production, use the `ca_cert` option to specify the self-signed
/// certificate or the CA that signed it. This is the recommended secure approach.
///
/// For development/testing environments where you want to skip verification entirely,
/// you can use `insecure: true`, but be aware this makes your connection vulnerable to
/// man-in-the-middle attacks.
///
/// # Insecure Mode
///
/// WARNING: Setting `insecure: true` disables all certificate verification and should ONLY
/// be used for development and testing purposes. In production, use the `ca_cert` option instead.
///
/// When insecure mode is enabled:
/// - Server certificates are not validated
/// - Any certificate will be accepted (including invalid, expired, or self-signed certificates)
/// - The connection is vulnerable to man-in-the-middle attacks
/// - Cannot be combined with client certificates (mutual TLS)
/// - A warning will be logged each time a connection is established
///
/// # Fields
/// - `insecure`: Disable certificate verification (insecure mode). WARNING: Only use for development/testing!
/// - `ca_cert`: Optional path to a custom CA certificate file (overrides system root certificates).
/// - `client_cert`: Optional path to a client certificate file for mutual TLS.
/// - `client_key`: Optional path to a client private key file for mutual TLS.
///
/// # Examples
///
/// ## Example 1: Custom CA for self-signed certificates (RECOMMENDED)
/// ```yaml
/// tls:
///   insecure: false
///   ca_cert: /etc/certs/self-signed-ca.crt  # Add your self-signed cert here
///   client_cert: /etc/certs/client.crt      # Optional: for mutual TLS
///   client_key: /etc/certs/client.key       # Optional: for mutual TLS
/// ```
///
/// ## Example 2: Insecure mode for development/testing (NOT for production!)
/// ```yaml
/// tls:
///   insecure: true  # Skip all certificate verification
/// ```
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TlsOptions {
    /// Disable certificate verification (insecure mode).
    /// WARNING: Only use for development/testing! Makes connections vulnerable to MITM attacks.
    /// Cannot be combined with client certificates.
    pub insecure: bool,
    /// Path to the CA certificate file for server verification.
    /// When provided, this overrides system root certificates.
    /// Use this for self-signed certificates by specifying your self-signed cert or CA.
    pub ca_cert: Option<String>,
    /// Path to the client certificate file for mutual TLS.
    /// Must be provided together with client_key.
    /// Cannot be used with insecure mode.
    pub client_cert: Option<String>,
    /// Path to the client private key file for mutual TLS.
    /// Must be provided together with client_cert.
    /// Cannot be used with insecure mode.
    pub client_key: Option<String>,
}

impl AuthOptions {
    // TODO: Implement authentication header generation for OTLP exporters - ENG-120
    // This should create appropriate headers based on the auth configuration
    pub fn generate_auth_headers(&self) -> Result<HashMap<String, String>, String> {
        let mut headers = HashMap::new();

        if let Some(basic) = &self.basic {
            let credentials =
                general_purpose::STANDARD.encode(format!("{}:{}", basic.user, basic.pass));
            headers.insert("Authorization".to_string(), format!("Basic {credentials}"));
        }

        // TODO: Add support for other auth methods like bearer, api_key, oauth2, mtls, etc. - ENG-120

        Ok(headers)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExporterProtocol {
    Grpc,
    HttpBinary,
}

impl serde::Serialize for ExporterProtocol {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            ExporterProtocol::Grpc => "grpc",
            ExporterProtocol::HttpBinary => "http_binary",
        };
        serializer.serialize_str(s)
    }
}

impl<'de> serde::Deserialize<'de> for ExporterProtocol {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(ExporterProtocol::from(s))
    }
}

impl From<ExporterProtocol> for Protocol {
    fn from(val: ExporterProtocol) -> Self {
        match val {
            ExporterProtocol::Grpc => Protocol::Grpc,
            ExporterProtocol::HttpBinary => Protocol::HttpBinary,
        }
    }
}

impl std::fmt::Display for ExporterProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExporterProtocol::Grpc => write!(f, "grpc"),
            ExporterProtocol::HttpBinary => write!(f, "http_binary"),
        }
    }
}

impl From<String> for ExporterProtocol {
    fn from(value: String) -> Self {
        match value.to_lowercase().as_str() {
            "grpc" => ExporterProtocol::Grpc,
            "http_binary" => ExporterProtocol::HttpBinary,
            _ => ExporterProtocol::Grpc,
        }
    }
}

pub mod defaults {
    use std::time::Duration;

    use crate::otlp::opts::{
        ExporterProtocol, OtlpExporterOptions, StdoutFmt, TracesExportOptions,
    };

    pub fn traces() -> TracesExportOptions {
        TracesExportOptions {
            otlp: otlp(),
            stdout: stdout(),
        }
    }

    pub fn otlp() -> Option<OtlpExporterOptions> {
        Some(OtlpExporterOptions {
            endpoint: endpoint(),
            protocol: protocol(),
            timeout: timeout(),
            auth: None,
            tls: None,
            max_batch_size: max_batch_size(),
            max_batch_interval: max_batch_interval(),
            max_queue_size: max_queue_size(),
            max_concurrent_exports: max_concurrent_exports(),
            max_export_timeout: max_export_timeout(),
        })
    }
    pub fn stdout() -> Option<StdoutFmt> {
        None
    }
    pub fn endpoint() -> String {
        "http://localhost:4317".to_string()
    }
    pub fn protocol() -> ExporterProtocol {
        ExporterProtocol::Grpc
    }
    pub fn timeout() -> Duration {
        Duration::from_secs(10)
    }
    pub fn max_batch_size() -> usize {
        512
    }
    pub fn max_batch_interval() -> Duration {
        Duration::from_secs(5)
    }
    pub fn max_queue_size() -> usize {
        2048
    }
    pub fn max_concurrent_exports() -> usize {
        1
    }
    pub fn max_export_timeout() -> Duration {
        Duration::from_millis(30000)
    }
}

#[cfg(test)]
mod tests {
    use serde_json;

    use super::*;

    #[test]
    fn test_exporter_protocol_serialization() {
        // Test Grpc variant
        let grpc = ExporterProtocol::Grpc;
        let serialized = serde_json::to_string(&grpc).unwrap();
        assert_eq!(serialized, "\"grpc\"");

        // Test HttpBinary variant
        let http_binary = ExporterProtocol::HttpBinary;
        let serialized = serde_json::to_string(&http_binary).unwrap();
        assert_eq!(serialized, "\"http_binary\"");
    }

    #[test]
    fn test_exporter_protocol_deserialization() {
        // Test grpc string
        let deserialized: ExporterProtocol = serde_json::from_str("\"grpc\"").unwrap();
        assert!(matches!(deserialized, ExporterProtocol::Grpc));

        // Test http_binary string
        let deserialized: ExporterProtocol = serde_json::from_str("\"http_binary\"").unwrap();
        assert!(matches!(deserialized, ExporterProtocol::HttpBinary));

        // Test case insensitive
        let deserialized: ExporterProtocol = serde_json::from_str("\"GRPC\"").unwrap();
        assert!(matches!(deserialized, ExporterProtocol::Grpc));

        // Test invalid value defaults to Grpc
        let deserialized: ExporterProtocol = serde_json::from_str("\"invalid\"").unwrap();
        assert!(matches!(deserialized, ExporterProtocol::Grpc));
    }

    #[test]
    fn test_exporter_protocol_display() {
        assert_eq!(ExporterProtocol::Grpc.to_string(), "grpc");
        assert_eq!(ExporterProtocol::HttpBinary.to_string(), "http_binary");
    }
}
