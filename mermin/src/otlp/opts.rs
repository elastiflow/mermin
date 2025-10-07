use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose};
use opentelemetry_otlp::Protocol;
use serde::{Deserialize, Serialize};

use crate::runtime::conf::conf_serde::exporter_protocol;

/// Configuration options for all telemetry exporters used by the application.
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
/// exporter:
///   otlp:
///     main:
///       address: example.com
///       port: 4317
///       # ... other OTLP options ...
///   stdout:
///     json:
///       format: full
///     console:
///       format: compact
/// ```
///
/// # Fields
/// - `otlp`: Optional map of OTLP exporter configurations, keyed by exporter name.
/// - `stdout`: Optional map of stdout exporter configurations, keyed by exporter name.
///
/// Exporter references in the agent configuration (e.g., `exporter.otlp.main`) must match
/// the keys defined in these maps.
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct ExporterOptions {
    /// OTLP (OpenTelemetry Protocol) exporter configurations, keyed by exporter name.
    pub otlp: Option<HashMap<String, OtlpExporterOptions>>,
    /// Stdout exporter configurations, keyed by exporter name.
    pub stdout: Option<HashMap<String, StdoutExporterOptions>>,
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
/// # Example (YAML)
/// ```yaml
/// exporter:
///   otlp:
///     main:
///       address: example.com
///       port: 4317
///       auth:
///         basic:
///           user: foo
///           pass: env("MY_SECRET_PASS")
///       tls:
///         enabled: true
///         insecure: false
///         ca_cert: /etc/certs/ca.crt
///         client_cert: /etc/certs/cert.crt
///         client_key: /etc/certs/cert.key
/// ```
///
/// # Fields
/// - `address`: The hostname or IP address of the OTLP collector or backend.
/// - `port`: The port number to connect to on the OTLP endpoint.
/// - `auth`: Optional authentication configuration (e.g., basic auth).
/// - `tls`: Optional TLS configuration for secure communication.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OtlpExporterOptions {
    #[serde(default = "defaults::address")]
    pub address: String,
    #[serde(default = "defaults::scheme")]
    pub scheme: String,
    #[serde(default = "defaults::port")]
    pub port: u16,
    #[serde(default = "defaults::protocol", with = "exporter_protocol")]
    pub protocol: ExporterProtocol,
    #[serde(default = "defaults::connection_timeout_ms")]
    pub connection_timeout_ms: u64,
    pub auth: Option<AuthOptions>,
    pub tls: Option<TlsOptions>,
}

/// Configuration options for an individual Stdout exporter instance.
///
/// This struct defines the parameters for configuring a Stdout exporter,
/// which outputs telemetry data (such as traces or metrics) directly to
/// the standard output (stdout) of the running process. This is useful
/// for debugging, development, or environments where logs are collected
/// from container or process output.
///
/// Each Stdout exporter is uniquely identified by a name in the configuration file,
/// and its settings are provided via this struct. The primary configurable field
/// is the output format, which determines how the telemetry data is rendered.
///
/// # Fields
/// - `format`: The output format for the exporter (e.g., "full", "compact", "json").
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct StdoutExporterOptions {
    /// The output format for the exporter (e.g., "full", "compact", "json", etc.).
    /// Note: Only "full" is supported.
    pub format: String,
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
/// to telemetry backends (such as OTLP collectors). It allows specifying whether
/// TLS is enabled, whether to skip certificate verification (insecure mode), and
/// provides fields for custom certificate authority (CA) certificates and client
/// certificates/keys for mutual TLS authentication.
///
/// # Fields
/// - `enabled`: If true, TLS is enabled for the exporter connection.
/// - `insecure`: If true, disables certificate verification (not recommended for production).
/// - `ca_cert`: Optional path to a custom CA certificate file for server verification.
/// - `client_cert`: Optional path to a client certificate file for mutual TLS.
/// - `client_key`: Optional path to a client private key file for mutual TLS.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TlsOptions {
    /// Enable TLS for the exporter connection.
    pub enabled: bool,
    /// Disable certificate verification (insecure mode).
    pub insecure: bool,
    /// Path to the CA certificate file for server verification.
    pub ca_cert: Option<String>,
    /// Path to the client certificate file for mutual TLS.
    pub client_cert: Option<String>,
    /// Path to the client private key file for mutual TLS.
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

impl OtlpExporterOptions {
    pub fn build_endpoint(&self) -> String {
        format!("{}://{}:{}", self.scheme, self.address, self.port)
    }
}

#[derive(Debug, Clone)]
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

mod defaults {
    use crate::otlp::opts::ExporterProtocol;

    pub fn address() -> String {
        "localhost".to_string()
    }
    pub fn port() -> u16 {
        4317
    }
    pub fn protocol() -> ExporterProtocol {
        ExporterProtocol::Grpc
    }
    pub fn scheme() -> String {
        "http".to_string()
    }
    pub fn connection_timeout_ms() -> u64 {
        10_000
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
