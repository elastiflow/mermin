use std::{collections::HashMap, time::Duration};

use base64::{Engine as _, engine::general_purpose};
use opentelemetry_otlp::Protocol;
use serde::{Deserialize, Serialize};

use crate::runtime::conf::conf_serde::{duration, exporter_protocol, stdout_fmt};

/// Configuration options for the Mermin traces exporter.
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
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct ExportOptions {
    pub traces: TracesExportOptions,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct TracesExportOptions {
    pub stdout: Option<StdoutExportOptions>,
    pub otlp: Option<OtlpExportOptions>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct StdoutExportOptions {
    #[serde(with = "stdout_fmt")]
    pub format: Option<StdoutFmt>,
}

impl Default for StdoutExportOptions {
    fn default() -> Self {
        Self {
            format: Some(StdoutFmt::TextIndent),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
            _ => StdoutFmt::TextIndent,
        }
    }
}

impl std::str::FromStr for StdoutFmt {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(s.to_string()))
    }
}

/// Configuration options for an individual OTLP exporter instance.
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
///       insecure_skip_verify = false
///       ca_cert = "/etc/certs/ca.crt"
///       client_cert = "/etc/certs/cert.crt"
///       client_key = "/etc/certs/cert.key"
///     }
///   }
/// }
/// ```
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OtlpExportOptions {
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
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    pub tls: Option<TlsOptions>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuthOptions {
    pub basic: Option<BasicAuthOptions>,
    pub bearer: Option<String>, // TODO: Add support for api_key, oauth2, mtls, etc. - ENG-120
}

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
    pub pass: String, // TODO: Support environment variable substitution - ENG-120
}

/// TLS configuration for secure exporter connections.
///
/// ## Automatic TLS behavior
///
/// - **https:// endpoints**: TLS is automatically enabled using system root certificates.
/// - **http:// endpoints**: No TLS unless explicitly configured via this struct.
///
/// ## Certificate verification
///
/// - **Custom CA**: Provide `ca_cert` to use a custom CA instead of system roots (for private CAs or self-signed certs).
/// - **Mutual TLS**: Provide both `client_cert` and `client_key` for mTLS authentication.
/// - **Skip verification**: Set `insecure_skip_verify: true` to disable certificate verification entirely.
///
/// WARNING: `insecure_skip_verify: true` disables all certificate verification and should ONLY be used
/// for development and testing. It cannot be combined with client certificates.
///
/// # Examples
///
/// ## Custom CA (recommended for self-signed certs)
/// ```yaml
/// tls:
///   ca_cert: /etc/certs/self-signed-ca.crt
///   client_cert: /etc/certs/client.crt  # optional, for mTLS
///   client_key: /etc/certs/client.key   # optional, for mTLS
/// ```
///
/// ## Skip verification (development only)
/// ```yaml
/// tls:
///   insecure_skip_verify: true
/// ```
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TlsOptions {
    /// Skip certificate and hostname verification. WARNING: development/testing only; vulnerable to MITM.
    pub insecure_skip_verify: Option<bool>,
    /// Path to a CA certificate file. Overrides system root certificates.
    pub ca_cert: Option<String>,
    /// Path to a client certificate file for mutual TLS. Must be paired with `client_key`.
    pub client_cert: Option<String>,
    /// Path to a client private key file for mutual TLS. Must be paired with `client_cert`.
    pub client_key: Option<String>,
}

impl AuthOptions {
    pub fn generate_auth_headers(&self) -> Result<HashMap<String, String>, String> {
        let mut headers = HashMap::new();

        if let Some(basic) = &self.basic {
            let credentials =
                general_purpose::STANDARD.encode(format!("{}:{}", basic.user, basic.pass));
            headers.insert("Authorization".to_string(), format!("Basic {credentials}"));
        }

        if let Some(bearer) = &self.bearer {
            headers.insert("Authorization".to_string(), format!("Bearer {bearer}"));
        }

        // TODO: Add support for other auth methods like api_key, oauth2, mtls, etc. - ENG-120

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

    use crate::otlp::opts::ExporterProtocol;

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
        1024
    }
    pub fn max_batch_interval() -> Duration {
        Duration::from_secs(2)
    }
    pub fn max_queue_size() -> usize {
        32768
    }
    pub fn max_concurrent_exports() -> usize {
        4
    }
    pub fn max_export_timeout() -> Duration {
        Duration::from_secs(10)
    }
}

#[cfg(test)]
mod tests {
    use serde_json;

    use super::*;

    #[test]
    fn test_exporter_protocol_serialization() {
        let grpc = ExporterProtocol::Grpc;
        let serialized = serde_json::to_string(&grpc).unwrap();
        assert_eq!(serialized, "\"grpc\"");

        let http_binary = ExporterProtocol::HttpBinary;
        let serialized = serde_json::to_string(&http_binary).unwrap();
        assert_eq!(serialized, "\"http_binary\"");
    }

    #[test]
    fn test_exporter_protocol_deserialization() {
        let deserialized: ExporterProtocol = serde_json::from_str("\"grpc\"").unwrap();
        assert!(matches!(deserialized, ExporterProtocol::Grpc));

        let deserialized: ExporterProtocol = serde_json::from_str("\"http_binary\"").unwrap();
        assert!(matches!(deserialized, ExporterProtocol::HttpBinary));

        let deserialized: ExporterProtocol = serde_json::from_str("\"GRPC\"").unwrap();
        assert!(matches!(deserialized, ExporterProtocol::Grpc));

        let deserialized: ExporterProtocol = serde_json::from_str("\"invalid\"").unwrap();
        assert!(matches!(deserialized, ExporterProtocol::Grpc));
    }

    #[test]
    fn test_exporter_protocol_display() {
        assert_eq!(ExporterProtocol::Grpc.to_string(), "grpc");
        assert_eq!(ExporterProtocol::HttpBinary.to_string(), "http_binary");
    }
}
