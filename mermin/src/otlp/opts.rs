use std::{collections::HashMap, time::Duration};

use base64::{Engine as _, engine::general_purpose};
use opentelemetry_otlp::Protocol;
use serde::{Deserialize, Serialize};

use crate::runtime::conf::conf_serde::duration;

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
#[derive(Debug, Deserialize, Serialize, Clone)]
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
    pub address: String,
    pub port: u16,
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

// TODO: Implement environment variable substitution for authentication credentials - ENG-120
// This function should handle patterns like env("VAR_NAME") and replace them with actual env values
pub fn resolve_env_vars(value: &str) -> Result<String, String> {
    if value.starts_with("env(") && value.ends_with(')') {
        let env_var = &value[4..value.len() - 1]; // Remove "env(" and ")"
        std::env::var(env_var).map_err(|_| format!("Environment variable '{env_var}' not found"))
    } else {
        Ok(value.to_string())
    }
}

impl AuthOptions {
    // TODO: Implement authentication header generation for OTLP exporters - ENG-120
    // This should create appropriate headers based on the auth configuration
    pub fn generate_auth_headers(&self) -> Result<HashMap<String, String>, String> {
        let mut headers = HashMap::new();

        if let Some(basic) = &self.basic {
            let resolved_user = resolve_env_vars(&basic.user)?;
            let resolved_pass = resolve_env_vars(&basic.pass)?;
            let credentials =
                general_purpose::STANDARD.encode(format!("{resolved_user}:{resolved_pass}"));
            headers.insert("Authorization".to_string(), format!("Basic {credentials}"));
        }

        // TODO: Add support for other auth methods like bearer, api_key, oauth2, mtls, etc. - ENG-120

        Ok(headers)
    }
}

impl OtlpExporterOptions {
    // Helper function to build endpoint URL from address and port
    pub fn build_endpoint(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }
}

pub enum ExporterProtocol {
    Grpc,
    HttpProto,
}

impl From<ExporterProtocol> for Protocol {
    fn from(val: ExporterProtocol) -> Self {
        match val {
            ExporterProtocol::Grpc => Protocol::Grpc,
            ExporterProtocol::HttpProto => Protocol::HttpBinary,
        }
    }
}

impl From<String> for ExporterProtocol {
    fn from(value: String) -> Self {
        match value.to_lowercase().as_str() {
            "grpc" => ExporterProtocol::Grpc,
            "http_proto" => ExporterProtocol::HttpProto,
            _ => ExporterProtocol::Grpc,
        }
    }
}

/// The `FlowConf` struct represents the configuration parameters for managing flows in a system.
/// Each field specifies configurable time-to-live (TTL) values or intervals for different types
/// of network traffic flows. These configurations influence when flow records are generated and
/// how long active or inactive flows are tracked.
///
/// Example logic for generating flow records:
///
/// expiry_interval: 10 - Check every 10 seconds for flows records that are ready to send.
/// max_active_life: 60 - The longest an active traffic flow will be tracked before a record is generated is 60 secs.
/// flow_generic: 30 - If no activity has been observed for a flow in the last 30 seconds, generate a record. unless...
/// icmp: 10 - If no activity has been observed for an ICMP flow in the last 10 seconds, generate a record.
/// tcp: 20 - If no activity has been observed for a TCP flow in the last 20 seconds, generate a record. unless...
/// tcp-fin: 5 - If we see a FIN flag for a TCP flow, generate a record 5 secs after the flag.
/// tcp-rst: 5 - If we see an RST flag for a TCP flow, generate a record 5 secs after the flag.
/// udp: 20 - If no activity has been observed for a UDP flow in the last 20 seconds, generate a record.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SpanOptions {
    /// The maximum number of flow records in a batch.
    /// - Default Value: `64`
    /// - Example: If set to `64`, the system will flush a batch of 64 flow records to the output.
    #[serde(default = "defaults::max_batch_size")]
    pub max_batch_size: usize,

    /// The maxmimum interval when a batch of flow records is flushed to the output.
    /// - Default Value: `10s`
    /// - Example: If set to `10s`, the system will flush a batch of flow records to the output every 10 seconds if the batch size is not reached.
    #[serde(default = "defaults::max_batch_interval", with = "duration")]
    pub max_batch_interval: Duration,

    /// The maximum interval between records for an active flow.
    /// - Default Value: `60s`
    /// - Example: If set to `60s`, a flow record will be generated if the flow has been active for 60 seconds, but has not timed out.
    #[serde(default = "defaults::max_record_interval", with = "duration")]
    pub max_record_interval: Duration,

    /// A general timeout for all types of network connections
    /// unless overridden by specific rules for the traffic type (e.g., TCP, UDP, ICMP).
    /// A flow is dropped when a flow has not seen any activity for the timeout period.
    /// Typically, this a flow timeout will generate a flow record, but if a flow has seen 0 packets, it will not generate a flow record.
    /// - Default Value: `30s`
    /// - Example: If set to `30s`, a flow record will be generated if flow packet count is not zero and the flow has not seen any activity for 30 seconds, then the flow will be dropped.
    #[serde(default = "defaults::generic_timeout", with = "duration")]
    pub generic_timeout: Duration,

    /// The timeout for ICMP flows.
    /// - Default Value: `10s`
    /// - Example: If set to `10s`, an ICMP flow with no activity for 10 seconds will be recorded.
    #[serde(default = "defaults::icmp_timeout", with = "duration")]
    pub icmp_timeout: Duration,

    /// The timeout for general TCP flows. This is used for connections that are still open
    /// without specific termination signals (e.g., FIN or RST).
    /// - Default Value: `20s`
    #[serde(default = "defaults::tcp_timeout", with = "duration")]
    pub tcp_timeout: Duration,

    /// The timeout applied to TCP flows when a FIN (finish) flag is observed.
    /// This indicates the connection is being gracefully closed.
    /// - Default Value: `5s`
    #[serde(default = "defaults::tcp_fin_timeout", with = "duration")]
    pub tcp_fin_timeout: Duration,

    /// The timeout applied to TCP flows when a RST (reset) flag is observed.
    /// This indicates a connection termination, typically in error or unexpectedly.
    /// - Default Value: `5s`
    #[serde(default = "defaults::tcp_rst_timeout", with = "duration")]
    pub tcp_rst_timeout: Duration,

    /// The timeout for UDP flows.
    /// - Default Value: `60s`
    #[serde(default = "defaults::udp_timeout", with = "duration")]
    pub udp_timeout: Duration,
}

impl Default for SpanOptions {
    fn default() -> SpanOptions {
        SpanOptions {
            max_batch_size: defaults::max_batch_size(),
            max_batch_interval: defaults::max_batch_interval(),
            max_record_interval: defaults::max_record_interval(),
            generic_timeout: defaults::generic_timeout(),
            icmp_timeout: defaults::icmp_timeout(),
            tcp_timeout: defaults::tcp_timeout(),
            tcp_fin_timeout: defaults::tcp_fin_timeout(),
            tcp_rst_timeout: defaults::tcp_rst_timeout(),
            udp_timeout: defaults::udp_timeout(),
        }
    }
}

mod defaults {
    use std::time::Duration;

    pub fn max_batch_size() -> usize {
        64
    }
    pub fn max_batch_interval() -> Duration {
        Duration::from_secs(5)
    }
    pub fn max_record_interval() -> Duration {
        Duration::from_secs(60)
    }
    pub fn generic_timeout() -> Duration {
        Duration::from_secs(30)
    }
    pub fn icmp_timeout() -> Duration {
        Duration::from_secs(10)
    }
    pub fn tcp_timeout() -> Duration {
        Duration::from_secs(20)
    }
    pub fn tcp_fin_timeout() -> Duration {
        Duration::from_secs(5)
    }
    pub fn tcp_rst_timeout() -> Duration {
        Duration::from_secs(5)
    }
    pub fn udp_timeout() -> Duration {
        Duration::from_secs(60)
    }
}
