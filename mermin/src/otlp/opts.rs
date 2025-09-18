use std::time::Duration;

use opentelemetry_otlp::Protocol;
use serde::{Deserialize, Serialize};

use crate::runtime::conf::conf_serde::duration;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ExporterOptions {
    pub otlp_enabled: bool,
    pub stdout_enabled: bool,
    pub otlp_endpoint: String,
    pub otlp_timeout_seconds: u64,
    pub otlp_protocol: String,
}

impl Default for ExporterOptions {
    fn default() -> Self {
        ExporterOptions {
            stdout_enabled: false,
            otlp_enabled: false,
            otlp_endpoint: "http://host.docker.internal:4317".to_string(),
            otlp_timeout_seconds: 3, // TODO: convert to Duration that uses human readable format
            otlp_protocol: "grpc".to_string(),
        }
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
