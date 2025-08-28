use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::runtime::conf::conf_serde::duration;

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
#[derive(Debug, Deserialize, Serialize)]
pub struct FlowConf {
    /// The interval between checks for expired flows.
    /// Adjusting this parameter can group more flows into a single NetFlow packet
    /// or increase efficiency by reducing expiration checks.
    /// - Default Value: `10s`
    /// - Example: If set to `10s`, the system will check every 10 seconds for flows that are ready to be sent.
    #[serde(default = "defaults::expiry_interval", with = "duration")]
    pub expiry_interval: Duration,

    /// The maximum time-to-live for an active flow.
    /// Flows will be forcefully terminated after this period, regardless of their state.
    /// - Default Value: `60s`
    /// - Example: If set to `60s`, an active flow exceeding 60 seconds will be forcibly recorded and stopped.
    #[serde(default = "defaults::max_active_life", with = "duration")]
    pub max_active_life: Duration,

    /// A general time-to-live for all types of network connections
    /// unless overridden by specific rules for the traffic type (e.g., TCP, UDP, ICMP).
    /// - Default Value: `30s`
    /// - Example: If a flow remains inactive for 30 seconds, its record will be generated.
    #[serde(default = "defaults::flow_generic", with = "duration")]
    pub flow_generic: Duration,

    /// The time-to-live for ICMP flows. If no activity is observed within this period,
    /// a record will be generated.
    /// - Default Value: `10s`
    /// - Example: If set to `10s`, an ICMP flow with no activity for 10 seconds will be recorded.
    #[serde(default = "defaults::icmp", with = "duration")]
    pub icmp: Duration,

    /// The time-to-live for general TCP flows. This is used for connections that are still open
    /// without specific termination signals (e.g., FIN or RST).
    /// - Default Value: `20s`
    /// - Example: A TCP flow with no activity for 20 seconds will have a record generated.
    #[serde(default = "defaults::tcp", with = "duration")]
    pub tcp: Duration,

    /// The time-to-live applied to TCP flows when a FIN (finish) flag is observed.
    /// This indicates the connection is being gracefully closed.
    /// - Default Value: `5s`
    /// - Example: A TCP flow will have a record generated 5 seconds after both endpoints send a FIN packet.
    #[serde(default = "defaults::tcp_fin", with = "duration")]
    pub tcp_fin: Duration,

    /// The time-to-live applied to TCP flows when a RST (reset) flag is observed.
    /// This indicates a connection termination, typically in error or unexpectedly.
    /// - Default Value: `5s`
    /// - Example: A flow will have a record generated 5 seconds after a RST flag is detected.
    #[serde(default = "defaults::tcp_rst", with = "duration")]
    pub tcp_rst: Duration,

    /// The time-to-live for UDP flows. Since UDP is connectionless,
    /// this determines how long inactive flows are tracked before being recorded.
    /// - Default Value: `20s`
    /// - Example: A UDP flow with no activity for 20 seconds will have a record generated.
    #[serde(default = "defaults::udp", with = "duration")]
    pub udp: Duration,
}

impl Default for FlowConf {
    fn default() -> FlowConf {
        FlowConf {
            expiry_interval: defaults::expiry_interval(),
            max_active_life: defaults::max_active_life(),
            flow_generic: defaults::flow_generic(),
            icmp: defaults::icmp(),
            tcp: defaults::tcp(),
            tcp_fin: defaults::tcp_fin(),
            tcp_rst: defaults::tcp_rst(),
            udp: defaults::udp(),
        }
    }
}

mod defaults {
    use std::time::Duration;

    pub fn expiry_interval() -> Duration {
        Duration::from_secs(10)
    }
    pub fn max_active_life() -> Duration {
        Duration::from_secs(300) // 5 minutes - better for long-lived connections
    }
    pub fn flow_generic() -> Duration {
        Duration::from_secs(60) // 1 minute - more reasonable for enterprise
    }
    pub fn icmp() -> Duration {
        Duration::from_secs(30) // 30 seconds - ICMP can have longer intervals
    }
    pub fn tcp() -> Duration {
        Duration::from_secs(120) // 2 minutes - better for enterprise TCP connections
    }
    pub fn tcp_fin() -> Duration {
        Duration::from_secs(10) // 10 seconds - allow time for FIN handshake
    }
    pub fn tcp_rst() -> Duration {
        Duration::from_secs(5) // 5 seconds - RST should be quick
    }
    pub fn udp() -> Duration {
        Duration::from_secs(60) // 1 minute - UDP flows can be longer in enterprise
    }
}
