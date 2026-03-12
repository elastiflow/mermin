//! Span kind direction inference for network flows.
//!
//! This module determines the OpenTelemetry [`SpanKind`] for a flow — whether the
//! agent is observing the CLIENT side (connection initiator), the SERVER side
//! (connection receiver), or an INTERNAL flow where the role cannot be determined.
//!
//! # Inference Hierarchy
//!
//! The [`DirectionInferrer`] applies rules in priority order:
//!
//! 1. **Listen Port State** (most reliable): If either port matches a local listening
//!    port tracked in the eBPF map, the flow is SERVER-side.
//!
//! 2. **TCP Handshake Flags**: For TCP flows, analyzes SYN and SYN-ACK patterns:
//!    - Forward SYN + Reverse SYN-ACK → CLIENT
//!    - Forward SYN-ACK + Reverse SYN → SERVER
//!
//! 3. **Port Number Heuristic**: Higher port number is typically the client.
//!
//! 4. **ICMP Type-Based Logic**:
//!    - Request types (Echo Request, Timestamp Request, etc.) → CLIENT
//!    - Reply types (Echo Reply, Timestamp Reply, etc.) → SERVER
//!    - Error/informational types → INTERNAL
//!
//! 5. **Fallback**: If no rule matches, returns INTERNAL.
//!
//! # Examples
//!
//! ```no_run
//! use std::sync::Arc;
//! use std::time::Duration;
//! use tokio::sync::Mutex;
//! # use mermin::span::direction::DirectionInferrer;
//!
//! # async fn example(listening_ports_map: Arc<Mutex<aya::maps::HashMap<aya::maps::MapData, mermin_common::ListeningPortKey, u8>>>) {
//! let inferrer = DirectionInferrer::new(listening_ports_map);
//!
//! // Use inferrer to analyze flows and determine span kind...
//! # }
//! ```

use std::sync::Arc;

use aya::maps::HashMap as EbpfHashMap;
use mermin_common::{
    Direction, FlowKey, FlowStats, ListeningPortKey,
    ip::IpProto,
    tcp::{TCP_FLAG_ACK, TCP_FLAG_SYN},
};
use opentelemetry::trace::SpanKind;
use tokio::sync::Mutex;
use tracing::warn;

use crate::metrics::{
    self,
    ebpf::{EbpfMapName, EbpfMapOperation, EbpfMapStatus},
};

// ICMP (IPv4) Type Constants
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_TIMESTAMP_REQUEST: u8 = 13;
const ICMP_TIMESTAMP_REPLY: u8 = 14;
const ICMP_ADDRESS_MASK_REQUEST: u8 = 17;
const ICMP_ADDRESS_MASK_REPLY: u8 = 18;

// ICMPv6 Type Constants
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;
const ICMPV6_MLD_QUERY: u8 = 130;
const ICMPV6_MLD_REPORT: u8 = 131;

/// The inferred direction of a flow from the observer's perspective.
///
/// Corresponds to the OTel `flow.direction` semantic convention attribute and is
/// always consistent with [`SpanKind`]:
///
/// | `SpanKind` | `FlowDirection` |
/// |------------|-----------------|
/// | Client     | Forward         |
/// | Server     | Reverse         |
/// | Internal   | Unknown         |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowDirection {
    /// Traffic flows in the initiator→responder direction (client → server).
    Forward,
    /// Traffic flows in the responder→initiator direction (server → client).
    Reverse,
    /// Direction could not be reliably determined.
    Unknown,
}

impl FlowDirection {
    /// Returns the `flow.direction` attribute string value.
    pub fn as_str(self) -> &'static str {
        match self {
            FlowDirection::Forward => "forward",
            FlowDirection::Reverse => "reverse",
            FlowDirection::Unknown => "unknown",
        }
    }
}

impl From<SpanKind> for FlowDirection {
    fn from(kind: SpanKind) -> Self {
        match kind {
            SpanKind::Client => FlowDirection::Forward,
            SpanKind::Server => FlowDirection::Reverse,
            _ => FlowDirection::Unknown,
        }
    }
}

/// Direction inference engine
///
/// Determines whether a flow represents CLIENT, SERVER, or INTERNAL traffic
/// by analyzing listening ports, TCP handshake patterns, port numbers, and ICMP types.
pub struct DirectionInferrer {
    listening_ports_map: Arc<Mutex<EbpfHashMap<aya::maps::MapData, ListeningPortKey, u8>>>,
}

impl DirectionInferrer {
    pub fn new(
        listening_ports_map: Arc<Mutex<EbpfHashMap<aya::maps::MapData, ListeningPortKey, u8>>>,
    ) -> Self {
        Self {
            listening_ports_map,
        }
    }

    /// Infer the direction of a flow (CLIENT, SERVER, or INTERNAL)
    ///
    /// Applies the inference rule hierarchy described in the [module-level documentation](self)
    /// to determine the role of the observed endpoint. Returns the OpenTelemetry [`SpanKind`].
    #[must_use = "direction inference result must be used to set the span kind"]
    pub async fn infer_from_stats(&self, flow_key: &FlowKey, stats: &FlowStats) -> SpanKind {
        if let Some(kind) = self.check_listening_port(flow_key, stats).await {
            return kind;
        }

        if stats.protocol == IpProto::Tcp
            && let Some(kind) = Self::check_tcp_handshake(stats)
        {
            return kind;
        }

        if matches!(stats.protocol, IpProto::Tcp | IpProto::Udp)
            && let Some(kind) = Self::check_ephemeral_port(flow_key)
        {
            return kind;
        }

        if matches!(stats.protocol, IpProto::Icmp | IpProto::Ipv6Icmp)
            && let Some(kind) = Self::check_icmp_type(stats)
        {
            return kind;
        }

        SpanKind::Internal
    }

    /// Rule 1: Check if either port is in listening ports map, combined with direction
    ///
    /// Direction is essential here because the same port appearing in different
    /// positions combined with the flow's direction determines our role:
    ///
    /// - `dst_port` listening + Ingress → we are the server receiving a request
    /// - `src_port` listening + Egress  → we are the server sending a response
    /// - `dst_port` listening + Egress  → we are the client connecting to our own
    ///   server (loopback); return `SpanKind::Client`
    /// - `src_port` listening + Ingress → we are the client receiving a response from
    ///   our own server (loopback); return `SpanKind::Client`
    ///
    /// Returns `Some(SpanKind)` when a local listening port is matched,
    /// or `None` when neither port is in the map.
    async fn check_listening_port(
        &self,
        flow_key: &FlowKey,
        stats: &FlowStats,
    ) -> Option<SpanKind> {
        let map = self.listening_ports_map.lock().await;

        let lookup_port = |port: u16| -> bool {
            let key = ListeningPortKey {
                port,
                protocol: stats.protocol,
            };

            match map.get(&key, 0) {
                Ok(_) => {
                    metrics::registry::EBPF_MAP_OPS_TOTAL
                        .with_label_values(&[
                            EbpfMapName::ListeningPorts.as_str(),
                            EbpfMapOperation::Read.as_str(),
                            EbpfMapStatus::Ok.as_str(),
                        ])
                        .inc();
                    true
                }
                Err(e) => {
                    let is_not_found = matches!(
                        e,
                        aya::maps::MapError::KeyNotFound | aya::maps::MapError::ElementNotFound
                    );

                    let status = if is_not_found {
                        EbpfMapStatus::NotFound
                    } else {
                        EbpfMapStatus::Error
                    };

                    metrics::registry::EBPF_MAP_OPS_TOTAL
                        .with_label_values(&[
                            EbpfMapName::ListeningPorts.as_str(),
                            EbpfMapOperation::Read.as_str(),
                            status.as_str(),
                        ])
                        .inc();

                    if !is_not_found {
                        warn!(
                            event.name = "ebpf.map_read_failed",
                            map = EbpfMapName::ListeningPorts.as_str(),
                            error.message = %e,
                            "failed to read listening ports map"
                        );
                    }
                    false
                }
            }
        };

        if lookup_port(flow_key.dst_port) {
            return Some(match stats.direction {
                Direction::Ingress => SpanKind::Server,
                Direction::Egress => SpanKind::Client,
            });
        }

        if lookup_port(flow_key.src_port) {
            return Some(match stats.direction {
                Direction::Egress => SpanKind::Server,
                Direction::Ingress => SpanKind::Client,
            });
        }

        None
    }

    /// Rule 2: TCP Handshake Analysis using direction and flags
    ///
    /// Handles all 6 possible first-packet scenarios during the 3-way handshake,
    /// including late-start cases where Mermin begins observing mid-handshake.
    ///
    /// Note: Only examines the FIRST packet's flags (forward_tcp_flags). If Mermin
    /// starts observing mid-connection, this check will fail and fall through to
    /// ephemeral port heuristics.
    fn check_tcp_handshake(stats: &FlowStats) -> Option<SpanKind> {
        const SYN_ACK: u8 = TCP_FLAG_SYN | TCP_FLAG_ACK;

        let flags = stats.forward_tcp_flags;

        // Distinguish between SYN, SYN-ACK, and pure ACK (third handshake packet)
        let is_syn_only = (flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) == 0;
        let is_syn_ack = (flags & SYN_ACK) == SYN_ACK;
        // Pure ACK for third handshake packet - must not have other flags like PSH/FIN
        let is_ack_only = flags == TCP_FLAG_ACK;

        // CLIENT cases - we are the connection initiator
        //
        // Case 1: Egress SYN - We sent initial SYN (packet 1, we are source)
        // Case 2: Ingress SYN-ACK - We received server response (packet 2, we are destination)
        // Case 3: Egress ACK - We sent final ACK (packet 3, we are source)
        if (stats.direction == Direction::Egress && is_syn_only)
            || (stats.direction == Direction::Ingress && is_syn_ack)
            || (stats.direction == Direction::Egress && is_ack_only)
        {
            return Some(SpanKind::Client);
        }

        // SERVER cases - we are accepting the connection
        //
        // Case 4: Ingress SYN - We received initial SYN (packet 1, we are destination)
        // Case 5: Egress SYN-ACK - We sent SYN-ACK response (packet 2, we are source)
        // Case 6: Ingress ACK - We received final ACK (packet 3, we are destination)
        if (stats.direction == Direction::Ingress && is_syn_only)
            || (stats.direction == Direction::Egress && is_syn_ack)
            || (stats.direction == Direction::Ingress && is_ack_only)
        {
            return Some(SpanKind::Server);
        }

        None
    }

    /// Rule 3: Port Number Heuristic (ephemeral vs well-known ports)
    ///
    /// Uses Linux's default ephemeral port range (32768-65535) to identify clients.
    /// If one port is ephemeral and the other is not, the ephemeral port is the client.
    /// If both are ephemeral (or both are well-known), uses higher port as tiebreaker.
    ///
    /// Returns the appropriate SpanKind based on whether the source is the client or server.
    ///
    /// Note: Linux default is 32768-60999 (/proc/sys/net/ipv4/ip_local_port_range).
    /// IANA standard is 49152-65535. We use 32768 to match actual Linux behavior.
    fn check_ephemeral_port(flow_key: &FlowKey) -> Option<SpanKind> {
        const EPHEMERAL_PORT_START: u16 = 32768;

        let src_is_ephemeral = flow_key.src_port >= EPHEMERAL_PORT_START;
        let dst_is_ephemeral = flow_key.dst_port >= EPHEMERAL_PORT_START;

        match (src_is_ephemeral, dst_is_ephemeral) {
            // Source is client (ephemeral), destination is server (well-known)
            (true, false) => Some(SpanKind::Client),
            // Source is server (well-known), destination is client (ephemeral)
            (false, true) => Some(SpanKind::Server),
            (true, true) => {
                // Both ephemeral: use higher port as tiebreaker
                if flow_key.src_port > flow_key.dst_port {
                    Some(SpanKind::Client)
                } else if flow_key.dst_port > flow_key.src_port {
                    Some(SpanKind::Server)
                } else {
                    None
                }
            }
            (false, false) => None,
        }
    }

    /// Rule 4: ICMP Type-Based Logic using direction and message type
    ///
    /// Handles both normal and late-start scenarios by combining ICMP message type
    /// (request vs reply) with packet direction (egress vs ingress).
    fn check_icmp_type(stats: &FlowStats) -> Option<SpanKind> {
        let icmp_type = stats.icmp_type;
        let is_icmpv6 = stats.protocol == IpProto::Ipv6Icmp;

        let is_request = if is_icmpv6 {
            matches!(icmp_type, ICMPV6_ECHO_REQUEST | ICMPV6_MLD_QUERY)
        } else {
            matches!(
                icmp_type,
                ICMP_ECHO_REQUEST | ICMP_TIMESTAMP_REQUEST | ICMP_ADDRESS_MASK_REQUEST
            )
        };

        let is_reply = if is_icmpv6 {
            matches!(icmp_type, ICMPV6_ECHO_REPLY | ICMPV6_MLD_REPORT)
        } else {
            matches!(
                icmp_type,
                ICMP_ECHO_REPLY | ICMP_TIMESTAMP_REPLY | ICMP_ADDRESS_MASK_REPLY
            )
        };

        // CLIENT: Egress Request (we sent a request) or Ingress Reply (we received a reply)
        if (stats.direction == Direction::Egress && is_request)
            || (stats.direction == Direction::Ingress && is_reply)
        {
            return Some(SpanKind::Client);
        }

        // SERVER: Ingress Request (we received a request) or Egress Reply (we sent a reply)
        if (stats.direction == Direction::Ingress && is_request)
            || (stats.direction == Direction::Egress && is_reply)
        {
            return Some(SpanKind::Server);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use mermin_common::{ConnectionState, Direction, IpVersion, eth::EtherType};

    use super::*;

    fn create_test_stats(protocol: IpProto) -> FlowStats {
        FlowStats {
            first_seen_ns: 0,
            last_seen_ns: 0,
            packets: 1,
            bytes: 100,
            reverse_packets: 0,
            reverse_bytes: 0,
            tcp_syn_ns: 0,
            tcp_syn_ack_ns: 0,
            tcp_last_payload_fwd_ns: 0,
            tcp_last_payload_rev_ns: 0,
            tcp_txn_sum_ns: 0,
            src_ip: [192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            dst_ip: [192, 168, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ifindex: 1,
            ip_flow_label: 0,
            reverse_ip_flow_label: 0,
            tcp_txn_count: 0,
            tcp_jitter_avg_ns: 0,
            ether_type: EtherType::Ipv4,
            src_port: 50000,
            dst_port: 80,
            src_mac: [0; 6],
            direction: Direction::Egress,
            ip_version: IpVersion::V4,
            protocol,
            ip_dscp: 0,
            ip_ecn: 0,
            ip_ttl: 64,
            reverse_ip_dscp: 0,
            reverse_ip_ecn: 0,
            reverse_ip_ttl: 0,
            forward_metadata_seen: 1,
            reverse_metadata_seen: 0,
            tcp_flags: 0,
            tcp_state: ConnectionState::default(),
            forward_tcp_flags: 0,
            reverse_tcp_flags: 0,
            icmp_type: 0,
            icmp_code: 0,
            reverse_icmp_type: 0,
            reverse_icmp_code: 0,
            pid: 0,
            comm: [0u8; 16],
        }
    }

    #[test]
    fn test_tcp_handshake_client_egress_syn() {
        let mut stats = create_test_stats(IpProto::Tcp);
        stats.direction = Direction::Egress;
        stats.forward_tcp_flags = 0x02;

        let result = DirectionInferrer::check_tcp_handshake(&stats);
        assert_eq!(result, Some(SpanKind::Client));
    }

    #[test]
    fn test_tcp_handshake_client_ingress_syn_ack() {
        let mut stats = create_test_stats(IpProto::Tcp);
        stats.direction = Direction::Ingress;
        stats.forward_tcp_flags = 0x12;

        let result = DirectionInferrer::check_tcp_handshake(&stats);
        assert_eq!(result, Some(SpanKind::Client));
    }

    #[test]
    fn test_tcp_handshake_client_egress_ack() {
        let mut stats = create_test_stats(IpProto::Tcp);
        stats.direction = Direction::Egress;
        stats.forward_tcp_flags = 0x10;

        let result = DirectionInferrer::check_tcp_handshake(&stats);
        assert_eq!(result, Some(SpanKind::Client));
    }

    #[test]
    fn test_tcp_handshake_server_ingress_syn() {
        let mut stats = create_test_stats(IpProto::Tcp);
        stats.direction = Direction::Ingress;
        stats.forward_tcp_flags = 0x02;

        let result = DirectionInferrer::check_tcp_handshake(&stats);
        assert_eq!(result, Some(SpanKind::Server));
    }

    #[test]
    fn test_tcp_handshake_server_egress_syn_ack() {
        let mut stats = create_test_stats(IpProto::Tcp);
        stats.direction = Direction::Egress;
        stats.forward_tcp_flags = 0x12;

        let result = DirectionInferrer::check_tcp_handshake(&stats);
        assert_eq!(result, Some(SpanKind::Server));
    }

    #[test]
    fn test_tcp_handshake_server_ingress_ack() {
        let mut stats = create_test_stats(IpProto::Tcp);
        stats.direction = Direction::Ingress;
        stats.forward_tcp_flags = 0x10;

        let result = DirectionInferrer::check_tcp_handshake(&stats);
        assert_eq!(result, Some(SpanKind::Server));
    }

    #[test]
    fn test_ephemeral_port_client() {
        let mut flow_key = FlowKey::default();
        flow_key.src_port = 50000;
        flow_key.dst_port = 80;

        let result = DirectionInferrer::check_ephemeral_port(&flow_key);
        assert_eq!(result, Some(SpanKind::Client));
    }

    #[test]
    fn test_icmp_client_egress_request() {
        let mut stats = create_test_stats(IpProto::Icmp);
        stats.direction = Direction::Egress;
        stats.icmp_type = ICMP_ECHO_REQUEST;

        let result = DirectionInferrer::check_icmp_type(&stats);
        assert_eq!(result, Some(SpanKind::Client));
    }

    #[test]
    fn test_icmp_client_ingress_reply() {
        let mut stats = create_test_stats(IpProto::Icmp);
        stats.direction = Direction::Ingress;
        stats.icmp_type = ICMP_ECHO_REPLY;

        let result = DirectionInferrer::check_icmp_type(&stats);
        assert_eq!(result, Some(SpanKind::Client));
    }

    #[test]
    fn test_icmp_server_ingress_request() {
        let mut stats = create_test_stats(IpProto::Icmp);
        stats.direction = Direction::Ingress;
        stats.icmp_type = ICMP_ECHO_REQUEST;

        let result = DirectionInferrer::check_icmp_type(&stats);
        assert_eq!(result, Some(SpanKind::Server));
    }

    #[test]
    fn test_icmp_server_egress_reply() {
        let mut stats = create_test_stats(IpProto::Icmp);
        stats.direction = Direction::Egress;
        stats.icmp_type = ICMP_ECHO_REPLY;

        let result = DirectionInferrer::check_icmp_type(&stats);
        assert_eq!(result, Some(SpanKind::Server));
    }

    #[test]
    fn test_icmp_ambiguous_type() {
        let mut stats = create_test_stats(IpProto::Icmp);
        stats.direction = Direction::Egress;
        stats.icmp_type = 3;

        let result = DirectionInferrer::check_icmp_type(&stats);
        assert!(result.is_none());
    }

    #[test]
    fn test_port_heuristic_higher_source() {
        let mut flow_key = FlowKey::default();
        flow_key.src_port = 50000;
        flow_key.dst_port = 80;

        let result = DirectionInferrer::check_ephemeral_port(&flow_key);
        assert_eq!(result, Some(SpanKind::Client));
    }

    #[test]
    fn test_port_heuristic_higher_destination() {
        let mut flow_key = FlowKey::default();
        flow_key.src_port = 80;
        flow_key.dst_port = 50000;

        let result = DirectionInferrer::check_ephemeral_port(&flow_key);
        assert_eq!(result, Some(SpanKind::Server));
    }

    #[test]
    fn test_port_heuristic_both_ephemeral() {
        let mut flow_key = FlowKey::default();
        flow_key.src_port = 50000;
        flow_key.dst_port = 51000;

        let result = DirectionInferrer::check_ephemeral_port(&flow_key);
        assert_eq!(result, Some(SpanKind::Server));
    }

    #[test]
    fn test_port_heuristic_both_well_known() {
        let mut flow_key = FlowKey::default();
        flow_key.src_port = 80;
        flow_key.dst_port = 443;

        let result = DirectionInferrer::check_ephemeral_port(&flow_key);
        assert!(result.is_none());
    }

    #[test]
    fn test_port_heuristic_equal_ports() {
        let mut flow_key = FlowKey::default();
        flow_key.src_port = 8080;
        flow_key.dst_port = 8080;

        let result = DirectionInferrer::check_ephemeral_port(&flow_key);
        assert!(result.is_none());
    }

    #[test]
    fn test_icmpv6_client_egress_request() {
        let mut stats = create_test_stats(IpProto::Ipv6Icmp);
        stats.direction = Direction::Egress;
        stats.icmp_type = ICMPV6_ECHO_REQUEST;

        let result = DirectionInferrer::check_icmp_type(&stats);
        assert_eq!(result, Some(SpanKind::Client));
    }

    #[test]
    fn test_icmpv6_mld_query_egress() {
        let mut stats = create_test_stats(IpProto::Ipv6Icmp);
        stats.direction = Direction::Egress;
        stats.icmp_type = ICMPV6_MLD_QUERY;

        let result = DirectionInferrer::check_icmp_type(&stats);
        assert_eq!(result, Some(SpanKind::Client));
    }

    #[test]
    fn test_icmpv6_server_egress_reply() {
        let mut stats = create_test_stats(IpProto::Ipv6Icmp);
        stats.direction = Direction::Egress;
        stats.icmp_type = ICMPV6_ECHO_REPLY;

        let result = DirectionInferrer::check_icmp_type(&stats);
        assert_eq!(result, Some(SpanKind::Server));
    }

    #[test]
    fn test_tcp_handshake_non_handshake_packet() {
        let mut stats = create_test_stats(IpProto::Tcp);
        stats.direction = Direction::Egress;
        stats.forward_tcp_flags = 0x18;

        let result = DirectionInferrer::check_tcp_handshake(&stats);
        assert!(result.is_none());
    }

    #[test]
    fn test_both_ports_well_known() {
        let mut flow_key = FlowKey::default();
        flow_key.src_port = 80;
        flow_key.dst_port = 443;

        let result = DirectionInferrer::check_ephemeral_port(&flow_key);
        assert!(result.is_none());
    }
}
