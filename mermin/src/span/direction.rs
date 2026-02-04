//! Client/Server direction inference for network flows.
//!
//! This module determines whether the agent is observing the "client" or "server"
//! side of a network connection by applying a hierarchy of inference rules.
//!
//! # Inference Hierarchy
//!
//! The [`DirectionInferrer`] applies rules in priority order:
//!
//! 1. **Listen Port State** (most reliable): If the destination port matches a
//!    local listening port tracked in the eBPF map, the flow is SERVER-side.
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

use std::{net::IpAddr, sync::Arc};

use aya::maps::HashMap as EbpfHashMap;
use mermin_common::{Direction, FlowKey, FlowStats, IcmpStats, ListeningPortKey, TcpStats};
use network_types::{
    ip::IpProto,
    tcp::{TCP_FLAG_ACK, TCP_FLAG_SYN},
};
use opentelemetry::trace::SpanKind;
use tokio::sync::Mutex;
use tracing::trace;

use crate::{
    ip::flow_key_to_ip_addrs,
    metrics::{
        self,
        ebpf::{EbpfMapName, EbpfMapOperation, EbpfMapStatus},
    },
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

/// Client and server endpoint information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientServer {
    /// IP address of the client (initiator)
    pub client_ip: IpAddr,
    /// Port number of the client
    pub client_port: u16,
    /// IP address of the server (responder)
    pub server_ip: IpAddr,
    /// Port number of the server
    pub server_port: u16,
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

    pub fn listening_ports_map(
        &self,
    ) -> Arc<Mutex<EbpfHashMap<aya::maps::MapData, ListeningPortKey, u8>>> {
        Arc::clone(&self.listening_ports_map)
    }

    /// Infer the direction of a flow (CLIENT, SERVER, or INTERNAL)
    ///
    /// Applies the inference rule hierarchy described in the [module-level documentation](self)
    /// to determine the role of the observed endpoint. Returns the OpenTelemetry [`SpanKind`]
    /// and optionally the [`ClientServer`] details.
    #[must_use = "direction inference result must be used to set span attributes"]
    pub async fn infer_from_stats(
        &self,
        flow_key: &FlowKey,
        stats: &FlowStats,
        tcp_stats: Option<&TcpStats>,
        icmp_stats: Option<&IcmpStats>,
    ) -> (SpanKind, Option<ClientServer>) {
        let (src_ip, dst_ip) = match flow_key_to_ip_addrs(flow_key) {
            Ok((src, dst)) => (src, dst),
            Err(_) => return (SpanKind::Internal, None),
        };

        if let Some(cs) = self
            .check_listening_port(flow_key, &src_ip, &dst_ip, stats)
            .await
        {
            return (SpanKind::Server, Some(cs));
        }

        if stats.protocol == IpProto::Tcp
            && let Some(ts) = tcp_stats
            && let Some((kind, cs)) = Self::check_tcp_handshake(stats, ts, &src_ip, &dst_ip)
        {
            return (kind, Some(cs));
        }

        if matches!(stats.protocol, IpProto::Tcp | IpProto::Udp)
            && let Some((kind, cs)) = Self::check_ephemeral_port(flow_key, &src_ip, &dst_ip)
        {
            return (kind, Some(cs));
        }

        if matches!(stats.protocol, IpProto::Icmp | IpProto::Ipv6Icmp)
            && let Some(is) = icmp_stats
            && let Some((kind, cs)) = Self::check_icmp_type(stats, is, &src_ip, &dst_ip)
        {
            return (kind, Some(cs));
        }

        // Rule 5: Fallback to INTERNAL
        (SpanKind::Internal, None)
    }

    /// Rule 1: Check if either port is in listening ports map
    ///
    /// Checks both source and destination ports to handle:
    /// - Request packets: client:ephemeral -> server:listening
    /// - Response packets: server:listening -> client:ephemeral
    /// - Server-to-server: server:listening -> server:listening
    async fn check_listening_port(
        &self,
        flow_key: &FlowKey,
        src_ip: &IpAddr,
        dst_ip: &IpAddr,
        stats: &FlowStats,
    ) -> Option<ClientServer> {
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
                        trace!(
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
            return Some(ClientServer {
                client_ip: *src_ip,
                client_port: flow_key.src_port,
                server_ip: *dst_ip,
                server_port: flow_key.dst_port,
            });
        }

        if lookup_port(flow_key.src_port) {
            return Some(ClientServer {
                client_ip: *dst_ip,
                client_port: flow_key.dst_port,
                server_ip: *src_ip,
                server_port: flow_key.src_port,
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
    fn check_tcp_handshake(
        stats: &FlowStats,
        tcp_stats: &TcpStats,
        src_ip: &IpAddr,
        dst_ip: &IpAddr,
    ) -> Option<(SpanKind, ClientServer)> {
        const SYN_ACK: u8 = TCP_FLAG_SYN | TCP_FLAG_ACK;

        let flags = tcp_stats.forward_tcp_flags;

        // Distinguish between SYN, SYN-ACK, and pure ACK (third handshake packet)
        let is_syn_only = (flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) == 0;
        let is_syn_ack = (flags & SYN_ACK) == SYN_ACK;
        // Pure ACK for third handshake packet - must not have other flags like PSH/FIN
        let is_ack_only = flags == TCP_FLAG_ACK;

        // CLIENT cases - we are the connection initiator
        //
        // Case 1: Egress SYN - We sent initial SYN (packet 1, we are source)
        if stats.direction == Direction::Egress && is_syn_only {
            return Some((
                SpanKind::Client,
                ClientServer {
                    client_ip: *src_ip,
                    client_port: stats.src_port,
                    server_ip: *dst_ip,
                    server_port: stats.dst_port,
                },
            ));
        }

        // Case 2: Ingress SYN-ACK - We received server response (packet 2, we are destination)
        if stats.direction == Direction::Ingress && is_syn_ack {
            return Some((
                SpanKind::Client,
                ClientServer {
                    client_ip: *dst_ip,
                    client_port: stats.dst_port,
                    server_ip: *src_ip,
                    server_port: stats.src_port,
                },
            ));
        }

        // Case 3: Egress ACK - We sent final ACK (packet 3, we are source)
        if stats.direction == Direction::Egress && is_ack_only {
            return Some((
                SpanKind::Client,
                ClientServer {
                    client_ip: *src_ip,
                    client_port: stats.src_port,
                    server_ip: *dst_ip,
                    server_port: stats.dst_port,
                },
            ));
        }

        // SERVER cases - we are accepting the connection
        //
        // Case 4: Ingress SYN - We received initial SYN (packet 1, we are destination)
        if stats.direction == Direction::Ingress && is_syn_only {
            return Some((
                SpanKind::Server,
                ClientServer {
                    client_ip: *src_ip,
                    client_port: stats.src_port,
                    server_ip: *dst_ip,
                    server_port: stats.dst_port,
                },
            ));
        }

        // Case 5: Egress SYN-ACK - We sent SYN-ACK response (packet 2, we are source)
        if stats.direction == Direction::Egress && is_syn_ack {
            return Some((
                SpanKind::Server,
                ClientServer {
                    client_ip: *dst_ip,
                    client_port: stats.dst_port,
                    server_ip: *src_ip,
                    server_port: stats.src_port,
                },
            ));
        }

        // Case 6: Ingress ACK - We received final ACK (packet 3, we are destination)
        if stats.direction == Direction::Ingress && is_ack_only {
            return Some((
                SpanKind::Server,
                ClientServer {
                    client_ip: *src_ip,
                    client_port: stats.src_port,
                    server_ip: *dst_ip,
                    server_port: stats.dst_port,
                },
            ));
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
    fn check_ephemeral_port(
        flow_key: &FlowKey,
        src_ip: &IpAddr,
        dst_ip: &IpAddr,
    ) -> Option<(SpanKind, ClientServer)> {
        const EPHEMERAL_PORT_START: u16 = 32768;

        let src_is_ephemeral = flow_key.src_port >= EPHEMERAL_PORT_START;
        let dst_is_ephemeral = flow_key.dst_port >= EPHEMERAL_PORT_START;

        match (src_is_ephemeral, dst_is_ephemeral) {
            (true, false) => {
                // Source is client (ephemeral), destination is server (well-known)
                // We're observing from client perspective
                Some((
                    SpanKind::Client,
                    ClientServer {
                        client_ip: *src_ip,
                        client_port: flow_key.src_port,
                        server_ip: *dst_ip,
                        server_port: flow_key.dst_port,
                    },
                ))
            }
            (false, true) => {
                // Source is server (well-known), destination is client (ephemeral)
                // We're observing from server perspective
                Some((
                    SpanKind::Server,
                    ClientServer {
                        client_ip: *dst_ip,
                        client_port: flow_key.dst_port,
                        server_ip: *src_ip,
                        server_port: flow_key.src_port,
                    },
                ))
            }
            (true, true) => {
                // Both ephemeral - use higher port as tiebreaker
                if flow_key.src_port > flow_key.dst_port {
                    Some((
                        SpanKind::Client,
                        ClientServer {
                            client_ip: *src_ip,
                            client_port: flow_key.src_port,
                            server_ip: *dst_ip,
                            server_port: flow_key.dst_port,
                        },
                    ))
                } else if flow_key.dst_port > flow_key.src_port {
                    Some((
                        SpanKind::Server,
                        ClientServer {
                            client_ip: *dst_ip,
                            client_port: flow_key.dst_port,
                            server_ip: *src_ip,
                            server_port: flow_key.src_port,
                        },
                    ))
                } else {
                    None
                }
            }
            // Both well-known: cannot reliably determine client/server
            (false, false) => None,
        }
    }

    /// Rule 4: ICMP Type-Based Logic using direction and message type
    ///
    /// Handles both normal and late-start scenarios by combining ICMP message type
    /// (request vs reply) with packet direction (egress vs ingress).
    fn check_icmp_type(
        stats: &FlowStats,
        icmp_stats: &IcmpStats,
        src_ip: &IpAddr,
        dst_ip: &IpAddr,
    ) -> Option<(SpanKind, ClientServer)> {
        let icmp_type = icmp_stats.icmp_type;
        let is_icmpv6 = stats.protocol == IpProto::Ipv6Icmp;

        let is_request = if is_icmpv6 {
            matches!(icmp_type, ICMPV6_ECHO_REQUEST | ICMPV6_MLD_QUERY)
        } else {
            matches!(
                icmp_type,
                ICMP_ECHO_REQUEST | ICMP_TIMESTAMP_REQUEST | ICMP_ADDRESS_MASK_REQUEST
            )
        };

        // Identify reply types
        let is_reply = if is_icmpv6 {
            matches!(icmp_type, ICMPV6_ECHO_REPLY | ICMPV6_MLD_REPORT)
        } else {
            matches!(
                icmp_type,
                ICMP_ECHO_REPLY | ICMP_TIMESTAMP_REPLY | ICMP_ADDRESS_MASK_REPLY
            )
        };

        // CLIENT cases:
        // - Egress Request: We sent a request (normal)
        // - Ingress Reply: We received a reply (late start or response)
        if (stats.direction == Direction::Egress && is_request)
            || (stats.direction == Direction::Ingress && is_reply)
        {
            return Some((
                SpanKind::Client,
                ClientServer {
                    client_ip: if stats.direction == Direction::Egress {
                        *src_ip
                    } else {
                        *dst_ip
                    },
                    client_port: 0,
                    server_ip: if stats.direction == Direction::Egress {
                        *dst_ip
                    } else {
                        *src_ip
                    },
                    server_port: 0,
                },
            ));
        }

        // SERVER cases:
        // - Ingress Request: We received a request (normal)
        // - Egress Reply: We sent a reply (late start or response)
        if (stats.direction == Direction::Ingress && is_request)
            || (stats.direction == Direction::Egress && is_reply)
        {
            return Some((
                SpanKind::Server,
                ClientServer {
                    client_ip: if stats.direction == Direction::Ingress {
                        *src_ip
                    } else {
                        *dst_ip
                    },
                    client_port: 0,
                    server_ip: if stats.direction == Direction::Ingress {
                        *dst_ip
                    } else {
                        *src_ip
                    },
                    server_port: 0,
                },
            ));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use mermin_common::{Direction, IpVersion};
    use network_types::eth::EtherType;

    use super::*;

    fn create_test_stats(protocol: IpProto) -> FlowStats {
        FlowStats {
            first_seen_ns: 0,
            last_seen_ns: 0,
            packets: 1,
            bytes: 100,
            reverse_packets: 0,
            reverse_bytes: 0,
            src_ip: [192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            dst_ip: [192, 168, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            src_mac: [0; 6],
            ifindex: 1,
            ip_flow_label: 0,
            reverse_ip_flow_label: 0,
            ether_type: EtherType::Ipv4,
            src_port: 50000,
            dst_port: 80,
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
        }
    }

    #[test]
    fn test_tcp_handshake_client_egress_syn() {
        // Client sends SYN (packet 1)
        let mut stats = create_test_stats(IpProto::Tcp);
        let mut tcp_stats = TcpStats::default();
        stats.direction = Direction::Egress;
        tcp_stats.forward_tcp_flags = 0x02; // SYN only

        let src_ip = "192.168.1.1".parse().unwrap();
        let dst_ip = "192.168.1.2".parse().unwrap();

        let result = DirectionInferrer::check_tcp_handshake(&stats, &tcp_stats, &src_ip, &dst_ip);
        assert!(result.is_some());

        let (kind, cs) = result.unwrap();
        assert_eq!(kind, SpanKind::Client);
        assert_eq!(cs.client_ip, src_ip);
        assert_eq!(cs.client_port, 50000);
        assert_eq!(cs.server_ip, dst_ip);
        assert_eq!(cs.server_port, 80);
    }

    #[test]
    fn test_tcp_handshake_client_ingress_syn_ack() {
        // Client receives SYN-ACK (packet 2, late start)
        let mut stats = create_test_stats(IpProto::Tcp);
        let mut tcp_stats = TcpStats::default();
        stats.direction = Direction::Ingress;
        tcp_stats.forward_tcp_flags = 0x12; // SYN+ACK

        let src_ip = "192.168.1.2".parse().unwrap(); // Server
        let dst_ip = "192.168.1.1".parse().unwrap(); // Client (us)

        let result = DirectionInferrer::check_tcp_handshake(&stats, &tcp_stats, &src_ip, &dst_ip);
        assert!(result.is_some());

        let (kind, cs) = result.unwrap();
        assert_eq!(kind, SpanKind::Client);
        assert_eq!(cs.client_ip, dst_ip); // We are destination
        assert_eq!(cs.server_ip, src_ip); // Server is source
    }

    #[test]
    fn test_tcp_handshake_client_egress_ack() {
        // Client sends final ACK (packet 3, very late start)
        let mut stats = create_test_stats(IpProto::Tcp);
        let mut tcp_stats = TcpStats::default();
        stats.direction = Direction::Egress;
        tcp_stats.forward_tcp_flags = 0x10; // ACK only

        let src_ip = "192.168.1.1".parse().unwrap();
        let dst_ip = "192.168.1.2".parse().unwrap();

        let result = DirectionInferrer::check_tcp_handshake(&stats, &tcp_stats, &src_ip, &dst_ip);
        assert!(result.is_some());

        let (kind, cs) = result.unwrap();
        assert_eq!(kind, SpanKind::Client);
        assert_eq!(cs.client_ip, src_ip);
        assert_eq!(cs.server_ip, dst_ip);
    }

    #[test]
    fn test_tcp_handshake_server_ingress_syn() {
        // Server receives SYN (packet 1)
        let mut stats = create_test_stats(IpProto::Tcp);
        let mut tcp_stats = TcpStats::default();
        stats.direction = Direction::Ingress;
        tcp_stats.forward_tcp_flags = 0x02; // SYN only

        let src_ip = "192.168.1.1".parse().unwrap(); // Client
        let dst_ip = "192.168.1.2".parse().unwrap(); // Server (us)

        let result = DirectionInferrer::check_tcp_handshake(&stats, &tcp_stats, &src_ip, &dst_ip);
        assert!(result.is_some());

        let (kind, cs) = result.unwrap();
        assert_eq!(kind, SpanKind::Server);
        assert_eq!(cs.server_ip, dst_ip); // We are destination
        assert_eq!(cs.client_ip, src_ip); // Client is source
    }

    #[test]
    fn test_tcp_handshake_server_egress_syn_ack() {
        // Server sends SYN-ACK (packet 2, late start)
        let mut stats = create_test_stats(IpProto::Tcp);
        let mut tcp_stats = TcpStats::default();
        stats.direction = Direction::Egress;
        tcp_stats.forward_tcp_flags = 0x12; // SYN+ACK

        let src_ip = "192.168.1.2".parse().unwrap(); // Server (us)
        let dst_ip = "192.168.1.1".parse().unwrap(); // Client

        let result = DirectionInferrer::check_tcp_handshake(&stats, &tcp_stats, &src_ip, &dst_ip);
        assert!(result.is_some());

        let (kind, cs) = result.unwrap();
        assert_eq!(kind, SpanKind::Server);
        assert_eq!(cs.server_ip, src_ip); // We are source
        assert_eq!(cs.client_ip, dst_ip); // Client is destination
    }

    #[test]
    fn test_tcp_handshake_server_ingress_ack() {
        // Server receives final ACK (packet 3, very late start)
        let mut stats = create_test_stats(IpProto::Tcp);
        let mut tcp_stats = TcpStats::default();
        stats.direction = Direction::Ingress;
        tcp_stats.forward_tcp_flags = 0x10; // ACK only

        let src_ip = "192.168.1.1".parse().unwrap(); // Client
        let dst_ip = "192.168.1.2".parse().unwrap(); // Server (us)

        let result = DirectionInferrer::check_tcp_handshake(&stats, &tcp_stats, &src_ip, &dst_ip);
        assert!(result.is_some());

        let (kind, cs) = result.unwrap();
        assert_eq!(kind, SpanKind::Server);
        assert_eq!(cs.server_ip, dst_ip); // We are destination
        assert_eq!(cs.client_ip, src_ip); // Client is source
    }

    #[test]
    fn test_ephemeral_port_client() {
        let mut flow_key = FlowKey::default();
        flow_key.src_port = 50000; // Ephemeral
        flow_key.dst_port = 80; // Well-known

        let src_ip = "192.168.1.1".parse().unwrap();
        let dst_ip = "192.168.1.2".parse().unwrap();

        let result = DirectionInferrer::check_ephemeral_port(&flow_key, &src_ip, &dst_ip);
        assert!(result.is_some());

        let (kind, cs) = result.unwrap();
        assert_eq!(kind, SpanKind::Client); // Source is client
        assert_eq!(cs.client_ip, src_ip);
        assert_eq!(cs.server_ip, dst_ip);
        assert_eq!(cs.client_port, 50000);
        assert_eq!(cs.server_port, 80);
    }

    #[test]
    fn test_icmp_client_egress_request() {
        // Client sends Echo Request (normal)
        let mut stats = create_test_stats(IpProto::Icmp);
        let mut icmp_stats = IcmpStats::default();
        stats.direction = Direction::Egress;
        icmp_stats.icmp_type = ICMP_ECHO_REQUEST;

        let src_ip = "192.168.1.1".parse().unwrap();
        let dst_ip = "8.8.8.8".parse().unwrap();

        let result = DirectionInferrer::check_icmp_type(&stats, &icmp_stats, &src_ip, &dst_ip);
        assert!(result.is_some());

        let (kind, cs) = result.unwrap();
        assert_eq!(kind, SpanKind::Client);
        assert_eq!(cs.client_ip, src_ip);
        assert_eq!(cs.server_ip, dst_ip);
    }

    #[test]
    fn test_icmp_client_ingress_reply() {
        // Client receives Echo Reply (late start or response)
        let mut stats = create_test_stats(IpProto::Icmp);
        let mut icmp_stats = IcmpStats::default();
        stats.direction = Direction::Ingress;
        icmp_stats.icmp_type = ICMP_ECHO_REPLY;

        let src_ip = "8.8.8.8".parse().unwrap(); // Server
        let dst_ip = "192.168.1.1".parse().unwrap(); // Client (us)

        let result = DirectionInferrer::check_icmp_type(&stats, &icmp_stats, &src_ip, &dst_ip);
        assert!(result.is_some());

        let (kind, cs) = result.unwrap();
        assert_eq!(kind, SpanKind::Client);
        assert_eq!(cs.client_ip, dst_ip); // We are destination
        assert_eq!(cs.server_ip, src_ip); // Server is source
    }

    #[test]
    fn test_icmp_server_ingress_request() {
        // Server receives Echo Request (normal)
        let mut stats = create_test_stats(IpProto::Icmp);
        let mut icmp_stats = IcmpStats::default();
        stats.direction = Direction::Ingress;
        icmp_stats.icmp_type = ICMP_ECHO_REQUEST;

        let src_ip = "192.168.1.1".parse().unwrap(); // Client
        let dst_ip = "8.8.8.8".parse().unwrap(); // Server (us)

        let result = DirectionInferrer::check_icmp_type(&stats, &icmp_stats, &src_ip, &dst_ip);
        assert!(result.is_some());

        let (kind, cs) = result.unwrap();
        assert_eq!(kind, SpanKind::Server);
        assert_eq!(cs.server_ip, dst_ip); // We are destination
        assert_eq!(cs.client_ip, src_ip); // Client is source
    }

    #[test]
    fn test_icmp_server_egress_reply() {
        // Server sends Echo Reply (late start or response)
        let mut stats = create_test_stats(IpProto::Icmp);
        let mut icmp_stats = IcmpStats::default();
        stats.direction = Direction::Egress;
        icmp_stats.icmp_type = ICMP_ECHO_REPLY;

        let src_ip = "8.8.8.8".parse().unwrap(); // Server (us)
        let dst_ip = "192.168.1.1".parse().unwrap(); // Client

        let result = DirectionInferrer::check_icmp_type(&stats, &icmp_stats, &src_ip, &dst_ip);
        assert!(result.is_some());

        let (kind, cs) = result.unwrap();
        assert_eq!(kind, SpanKind::Server);
        assert_eq!(cs.server_ip, src_ip); // We are source
        assert_eq!(cs.client_ip, dst_ip); // Client is destination
    }

    #[test]
    fn test_icmp_ambiguous_type() {
        // Ambiguous ICMP type (error message) - cannot determine client/server roles
        let mut stats = create_test_stats(IpProto::Icmp);
        let mut icmp_stats = IcmpStats::default();
        stats.direction = Direction::Egress;
        icmp_stats.icmp_type = 3; // Destination Unreachable

        let src_ip = "192.168.1.1".parse().unwrap();
        let dst_ip = "8.8.8.8".parse().unwrap();

        let result = DirectionInferrer::check_icmp_type(&stats, &icmp_stats, &src_ip, &dst_ip);
        // Returns None - will fall through to final INTERNAL fallback with no client/server attrs
        assert!(result.is_none());
    }

    #[test]
    fn test_port_heuristic_higher_source() {
        // Source port higher - source is client
        let mut flow_key = FlowKey::default();
        flow_key.src_port = 50000;
        flow_key.dst_port = 80;

        let src_ip = "192.168.1.1".parse().unwrap();
        let dst_ip = "192.168.1.2".parse().unwrap();

        let result = DirectionInferrer::check_ephemeral_port(&flow_key, &src_ip, &dst_ip);
        assert!(result.is_some());

        let (kind, cs) = result.unwrap();
        assert_eq!(kind, SpanKind::Client); // Source is client
        assert_eq!(cs.client_ip, src_ip);
        assert_eq!(cs.server_ip, dst_ip);
        assert_eq!(cs.client_port, 50000);
        assert_eq!(cs.server_port, 80);
    }

    #[test]
    fn test_port_heuristic_higher_destination() {
        // Destination port higher - destination is client
        let mut flow_key = FlowKey::default();
        flow_key.src_port = 80;
        flow_key.dst_port = 50000;

        let src_ip = "192.168.1.1".parse().unwrap();
        let dst_ip = "192.168.1.2".parse().unwrap();

        let result = DirectionInferrer::check_ephemeral_port(&flow_key, &src_ip, &dst_ip);
        assert!(result.is_some());

        let (kind, cs) = result.unwrap();
        assert_eq!(kind, SpanKind::Server); // Source is server
        assert_eq!(cs.client_ip, dst_ip);
        assert_eq!(cs.server_ip, src_ip);
        assert_eq!(cs.client_port, 50000);
        assert_eq!(cs.server_port, 80);
    }

    #[test]
    fn test_port_heuristic_both_ephemeral() {
        // Both ports ephemeral - higher port wins
        let mut flow_key = FlowKey::default();
        flow_key.src_port = 50000;
        flow_key.dst_port = 51000;

        let src_ip = "192.168.1.1".parse().unwrap();
        let dst_ip = "192.168.1.2".parse().unwrap();

        let result = DirectionInferrer::check_ephemeral_port(&flow_key, &src_ip, &dst_ip);
        assert!(result.is_some());

        let (kind, cs) = result.unwrap();
        // 51000 > 50000, so destination is client, source is server
        assert_eq!(kind, SpanKind::Server); // Source is server
        assert_eq!(cs.client_ip, dst_ip);
        assert_eq!(cs.server_ip, src_ip);
        assert_eq!(cs.client_port, 51000);
        assert_eq!(cs.server_port, 50000);
    }

    #[test]
    fn test_port_heuristic_both_well_known() {
        // Both ports well-known - cannot determine, returns None
        let mut flow_key = FlowKey::default();
        flow_key.src_port = 80;
        flow_key.dst_port = 443;

        let src_ip = "192.168.1.1".parse().unwrap();
        let dst_ip = "192.168.1.2".parse().unwrap();

        let result = DirectionInferrer::check_ephemeral_port(&flow_key, &src_ip, &dst_ip);
        // Both ports < 32768 (well-known range), so cannot determine
        assert!(result.is_none());
    }

    #[test]
    fn test_port_heuristic_equal_ports() {
        // Equal ports - cannot determine
        let mut flow_key = FlowKey::default();
        flow_key.src_port = 8080;
        flow_key.dst_port = 8080;

        let src_ip = "192.168.1.1".parse().unwrap();
        let dst_ip = "192.168.1.2".parse().unwrap();

        let result = DirectionInferrer::check_ephemeral_port(&flow_key, &src_ip, &dst_ip);
        // Should return None since ports are equal
        assert!(result.is_none());
    }

    #[test]
    fn test_icmpv6_client_egress_request() {
        // Client sends Echo Request (normal)
        let mut stats = create_test_stats(IpProto::Ipv6Icmp);
        let mut icmp_stats = IcmpStats::default();
        stats.direction = Direction::Egress;
        icmp_stats.icmp_type = ICMPV6_ECHO_REQUEST;

        let src_ip = "2001:db8::1".parse().unwrap();
        let dst_ip = "2001:db8::2".parse().unwrap();

        let result = DirectionInferrer::check_icmp_type(&stats, &icmp_stats, &src_ip, &dst_ip);
        assert!(result.is_some());

        let (kind, cs) = result.unwrap();
        assert_eq!(kind, SpanKind::Client);
        assert_eq!(cs.client_ip, src_ip);
        assert_eq!(cs.server_ip, dst_ip);
    }

    #[test]
    fn test_icmpv6_mld_query_egress() {
        // Send MLD Query (client role)
        let mut stats = create_test_stats(IpProto::Ipv6Icmp);
        let mut icmp_stats = IcmpStats::default();
        stats.direction = Direction::Egress;
        icmp_stats.icmp_type = ICMPV6_MLD_QUERY;

        let src_ip = "fe80::1".parse().unwrap();
        let dst_ip = "ff02::1".parse().unwrap();

        let result = DirectionInferrer::check_icmp_type(&stats, &icmp_stats, &src_ip, &dst_ip);
        assert!(result.is_some());

        let (kind, cs) = result.unwrap();
        assert_eq!(kind, SpanKind::Client);
        assert_eq!(cs.client_ip, src_ip);
    }

    #[test]
    fn test_icmpv6_server_egress_reply() {
        // Server sends Echo Reply (response)
        let mut stats = create_test_stats(IpProto::Ipv6Icmp);
        let mut icmp_stats = IcmpStats::default();
        stats.direction = Direction::Egress;
        icmp_stats.icmp_type = ICMPV6_ECHO_REPLY;

        let src_ip = "2001:db8::1".parse().unwrap(); // Server (us)
        let dst_ip = "2001:db8::2".parse().unwrap(); // Client

        let result = DirectionInferrer::check_icmp_type(&stats, &icmp_stats, &src_ip, &dst_ip);
        assert!(result.is_some());

        let (kind, cs) = result.unwrap();
        assert_eq!(kind, SpanKind::Server);
        assert_eq!(cs.server_ip, src_ip);
        assert_eq!(cs.client_ip, dst_ip);
    }

    #[test]
    fn test_tcp_handshake_non_handshake_packet() {
        // Mid-connection packet with multiple flags (not a handshake packet)
        let mut stats = create_test_stats(IpProto::Tcp);
        let mut tcp_stats = TcpStats::default();
        stats.direction = Direction::Egress;
        tcp_stats.forward_tcp_flags = 0x18; // PSH+ACK (not a handshake pattern)

        let src_ip = "192.168.1.1".parse().unwrap();
        let dst_ip = "192.168.1.2".parse().unwrap();

        let result = DirectionInferrer::check_tcp_handshake(&stats, &tcp_stats, &src_ip, &dst_ip);
        // Should return None since this isn't a handshake packet
        assert!(result.is_none());
    }

    #[test]
    fn test_both_ports_well_known() {
        // Both ports in well-known range - cannot determine
        let mut flow_key = FlowKey::default();
        flow_key.src_port = 80;
        flow_key.dst_port = 443;

        let src_ip = "192.168.1.1".parse().unwrap();
        let dst_ip = "192.168.1.2".parse().unwrap();

        let result = DirectionInferrer::check_ephemeral_port(&flow_key, &src_ip, &dst_ip);
        // Both ports < 32768 (well-known range), so returns None
        assert!(result.is_none());
    }
}
