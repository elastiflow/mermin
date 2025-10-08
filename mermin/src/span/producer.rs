use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};

use chrono::{DateTime, Utc};
use dashmap::{DashMap, mapref::entry::Entry};
use fxhash::FxBuildHasher;
use mermin_common::{IpAddrType, PacketMeta, TunnelType};
use network_types::{
    eth::EtherType,
    ip::{IpDscp, IpEcn, IpProto},
    tcp::{TCP_FLAG_FIN, TCP_FLAG_RST},
};
use opentelemetry::trace::SpanKind;
use pnet::datalink::MacAddr;
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, warn};

use crate::{
    ip::{Error, resolve_addrs},
    span::{
        community_id::CommunityIdGenerator,
        flow::{FlowEndReason, FlowSpan, SpanAttributes},
        opts::SpanOptions,
        tcp::{ConnectionState, TcpFlags},
    },
};

/// ### Concurrency Model
///
/// Multiple components access the flow map concurrently:
///
/// 1. **PacketWorker**: Creates new flows and updates existing ones
/// 2. **Record Task** (per flow): Periodically reads and records flow state
/// 3. **Timeout Task** (per flow): Removes flows on timeout
///
/// #### Synchronization
///
/// - `DashMap` provides per-shard locking for concurrent access
/// - Updates to flow attributes are performed under write lock
/// - Record task clones flow state while holding read lock
/// - Timeout task removes flow atomically
///
/// #### Potential Race Conditions
///
/// - Packet update vs. Record: Safe - record clones current state
/// - Packet update vs. Timeout removal: Safe - packet finds flow missing, no-op
/// - Record vs. Timeout: Safe - timeout waits for record to complete removal
pub type FlowSpanMap = Arc<DashMap<String, FlowEntry, FxBuildHasher>>;

/// Entry in the flow map containing both the flow span and its task handles
pub struct FlowEntry {
    pub flow_span: FlowSpan,
    pub task_handles: FlowTaskHandles,
}

/// Task handles and communication channels for managing a flow's lifecycle.
///
/// ### Task Lifecycle
///
/// Each flow entry spawns two concurrent tokio tasks:
///
/// 1. **Record Task** (`record_task_loop`):
///    - Wakes up periodically (every `max_record_interval`)
///    - Records the current flow state and sends it to the exporter
///    - Resets delta counters (bytes/packets) after recording
///    - Exits when the flow entry is removed from the map
///
/// 2. **Timeout Task** (`timeout_task_loop`):
///    - Sleeps for the configured timeout duration
///    - Can be reset by incoming packets via the `timeout_reset_tx` channel
///    - When timeout fires: records final flow state, removes from map, aborts record task
///    - Exits after timeout fires or on shutdown signal
///
/// #### Concurrency & Cleanup
///
/// - Both tasks hold an Arc to the flow_span_map for concurrent access
/// - The timeout task is responsible for final cleanup (removing flow, aborting record task)
/// - If a packet arrives during timeout: the timeout is reset, keeping the flow alive
/// - If the record interval fires during final timeout: both operations happen independently
/// - The timeout task holds its own JoinHandle for cleanup coordination
pub struct FlowTaskHandles {
    /// Channel to signal timeout task to reset its timer
    timeout_reset_tx: mpsc::Sender<TimeoutUpdate>,
    /// Handle to the record task (periodic recording)
    record_task: JoinHandle<()>,
    /// Handle to the timeout task (idle timeout)
    #[allow(dead_code)] // Used for cleanup when tasks complete
    timeout_task: JoinHandle<()>,
}

/// Update message sent to timeout task
#[derive(Debug, Clone)]
enum TimeoutUpdate {
    /// Reset timeout with a new duration (for TCP state changes)
    Reset(Duration),
}

pub struct FlowSpanProducer {
    span_opts: SpanOptions,
    packet_channel_capacity: usize,
    packet_worker_count: usize,
    boot_time_offset_nanos: u64,
    iface_map: HashMap<u32, String>,
    flow_span_map: FlowSpanMap,
    community_id_generator: CommunityIdGenerator,
    packet_meta_rx: mpsc::Receiver<PacketMeta>,
    flow_span_tx: mpsc::Sender<FlowSpan>,
}

impl FlowSpanProducer {
    pub fn new(
        span_opts: SpanOptions,
        packet_channel_capacity: usize,
        packet_worker_count: usize,
        iface_map: HashMap<u32, String>,
        packet_meta_rx: mpsc::Receiver<PacketMeta>,
        flow_span_tx: mpsc::Sender<FlowSpan>,
    ) -> Result<Self, BootTimeError> {
        let flow_span_map_capacity = packet_channel_capacity * 8;
        let flow_span_map = Arc::new(DashMap::with_capacity_and_hasher(
            flow_span_map_capacity,
            FxBuildHasher::default(),
        ));
        let community_id_generator = CommunityIdGenerator::new(span_opts.community_id_seed);

        // Calculate boot time offset to convert kernel boot-relative timestamps to wall clock
        // This is critical - if we can't determine boot time, timestamps will be wrong
        let boot_time_offset_nanos = calculate_boot_time_offset_nanos()?;

        Ok(Self {
            span_opts,
            packet_channel_capacity,
            packet_worker_count,
            boot_time_offset_nanos,
            community_id_generator,
            iface_map,
            flow_span_map,
            packet_meta_rx,
            flow_span_tx,
        })
    }

    pub async fn run(mut self) {
        // Create channels for each worker
        let mut worker_channels = Vec::new();
        let worker_capacity = self.packet_channel_capacity.max(self.packet_worker_count)
            / self.packet_worker_count.max(1);

        for _ in 0..self.packet_worker_count.max(1) {
            let (worker_tx, worker_rx) = mpsc::channel(worker_capacity);
            worker_channels.push(worker_tx);

            let packet_worker = PacketWorker::new(
                self.span_opts.clone(),
                self.boot_time_offset_nanos,
                self.community_id_generator.clone(),
                self.iface_map.clone(),
                Arc::clone(&self.flow_span_map),
                worker_rx,
                self.flow_span_tx.clone(),
            );

            tokio::spawn(async move {
                packet_worker.run().await;
            });
        }

        // Distribute packets with backpressure-aware fallback
        let mut worker_index = 0;
        let worker_count = self.packet_worker_count.max(1);

        while let Some(packet) = self.packet_meta_rx.recv().await {
            let mut sent = false;
            // Try current worker first, then try others if it's full
            for attempt in 0..worker_count {
                let current_worker = (worker_index + attempt) % worker_count;
                let worker_tx = &worker_channels[current_worker];

                match worker_tx.try_send(packet) {
                    Ok(_) => {
                        worker_index = (current_worker + 1) % worker_count;
                        sent = true;
                        break;
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        // This worker is full, try next one
                        continue;
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        // Worker is gone, try next one
                        continue;
                    }
                }
            }

            if !sent {
                // All workers are full - fallback to blocking send to preferred worker
                let worker_tx = &worker_channels[worker_index];
                if worker_tx.send(packet).await.is_err() {
                    // Worker channel is closed, handle gracefully
                    continue;
                }
                worker_index = (worker_index + 1) % worker_count;
            }
        }
    }
}

pub struct PacketWorker {
    max_record_interval: Duration,
    generic_timeout: Duration,
    icmp_timeout: Duration,
    tcp_timeout: Duration,
    tcp_fin_timeout: Duration,
    tcp_rst_timeout: Duration,
    udp_timeout: Duration,
    boot_time_offset_nanos: u64,
    community_id_generator: CommunityIdGenerator,
    iface_map: HashMap<u32, String>,
    flow_span_map: FlowSpanMap,
    packet_meta_rx: mpsc::Receiver<PacketMeta>,
    flow_span_tx: mpsc::Sender<FlowSpan>,
}

impl PacketWorker {
    pub fn new(
        span_opts: SpanOptions,
        boot_time_offset_nanos: u64,
        community_id_generator: CommunityIdGenerator,
        iface_map: HashMap<u32, String>,
        flow_span_map: FlowSpanMap,
        packet_meta_rx: mpsc::Receiver<PacketMeta>,
        flow_span_tx: mpsc::Sender<FlowSpan>,
    ) -> Self {
        Self {
            max_record_interval: span_opts.max_record_interval,
            generic_timeout: span_opts.generic_timeout,
            icmp_timeout: span_opts.icmp_timeout,
            tcp_timeout: span_opts.tcp_timeout,
            tcp_fin_timeout: span_opts.tcp_fin_timeout,
            tcp_rst_timeout: span_opts.tcp_rst_timeout,
            udp_timeout: span_opts.udp_timeout,
            boot_time_offset_nanos,
            community_id_generator,
            iface_map,
            flow_span_map,
            packet_meta_rx,
            flow_span_tx,
        }
    }

    pub async fn run(mut self) {
        while let Some(packet) = self.packet_meta_rx.recv().await {
            if let Err(e) = self.upsert_packet_meta(packet).await {
                warn!("Failed to process packet: {}", e);
            }
        }
    }

    /// Determine the appropriate timeout duration for a flow based on protocol and state
    fn calculate_timeout(&self, packet: &PacketMeta, flow_span: &FlowSpan) -> Duration {
        match packet.proto {
            IpProto::Icmp | IpProto::Ipv6Icmp => self.icmp_timeout,
            IpProto::Tcp => {
                // Check if FIN or RST seen in current packet or flow history
                let has_fin = packet.fin()
                    || flow_span
                        .attributes
                        .flow_tcp_flags_bits
                        .is_some_and(|flags| flags & TCP_FLAG_FIN != 0);
                let has_rst = packet.rst()
                    || flow_span
                        .attributes
                        .flow_tcp_flags_bits
                        .is_some_and(|flags| flags & TCP_FLAG_RST != 0);

                if has_fin {
                    self.tcp_fin_timeout
                } else if has_rst {
                    self.tcp_rst_timeout
                } else {
                    self.tcp_timeout
                }
            }
            IpProto::Udp => self.udp_timeout,
            _ => self.generic_timeout,
        }
    }

    async fn upsert_packet_meta(&self, packet: PacketMeta) -> Result<(), Error> {
        let (src_addr, dst_addr) = match resolve_addrs(
            packet.ip_addr_type,
            packet.src_ipv4_addr,
            packet.dst_ipv4_addr,
            packet.src_ipv6_addr,
            packet.dst_ipv6_addr,
        ) {
            Ok(addrs) => addrs,
            Err(e) => {
                return Err(e);
            }
        };
        let src_port = packet.src_port();
        let dst_port = packet.dst_port();
        // For ICMP/ICMPv6, use type and code instead of ports
        let (community_src_port, community_dst_port) =
            if packet.proto == IpProto::Icmp || packet.proto == IpProto::Ipv6Icmp {
                (packet.icmp_type_id as u16, packet.icmp_code_id as u16)
            } else {
                (src_port, dst_port)
            };
        let community_id = self.community_id_generator.generate(
            src_addr,
            dst_addr,
            community_src_port,
            community_dst_port,
            packet.proto,
        );
        let iface_name = self.iface_map.get(&packet.ifindex);

        // Log packet details if debug logging is enabled
        log_packet_info(
            &packet,
            &community_id,
            iface_name.map(String::as_str).unwrap_or(""),
        );

        // Pre-calculate commonly used conditions for readability
        let has_mac = packet.src_mac_addr != [0; 6];
        let is_icmp = packet.proto == IpProto::Icmp;
        let is_icmpv6 = packet.proto == IpProto::Ipv6Icmp;
        let is_icmp_any = is_icmp || is_icmpv6;
        let is_ip_flow =
            packet.ether_type == EtherType::Ipv4 || packet.ether_type == EtherType::Ipv6;
        let is_ipv6 = packet.ether_type == EtherType::Ipv6;
        let is_tcp = packet.proto == IpProto::Tcp;

        let is_ipip = packet.ipip_ip_addr_type != IpAddrType::Unknown;
        let ipip_addrs = if is_ipip {
            resolve_addrs(
                packet.ipip_ip_addr_type,
                packet.ipip_src_ipv4_addr,
                packet.ipip_dst_ipv4_addr,
                packet.ipip_src_ipv6_addr,
                packet.ipip_dst_ipv6_addr,
            )
            .ok()
        } else {
            None
        };

        let tunnel_has_mac = packet.tunnel_src_mac_addr != [0; 6];
        let is_tunneled = packet.tunnel_type != TunnelType::None;
        let tunnel_addrs = if is_tunneled {
            resolve_addrs(
                packet.tunnel_ip_addr_type,
                packet.tunnel_src_ipv4_addr,
                packet.tunnel_dst_ipv4_addr,
                packet.tunnel_src_ipv6_addr,
                packet.tunnel_dst_ipv6_addr,
            )
            .ok()
        } else {
            None
        };
        let tunnel_has_id = packet.tunnel_type == TunnelType::Gre
            || packet.tunnel_type == TunnelType::Geneve
            || packet.tunnel_type == TunnelType::Vxlan;

        // Use DashMap's entry API to avoid unnecessary allocations
        // For new flows: String is moved into the map with no extra allocation
        // For existing flows: No allocation happens at all
        match self.flow_span_map.entry(community_id) {
            Entry::Vacant(vacant) => {
                // Create new flow span
                // Convert boot-relative timestamp to wall clock time
                let wall_time_nanos = packet.capture_time + self.boot_time_offset_nanos;
                let flow_span = FlowSpan {
                    start_time: UNIX_EPOCH + Duration::from_nanos(wall_time_nanos),
                    end_time: UNIX_EPOCH + Duration::from_nanos(wall_time_nanos),
                    span_kind: SpanKind::Internal,
                    attributes: SpanAttributes {
                        // General flow attributes
                        flow_community_id: vacant.key().clone(),
                        flow_connection_state: is_tcp
                            .then(|| ConnectionState::from_packet(&packet))
                            .flatten(),

                        // Network endpoints
                        source_address: src_addr,
                        source_port: src_port,
                        destination_address: dst_addr,
                        destination_port: dst_port,

                        // Network layer info
                        network_transport: packet.proto,
                        network_type: packet.ether_type,
                        network_interface_index: Some(packet.ifindex),
                        network_interface_name: iface_name.cloned(),
                        network_interface_mac: has_mac.then_some(MacAddr::new(
                            packet.src_mac_addr[0],
                            packet.src_mac_addr[1],
                            packet.src_mac_addr[2],
                            packet.src_mac_addr[3],
                            packet.src_mac_addr[4],
                            packet.src_mac_addr[5],
                        )),

                        // IP-specific fields (only populated for IPv4/IPv6 traffic)
                        flow_ip_dscp_id: is_ip_flow.then_some(packet.ip_dscp_id),
                        flow_ip_dscp_name: is_ip_flow.then_some(
                            IpDscp::try_from_u8(packet.ip_dscp_id)
                                .unwrap_or_default()
                                .as_str()
                                .to_string(),
                        ),
                        flow_ip_ecn_id: is_ip_flow.then_some(packet.ip_ecn_id),
                        flow_ip_ecn_name: is_ip_flow.then_some(
                            IpEcn::try_from_u8(packet.ip_ecn_id)
                                .unwrap_or_default()
                                .as_str()
                                .to_string(),
                        ),
                        flow_ip_ttl: is_ip_flow.then_some(packet.ip_ttl),
                        flow_ip_flow_label: is_ipv6.then_some(packet.ip_flow_label),

                        // ICMP fields (only populated for ICMP/ICMPv6 traffic)
                        flow_icmp_type_id: is_icmp_any.then_some(packet.icmp_type_id),
                        flow_icmp_type_name: if is_icmp {
                            network_types::icmp::get_icmpv4_type_name(packet.icmp_type_id)
                                .map(String::from)
                        } else if is_icmpv6 {
                            network_types::icmp::get_icmpv6_type_name(packet.icmp_type_id)
                                .map(String::from)
                        } else {
                            None
                        },
                        flow_icmp_code_id: is_icmp_any.then_some(packet.icmp_code_id),
                        flow_icmp_code_name: if is_icmp {
                            network_types::icmp::get_icmpv4_code_name(
                                packet.icmp_type_id,
                                packet.icmp_code_id,
                            )
                            .map(String::from)
                        } else if is_icmpv6 {
                            network_types::icmp::get_icmpv6_code_name(
                                packet.icmp_type_id,
                                packet.icmp_code_id,
                            )
                            .map(String::from)
                        } else {
                            None
                        },

                        // TCP flags (only populated for TCP traffic)
                        flow_tcp_flags_bits: is_tcp.then_some(packet.tcp_flags),
                        flow_tcp_flags_tags: is_tcp
                            .then(|| TcpFlags::from_packet(&packet).active_flags()),

                        // IPsec attributes
                        flow_ipsec_ah_spi: packet.ah_exists.then_some(packet.ipsec_ah_spi),
                        flow_ipsec_esp_spi: packet.esp_exists.then_some(packet.ipsec_esp_spi),
                        flow_ipsec_sender_index: packet
                            .wireguard_exists
                            .then_some(packet.ipsec_sender_index),
                        flow_ipsec_receiver_index: packet
                            .wireguard_exists
                            .then_some(packet.ipsec_receiver_index),

                        // Flow metrics
                        flow_bytes_delta: packet.l3_byte_count as i64,
                        flow_bytes_total: packet.l3_byte_count as i64,
                        flow_packets_delta: 1,
                        flow_packets_total: 1,
                        flow_reverse_bytes_delta: 0,
                        flow_reverse_bytes_total: 0,
                        flow_reverse_packets_delta: 0,
                        flow_reverse_packets_total: 0,

                        // TODO: eng-29
                        // TCP performance metrics
                        // flow_tcp_handshake_snd_latency: None,
                        // flow_tcp_handshake_snd_jitter: None,
                        // flow_tcp_handshake_cnd_latency: None,
                        // flow_tcp_handshake_cnd_jitter: None,
                        // flow_tcp_svc_latency: None,
                        // flow_tcp_svc_jitter: None,
                        // flow_tcp_rndtrip_latency: None,
                        // flow_tcp_rndtrip_jitter: None,

                        // Ip-in-Ip attributes
                        ipip_network_type: is_ipip.then_some(packet.ipip_ether_type),
                        ipip_network_transport: is_ipip.then_some(packet.ipip_proto),
                        ipip_source_address: ipip_addrs.map(|(src, _)| src),
                        ipip_destination_address: ipip_addrs.map(|(_, dst)| dst),

                        // Tunnel attributes
                        tunnel_type: is_tunneled.then_some(packet.tunnel_type),
                        tunnel_network_interface_mac: (is_tunneled && tunnel_has_mac).then_some(
                            MacAddr::new(
                                packet.tunnel_src_mac_addr[0],
                                packet.tunnel_src_mac_addr[1],
                                packet.tunnel_src_mac_addr[2],
                                packet.tunnel_src_mac_addr[3],
                                packet.tunnel_src_mac_addr[4],
                                packet.tunnel_src_mac_addr[5],
                            ),
                        ),
                        tunnel_network_type: is_tunneled.then_some(packet.tunnel_ether_type),
                        tunnel_network_transport: is_tunneled.then_some(packet.tunnel_proto),
                        tunnel_source_address: tunnel_addrs.map(|(src, _)| src),
                        tunnel_source_port: is_tunneled.then(|| packet.tunnel_src_port()),
                        tunnel_destination_address: tunnel_addrs.map(|(_, dst)| dst),
                        tunnel_destination_port: is_tunneled.then(|| packet.tunnel_dst_port()),
                        tunnel_id: tunnel_has_id.then_some(packet.tunnel_id),
                        tunnel_ipsec_ah_spi: packet
                            .tunnel_ah_exists
                            .then_some(packet.tunnel_ipsec_ah_spi),

                        // Filtering pipelines
                        matched_pipelines: Vec::new(),

                        // All other attributes default to None
                        ..Default::default()
                    },
                };

                debug!(
                    start_time = %format_timestamp(flow_span.start_time),
                    end_time = %format_timestamp(flow_span.end_time),
                    community_id = ?flow_span.attributes.flow_community_id,
                    source_address = ?flow_span.attributes.source_address,
                    source_port = flow_span.attributes.source_port,
                    destination_address = ?flow_span.attributes.destination_address,
                    destination_port = ?flow_span.attributes.destination_port,
                    network_type = ?flow_span.attributes.network_type,
                    network_transport = ?flow_span.attributes.network_transport,
                    tcp_flags = ?flow_span.attributes.flow_tcp_flags_bits,
                    flow_end_reason = ?flow_span.attributes.flow_end_reason,
                    flow_bytes_delta = ?flow_span.attributes.flow_bytes_delta,
                    flow_bytes_total = ?flow_span.attributes.flow_bytes_total,
                    flow_packets_delta = ?flow_span.attributes.flow_packets_delta,
                    flow_packets_total = ?flow_span.attributes.flow_packets_total,
                    flow_reverse_bytes_delta = ?flow_span.attributes.flow_reverse_bytes_delta,
                    flow_reverse_bytes_total = ?flow_span.attributes.flow_reverse_bytes_total,
                    flow_reverse_packets_delta = ?flow_span.attributes.flow_reverse_packets_delta,
                    flow_reverse_packets_total = ?flow_span.attributes.flow_reverse_packets_total,
                    "span created"
                );
                let initial_timeout = self.calculate_timeout(&packet, &flow_span);
                // Spawn tasks for this new flow
                // Note: Under extremely high packet rates with many short-lived flows,
                // task spawning overhead could become significant. Future optimization
                // could use a task pool pattern if this becomes a bottleneck.
                // Channel capacity of 32 handles bursts of packets without blocking/dropping
                let (timeout_reset_tx, timeout_reset_rx) = mpsc::channel(32);
                let community_id_for_tasks = vacant.key().clone();
                let record_task = tokio::spawn(record_task_loop(
                    community_id_for_tasks.clone(),
                    Arc::clone(&self.flow_span_map),
                    self.flow_span_tx.clone(),
                    self.max_record_interval,
                ));
                let timeout_task = tokio::spawn(timeout_task_loop(
                    community_id_for_tasks,
                    Arc::clone(&self.flow_span_map),
                    self.flow_span_tx.clone(),
                    initial_timeout,
                    timeout_reset_rx,
                ));
                let task_handles = FlowTaskHandles {
                    timeout_reset_tx,
                    record_task,
                    timeout_task,
                };
                let flow_entry = FlowEntry {
                    flow_span,
                    task_handles,
                };
                vacant.insert(flow_entry);
            }
            Entry::Occupied(mut occupied) => {
                let entry = occupied.get_mut();
                let flow_span = &mut entry.flow_span;
                debug!(
                    community_id = ?flow_span.attributes.flow_community_id,
                    source_address = ?flow_span.attributes.source_address,
                    source_port = ?flow_span.attributes.source_port,
                    destination_address = ?flow_span.attributes.destination_address,
                    destination_port = ?flow_span.attributes.destination_port,
                    "span updating"
                );

                // Update end time - convert boot-relative timestamp to wall clock time
                let wall_time_nanos = packet.capture_time + self.boot_time_offset_nanos;
                flow_span.end_time = UNIX_EPOCH + Duration::from_nanos(wall_time_nanos);

                // Determine if this packet is in the forward or reverse direction
                let is_forward = flow_span.attributes.source_address == src_addr
                    && flow_span.attributes.destination_address == dst_addr;

                let bytes = packet.l3_byte_count as i64;

                if is_forward {
                    // Forward direction: update forward metrics
                    flow_span.attributes.flow_bytes_total += bytes;
                    flow_span.attributes.flow_bytes_delta += bytes;
                    flow_span.attributes.flow_packets_total += 1;
                    flow_span.attributes.flow_packets_delta += 1;
                } else {
                    // Reverse direction: update reverse metrics
                    flow_span.attributes.flow_reverse_bytes_total += bytes;
                    flow_span.attributes.flow_reverse_bytes_delta += bytes;
                    flow_span.attributes.flow_reverse_packets_total += 1;
                    flow_span.attributes.flow_reverse_packets_delta += 1;
                }

                // Update TCP-specific fields if this is a TCP flow
                if is_tcp {
                    // OR the TCP flags together to capture all flags seen in the flow
                    let existing_flags = flow_span.attributes.flow_tcp_flags_bits.unwrap_or(0);
                    let combined_flags = existing_flags | packet.tcp_flags;
                    flow_span.attributes.flow_tcp_flags_bits = Some(combined_flags);
                    flow_span.attributes.flow_tcp_flags_tags =
                        Some(TcpFlags::flags_from_bits(combined_flags));

                    // Update connection state based on current state and new packet
                    if let Some(current_state) = flow_span.attributes.flow_connection_state {
                        // Transition to next state based on current state and packet flags
                        let new_state =
                            ConnectionState::next_state(current_state, &packet, is_forward);
                        flow_span.attributes.flow_connection_state = Some(new_state);
                    } else if let Some(initial_state) = ConnectionState::from_packet(&packet) {
                        // First time seeing this flow - initialize state
                        flow_span.attributes.flow_connection_state = Some(initial_state);
                    }
                }

                debug!(
                    start_time = %format_timestamp(flow_span.start_time),
                    end_time = %format_timestamp(flow_span.end_time),
                    community_id = ?flow_span.attributes.flow_community_id,
                    source_address = ?flow_span.attributes.source_address,
                    source_port = flow_span.attributes.source_port,
                    destination_address = ?flow_span.attributes.destination_address,
                    destination_port = ?flow_span.attributes.destination_port,
                    network_type = ?flow_span.attributes.network_type,
                    network_transport = ?flow_span.attributes.network_transport,
                    tcp_flags = ?flow_span.attributes.flow_tcp_flags_bits,
                    flow_end_reason = ?flow_span.attributes.flow_end_reason,
                    flow_bytes_delta = ?flow_span.attributes.flow_bytes_delta,
                    flow_bytes_total = ?flow_span.attributes.flow_bytes_total,
                    flow_packets_delta = ?flow_span.attributes.flow_packets_delta,
                    flow_packets_total = ?flow_span.attributes.flow_packets_total,
                    flow_reverse_bytes_delta = ?flow_span.attributes.flow_reverse_bytes_delta,
                    flow_reverse_bytes_total = ?flow_span.attributes.flow_reverse_bytes_total,
                    flow_reverse_packets_delta = ?flow_span.attributes.flow_reverse_packets_delta,
                    flow_reverse_packets_total = ?flow_span.attributes.flow_reverse_packets_total,
                    "span updated"
                );
                // Calculate new timeout (might have changed due to TCP state)
                let new_timeout = self.calculate_timeout(&packet, flow_span);

                // Signal timeout task to reset with potentially new duration
                // Note: If the channel is full, this will drop the timeout update.
                // This is acceptable as it means the timeout task is processing updates,
                // and a subsequent packet will trigger another reset attempt.
                match entry
                    .task_handles
                    .timeout_reset_tx
                    .try_send(TimeoutUpdate::Reset(new_timeout))
                {
                    Ok(_) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        // This is potentially problematic - flow might timeout early
                        debug!(
                            "timeout reset channel full for flow {}, flow may timeout early",
                            occupied.key()
                        );
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        debug!("timeout reset channel closed for flow {}", occupied.key());
                    }
                }
            }
        }

        Ok(())
    }
}

/// Errors that can occur during boot time offset calculation
#[derive(Debug)]
pub enum BootTimeError {
    /// System clock is before UNIX epoch
    SystemClockBeforeEpoch(std::time::SystemTimeError),
    /// Failed to read /proc/uptime
    ReadProcUptime(std::io::Error),
    /// Failed to parse uptime value from /proc/uptime
    ParseUptime(String),
}

impl std::fmt::Display for BootTimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootTimeError::SystemClockBeforeEpoch(e) => {
                write!(f, "system clock is before unix epoch: {e}")
            }
            BootTimeError::ReadProcUptime(e) => {
                write!(f, "failed to read /proc/uptime: {e}")
            }
            BootTimeError::ParseUptime(content) => {
                write!(
                    f,
                    "failed to parse uptime from /proc/uptime (content: '{content}')",
                )
            }
        }
    }
}

impl std::error::Error for BootTimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BootTimeError::SystemClockBeforeEpoch(e) => Some(e),
            BootTimeError::ReadProcUptime(e) => Some(e),
            BootTimeError::ParseUptime(_) => None,
        }
    }
}

/// Determine the appropriate flow end reason based on TCP flags
///
/// If FIN or RST flags are present, returns EndOfFlowDetected.
/// Otherwise, returns the provided default reason.
fn determine_flow_end_reason(
    tcp_flags: Option<u8>,
    default_reason: FlowEndReason,
) -> FlowEndReason {
    if let Some(flags) = tcp_flags {
        if (flags & (TCP_FLAG_FIN | TCP_FLAG_RST)) != 0 {
            FlowEndReason::EndOfFlowDetected
        } else {
            default_reason
        }
    } else {
        default_reason
    }
}

/// Record task loop - periodically records active flows
///
/// This task runs in a loop, sleeping for the configured `max_record_interval`.
/// When it wakes up, it records the current state of the flow span and resets
/// the delta counters to prepare for the next interval.
async fn record_task_loop(
    community_id: String,
    flow_span_map: FlowSpanMap,
    flow_span_tx: mpsc::Sender<FlowSpan>,
    interval: Duration,
) {
    loop {
        tokio::time::sleep(interval).await;

        // Access the flow and record it
        if let Some(mut entry) = flow_span_map.get_mut(&community_id) {
            let flow_span = &mut entry.flow_span;

            // Clone the flow span for recording
            let mut recorded_span = flow_span.clone();
            recorded_span.attributes.flow_end_reason = Some(determine_flow_end_reason(
                flow_span.attributes.flow_tcp_flags_bits,
                FlowEndReason::ActiveTimeout,
            ));

            // Send the recorded span
            if flow_span_tx.send(recorded_span).await.is_err() {
                warn!(
                    "Failed to send flow span for recording (community_id: {})",
                    community_id
                );
                // Channel closed, exit task
                break;
            }

            // Reset delta counters for next interval
            flow_span.attributes.flow_bytes_delta = 0;
            flow_span.attributes.flow_packets_delta = 0;
            flow_span.attributes.flow_reverse_bytes_delta = 0;
            flow_span.attributes.flow_reverse_packets_delta = 0;
        } else {
            // Flow no longer exists, exit task
            break;
        }
    }
}

/// Timeout task loop - handles flow idle timeout
///
/// This task uses tokio::select! to wait for either:
/// 1. The timeout duration to elapse (flow is idle)
/// 2. A reset signal from packet processing (flow still active)
///
/// When the timeout elapses, the flow is recorded (if it has packets) and removed.
async fn timeout_task_loop(
    community_id: String,
    flow_span_map: FlowSpanMap,
    flow_span_tx: mpsc::Sender<FlowSpan>,
    mut timeout_duration: Duration,
    mut timeout_reset_rx: mpsc::Receiver<TimeoutUpdate>,
) {
    loop {
        tokio::select! {
            // Timeout elapsed - flow is idle
            _ = tokio::time::sleep(timeout_duration) => {
                // Remove the flow and record it if it has packets
                if let Some((_, entry)) = flow_span_map.remove(&community_id) {
                    let flow_span = entry.flow_span;

                    // Only record if the flow has seen at least one packet
                    let has_packets = flow_span.attributes.flow_packets_total > 0
                        || flow_span.attributes.flow_reverse_packets_total > 0;

                    if has_packets {
                        let mut recorded_span = flow_span.clone();
                        recorded_span.attributes.flow_end_reason = Some(determine_flow_end_reason(
                            flow_span.attributes.flow_tcp_flags_bits,
                            FlowEndReason::IdleTimeout,
                        ));

                        if flow_span_tx.send(recorded_span).await.is_err() {
                            warn!(
                                "failed to send timed-out flow span (community_id: {})",
                                community_id
                            );
                        }
                    }

                    // Abort the record task
                    entry.task_handles.record_task.abort();
                }

                // Exit the timeout task
                break;
            }
            // Reset signal received - flow still active
            Some(TimeoutUpdate::Reset(new_duration)) = timeout_reset_rx.recv() => {
                // Update timeout duration and continue loop
                // The sleep will be restarted in the next iteration
                timeout_duration = new_duration;
            }
        }
    }
}

/// Log packet information in a structured way
fn log_packet_info(packet_meta: &PacketMeta, community_id: &str, iface_name: &str) {
    let src_port = packet_meta.src_port();
    let dst_port = packet_meta.dst_port();

    // Check if this is tunneled traffic
    let is_tunneled =
        packet_meta.tunnel_src_ipv4_addr != [0; 4] || packet_meta.tunnel_src_ipv6_addr != [0; 16];

    if is_tunneled {
        let tunnel_src_ip = format_ip(
            packet_meta.tunnel_ip_addr_type,
            packet_meta.tunnel_src_ipv4_addr,
            packet_meta.tunnel_src_ipv6_addr,
        );
        let tunnel_dst_ip = format_ip(
            packet_meta.tunnel_ip_addr_type,
            packet_meta.tunnel_dst_ipv4_addr,
            packet_meta.tunnel_dst_ipv6_addr,
        );
        let inner_src_ip = format_ip(
            packet_meta.ip_addr_type,
            packet_meta.src_ipv4_addr,
            packet_meta.src_ipv6_addr,
        );
        let inner_dst_ip = format_ip(
            packet_meta.ip_addr_type,
            packet_meta.dst_ipv4_addr,
            packet_meta.dst_ipv6_addr,
        );
        let tunnel_src_port = packet_meta.tunnel_src_port();
        let tunnel_dst_port = packet_meta.tunnel_dst_port();

        debug!(
            "[{iface_name}] Tunneled {} packet: {} | Tunnel: {}:{} -> {}:{} ({}) | Inner: {}:{} -> {}:{} | bytes: {}",
            packet_meta.proto,
            community_id,
            tunnel_src_ip,
            tunnel_src_port,
            tunnel_dst_ip,
            tunnel_dst_port,
            packet_meta.tunnel_proto,
            inner_src_ip,
            src_port,
            inner_dst_ip,
            dst_port,
            packet_meta.l3_byte_count,
        );
    } else {
        let src_ip = format_ip(
            packet_meta.ip_addr_type,
            packet_meta.src_ipv4_addr,
            packet_meta.src_ipv6_addr,
        );
        let dst_ip = format_ip(
            packet_meta.ip_addr_type,
            packet_meta.dst_ipv4_addr,
            packet_meta.dst_ipv6_addr,
        );

        debug!(
            "[{iface_name}] {} packet: {} | {}:{} -> {}:{} | bytes: {}",
            packet_meta.proto,
            community_id,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            packet_meta.l3_byte_count,
        );
    }
}

/// Helper function to format IP address based on type
fn format_ip(addr_type: IpAddrType, ipv4_addr: [u8; 4], ipv6_addr: [u8; 16]) -> String {
    match addr_type {
        IpAddrType::Unknown => "unknown".to_string(),
        IpAddrType::Ipv4 => Ipv4Addr::from(ipv4_addr).to_string(),
        IpAddrType::Ipv6 => Ipv6Addr::from(ipv6_addr).to_string(),
    }
}

/// Helper function to format SystemTime as ISO 8601 timestamp (e.g., 2023-09-27T10:00:00.123Z)
fn format_timestamp(time: std::time::SystemTime) -> String {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let secs = duration.as_secs() as i64;
            let nanos = duration.subsec_nanos();
            let datetime = DateTime::<Utc>::from_timestamp(secs, nanos)
                .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).unwrap());
            datetime.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
        }
        Err(_) => "invalid_time".to_string(),
    }
}

/// Calculate the offset needed to convert boot-relative timestamps (from bpf_ktime_get_boot_ns)
/// to wall clock timestamps.
///
/// bpf_ktime_get_boot_ns() returns time in nanoseconds since boot using CLOCK_BOOTTIME,
/// which includes suspend time. This matches /proc/uptime in userspace.
///
/// This function calculates: wall_clock_time_ns - boot_time_ns = offset
///
/// Returns an error if the boot time cannot be determined, as this would make all
/// timestamps incorrect and render the program's output useless.
fn calculate_boot_time_offset_nanos() -> Result<u64, BootTimeError> {
    use std::time::SystemTime;

    // Get current wall clock time since UNIX epoch
    let now = SystemTime::now();
    let now_since_epoch = now
        .duration_since(UNIX_EPOCH)
        .map_err(BootTimeError::SystemClockBeforeEpoch)?;
    let wall_clock_nanos = now_since_epoch.as_nanos() as u64;

    // Read boot time from /proc/uptime (uses CLOCK_BOOTTIME, matching bpf_ktime_get_boot_ns)
    // Format: "uptime_seconds idle_seconds"
    let uptime_content =
        std::fs::read_to_string("/proc/uptime").map_err(BootTimeError::ReadProcUptime)?;

    let uptime_secs = uptime_content
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<f64>().ok())
        .ok_or_else(|| BootTimeError::ParseUptime(uptime_content.clone()))?;

    // Convert uptime to nanoseconds
    let uptime_nanos = (uptime_secs * 1_000_000_000.0) as u64;

    // Calculate offset: current_time - uptime = boot_time
    let offset = wall_clock_nanos.saturating_sub(uptime_nanos);

    debug!(
        "Boot time offset calculated: {} ns (wall clock: {} ns, uptime: {} ns)",
        offset, wall_clock_nanos, uptime_nanos
    );

    Ok(offset)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    /// Helper to create a test PacketWorker
    fn create_test_worker() -> (PacketWorker, mpsc::Receiver<FlowSpan>) {
        let span_opts = SpanOptions::default();
        let (packet_tx, packet_rx) = mpsc::channel(100);
        let (flow_span_tx, flow_span_rx) = mpsc::channel(100);
        let flow_span_map = Arc::new(DashMap::with_capacity_and_hasher(
            100,
            FxBuildHasher::default(),
        ));
        let community_id_generator = CommunityIdGenerator::new(span_opts.community_id_seed);
        let iface_map = HashMap::new();

        let worker = PacketWorker {
            max_record_interval: span_opts.max_record_interval,
            generic_timeout: span_opts.generic_timeout,
            icmp_timeout: span_opts.icmp_timeout,
            tcp_timeout: span_opts.tcp_timeout,
            tcp_fin_timeout: span_opts.tcp_fin_timeout,
            tcp_rst_timeout: span_opts.tcp_rst_timeout,
            udp_timeout: span_opts.udp_timeout,
            community_id_generator,
            iface_map,
            flow_span_map,
            packet_meta_rx: packet_rx,
            flow_span_tx: flow_span_tx.clone(),
            boot_time_offset_nanos: 0, // For tests, assume capture_time is already wall clock
        };

        drop(packet_tx); // Close the packet channel so worker will exit

        (worker, flow_span_rx)
    }

    /// Helper to create a basic test packet
    fn create_test_packet(proto: IpProto, tcp_flags: u8) -> PacketMeta {
        let mut packet = PacketMeta::default();
        packet.ip_addr_type = IpAddrType::Ipv4;
        packet.src_ipv4_addr = [192, 168, 1, 1];
        packet.dst_ipv4_addr = [192, 168, 1, 2];
        packet.src_port = 12345_u16.to_be_bytes();
        packet.dst_port = 80_u16.to_be_bytes();
        packet.proto = proto;
        packet.ether_type = EtherType::Ipv4;
        packet.tcp_flags = tcp_flags;
        packet.l3_byte_count = 100;
        packet.capture_time = 1_000_000_000; // 1 second in nanoseconds
        packet.ifindex = 1;
        packet
    }

    /// Helper to create a test FlowSpan
    fn create_test_flow_span(proto: IpProto, tcp_flags: u8) -> FlowSpan {
        FlowSpan {
            start_time: UNIX_EPOCH + Duration::from_secs(1),
            end_time: UNIX_EPOCH + Duration::from_secs(1),
            span_kind: SpanKind::Internal,
            attributes: SpanAttributes {
                flow_community_id: "test".to_string(),
                source_address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                source_port: 12345,
                destination_address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
                destination_port: 80,
                network_transport: proto,
                network_type: EtherType::Ipv4,
                network_interface_index: Some(1),
                flow_tcp_flags_bits: Some(tcp_flags),
                flow_bytes_delta: 100,
                flow_bytes_total: 100,
                flow_packets_delta: 1,
                flow_packets_total: 1,
                flow_reverse_bytes_delta: 0,
                flow_reverse_bytes_total: 0,
                flow_reverse_packets_delta: 0,
                flow_reverse_packets_total: 0,
                ..Default::default()
            },
        }
    }

    #[test]
    fn test_calculate_timeout_icmp() {
        let (worker, _rx) = create_test_worker();
        let packet = create_test_packet(IpProto::Icmp, 0);
        let flow_span = create_test_flow_span(IpProto::Icmp, 0);

        let timeout = worker.calculate_timeout(&packet, &flow_span);
        assert_eq!(timeout, worker.icmp_timeout);
    }

    #[test]
    fn test_calculate_timeout_icmpv6() {
        let (worker, _rx) = create_test_worker();
        let packet = create_test_packet(IpProto::Ipv6Icmp, 0);
        let flow_span = create_test_flow_span(IpProto::Ipv6Icmp, 0);

        let timeout = worker.calculate_timeout(&packet, &flow_span);
        assert_eq!(timeout, worker.icmp_timeout);
    }

    #[test]
    fn test_calculate_timeout_tcp_normal() {
        let (worker, _rx) = create_test_worker();
        let packet = create_test_packet(IpProto::Tcp, 0x10); // ACK only
        let flow_span = create_test_flow_span(IpProto::Tcp, 0x10);

        let timeout = worker.calculate_timeout(&packet, &flow_span);
        assert_eq!(timeout, worker.tcp_timeout);
    }

    #[test]
    fn test_calculate_timeout_tcp_with_fin() {
        let (worker, _rx) = create_test_worker();
        let packet = create_test_packet(IpProto::Tcp, 0x01); // FIN flag
        let flow_span = create_test_flow_span(IpProto::Tcp, 0x01);

        let timeout = worker.calculate_timeout(&packet, &flow_span);
        assert_eq!(timeout, worker.tcp_fin_timeout);
    }

    #[test]
    fn test_calculate_timeout_tcp_with_rst() {
        let (worker, _rx) = create_test_worker();
        let packet = create_test_packet(IpProto::Tcp, 0x04); // RST flag
        let flow_span = create_test_flow_span(IpProto::Tcp, 0x04);

        let timeout = worker.calculate_timeout(&packet, &flow_span);
        assert_eq!(timeout, worker.tcp_rst_timeout);
    }

    #[test]
    fn test_calculate_timeout_tcp_historical_fin() {
        let (worker, _rx) = create_test_worker();
        // Current packet has no FIN, but flow has seen FIN before
        let packet = create_test_packet(IpProto::Tcp, 0x10); // ACK only
        let flow_span = create_test_flow_span(IpProto::Tcp, 0x11); // FIN + ACK in history

        let timeout = worker.calculate_timeout(&packet, &flow_span);
        assert_eq!(timeout, worker.tcp_fin_timeout);
    }

    #[test]
    fn test_calculate_timeout_tcp_historical_rst() {
        let (worker, _rx) = create_test_worker();
        // Current packet has no RST, but flow has seen RST before
        let packet = create_test_packet(IpProto::Tcp, 0x10); // ACK only
        let flow_span = create_test_flow_span(IpProto::Tcp, 0x14); // RST + ACK in history

        let timeout = worker.calculate_timeout(&packet, &flow_span);
        assert_eq!(timeout, worker.tcp_rst_timeout);
    }

    #[test]
    fn test_calculate_timeout_udp() {
        let (worker, _rx) = create_test_worker();
        let packet = create_test_packet(IpProto::Udp, 0);
        let flow_span = create_test_flow_span(IpProto::Udp, 0);

        let timeout = worker.calculate_timeout(&packet, &flow_span);
        assert_eq!(timeout, worker.udp_timeout);
    }

    #[test]
    fn test_calculate_timeout_generic() {
        let (worker, _rx) = create_test_worker();
        let packet = create_test_packet(IpProto::Gre, 0); // GRE is generic
        let flow_span = create_test_flow_span(IpProto::Gre, 0);

        let timeout = worker.calculate_timeout(&packet, &flow_span);
        assert_eq!(timeout, worker.generic_timeout);
    }

    #[tokio::test]
    async fn test_new_flow_creates_tasks() {
        let (worker, mut flow_span_rx) = create_test_worker();
        let packet = create_test_packet(IpProto::Tcp, 0x02); // SYN

        // Process the packet
        worker.upsert_packet_meta(packet).await.unwrap();

        // Verify flow was created in map
        assert_eq!(worker.flow_span_map.len(), 1);

        // Verify the flow entry has task handles
        let entry = worker.flow_span_map.iter().next().unwrap();
        assert!(entry.task_handles.timeout_reset_tx.capacity() > 0);

        // Wait a moment for tasks to potentially send something
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Tasks should not have sent anything yet (not timed out)
        assert!(flow_span_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_existing_flow_updates_metrics() {
        let (worker, _flow_span_rx) = create_test_worker();

        // First packet - creates flow
        let packet1 = create_test_packet(IpProto::Tcp, 0x02); // SYN
        worker.upsert_packet_meta(packet1).await.unwrap();

        // Get initial metrics
        let initial_packets = {
            let entry: dashmap::mapref::multiple::RefMulti<'_, String, FlowEntry> =
                worker.flow_span_map.iter().next().unwrap();
            entry.flow_span.attributes.flow_packets_total
        };

        // Second packet - updates flow
        let packet2 = create_test_packet(IpProto::Tcp, 0x12); // SYN+ACK
        worker.upsert_packet_meta(packet2).await.unwrap();

        // Verify metrics updated
        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(
            entry.flow_span.attributes.flow_packets_total,
            initial_packets + 1
        );
        assert_eq!(entry.flow_span.attributes.flow_packets_delta, 2);
    }

    #[tokio::test]
    async fn test_tcp_flags_accumulate() {
        let (worker, _flow_span_rx) = create_test_worker();

        // First packet with SYN
        let packet1 = create_test_packet(IpProto::Tcp, 0x02);
        worker.upsert_packet_meta(packet1).await.unwrap();

        // Second packet with ACK
        let packet2 = create_test_packet(IpProto::Tcp, 0x10);
        worker.upsert_packet_meta(packet2).await.unwrap();

        // Verify flags are OR'd together
        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(
            entry.flow_span.attributes.flow_tcp_flags_bits,
            Some(0x02 | 0x10)
        );
    }

    #[tokio::test]
    async fn test_bidirectional_flow_tracking() {
        let (worker, _flow_span_rx) = create_test_worker();

        // First direction packet
        let mut packet1 = create_test_packet(IpProto::Tcp, 0x02);
        packet1.src_ipv4_addr = [192, 168, 1, 1];
        packet1.dst_ipv4_addr = [192, 168, 1, 2];
        packet1.src_port = 12345_u16.to_be_bytes();
        packet1.dst_port = 80_u16.to_be_bytes();
        packet1.l3_byte_count = 100;
        worker.upsert_packet_meta(packet1).await.unwrap();

        // Verify first packet created the flow
        assert_eq!(worker.flow_span_map.len(), 1);

        // Second direction packet (src/dst and ports swapped)
        let mut packet2 = create_test_packet(IpProto::Tcp, 0x12);
        packet2.src_ipv4_addr = [192, 168, 1, 2];
        packet2.dst_ipv4_addr = [192, 168, 1, 1];
        packet2.src_port = 80_u16.to_be_bytes();
        packet2.dst_port = 12345_u16.to_be_bytes();
        packet2.l3_byte_count = 200;
        worker.upsert_packet_meta(packet2).await.unwrap();

        // Should still be only one flow (same community ID)
        assert_eq!(worker.flow_span_map.len(), 1);

        // Verify both directions tracked
        let entry = worker.flow_span_map.iter().next().unwrap();
        let total_bytes = entry.flow_span.attributes.flow_bytes_total
            + entry.flow_span.attributes.flow_reverse_bytes_total;
        let total_packets = entry.flow_span.attributes.flow_packets_total
            + entry.flow_span.attributes.flow_reverse_packets_total;

        // Both packets should be counted
        assert_eq!(total_packets, 2, "Should have 2 packets total");
        assert_eq!(total_bytes, 300, "Should have 300 bytes total (100 + 200)");

        // Verify one direction has 100 bytes and the other has 200
        assert!(
            (entry.flow_span.attributes.flow_bytes_total == 100
                && entry.flow_span.attributes.flow_reverse_bytes_total == 200)
                || (entry.flow_span.attributes.flow_bytes_total == 200
                    && entry.flow_span.attributes.flow_reverse_bytes_total == 100),
            "One direction should have 100 bytes, the other 200"
        );
    }

    #[tokio::test]
    async fn test_record_task_periodically_records() {
        let flow_span_map = Arc::new(DashMap::with_capacity_and_hasher(
            10,
            FxBuildHasher::default(),
        ));
        let (flow_span_tx, mut flow_span_rx) = mpsc::channel(10);

        // Create a flow entry
        let flow_span = create_test_flow_span(IpProto::Tcp, 0x02);
        let (timeout_reset_tx, _timeout_reset_rx) = mpsc::channel(32);
        let record_task = tokio::spawn(async {}); // Dummy task
        let timeout_task = tokio::spawn(async {}); // Dummy task

        let entry = FlowEntry {
            flow_span,
            task_handles: FlowTaskHandles {
                timeout_reset_tx,
                record_task,
                timeout_task,
            },
        };
        flow_span_map.insert("test_flow".to_string(), entry);

        // Spawn record task with short interval
        let record_handle = tokio::spawn(record_task_loop(
            "test_flow".to_string(),
            Arc::clone(&flow_span_map),
            flow_span_tx,
            Duration::from_millis(50), // Short interval for testing
        ));

        // Wait for first recording
        tokio::time::timeout(Duration::from_millis(100), flow_span_rx.recv())
            .await
            .expect("Should receive recorded span")
            .expect("Channel should not be closed");

        // Verify delta counters were reset
        let entry = flow_span_map.get("test_flow").unwrap();
        assert_eq!(entry.flow_span.attributes.flow_bytes_delta, 0);
        assert_eq!(entry.flow_span.attributes.flow_packets_delta, 0);
        assert_eq!(entry.flow_span.attributes.flow_reverse_bytes_delta, 0);
        assert_eq!(entry.flow_span.attributes.flow_reverse_packets_delta, 0);

        // Cleanup
        record_handle.abort();
    }

    #[tokio::test]
    async fn test_timeout_task_fires_after_timeout() {
        let flow_span_map = Arc::new(DashMap::with_capacity_and_hasher(
            10,
            FxBuildHasher::default(),
        ));
        let (flow_span_tx, mut flow_span_rx) = mpsc::channel(10);

        // Create a flow entry
        let flow_span = create_test_flow_span(IpProto::Tcp, 0x02);
        let (timeout_reset_tx, timeout_reset_rx) = mpsc::channel(32);
        let record_task = tokio::spawn(async {}); // Dummy task
        let timeout_task_dummy = tokio::spawn(async {}); // Placeholder

        let entry = FlowEntry {
            flow_span,
            task_handles: FlowTaskHandles {
                timeout_reset_tx,
                record_task,
                timeout_task: timeout_task_dummy,
            },
        };
        flow_span_map.insert("test_flow".to_string(), entry);

        // Spawn timeout task with short timeout
        tokio::spawn(timeout_task_loop(
            "test_flow".to_string(),
            Arc::clone(&flow_span_map),
            flow_span_tx,
            Duration::from_millis(50), // Short timeout for testing
            timeout_reset_rx,
        ));

        // Wait for timeout to fire
        let recorded_span = tokio::time::timeout(Duration::from_millis(100), flow_span_rx.recv())
            .await
            .expect("Should receive timed-out span")
            .expect("Channel should not be closed");

        // Verify flow was removed from map
        assert!(flow_span_map.get("test_flow").is_none());

        // Verify end reason is IdleTimeout
        assert_eq!(
            recorded_span.attributes.flow_end_reason,
            Some(FlowEndReason::IdleTimeout)
        );
    }

    #[tokio::test]
    async fn test_timeout_task_resets_on_signal() {
        let flow_span_map = Arc::new(DashMap::with_capacity_and_hasher(
            10,
            FxBuildHasher::default(),
        ));
        let (flow_span_tx, mut flow_span_rx) = mpsc::channel(10);

        // Create a flow entry
        let flow_span = create_test_flow_span(IpProto::Tcp, 0x02);
        let (timeout_reset_tx, timeout_reset_rx) = mpsc::channel(32);
        let record_task = tokio::spawn(async {}); // Dummy task
        let timeout_task_dummy = tokio::spawn(async {}); // Placeholder

        let entry = FlowEntry {
            flow_span,
            task_handles: FlowTaskHandles {
                timeout_reset_tx: timeout_reset_tx.clone(),
                record_task,
                timeout_task: timeout_task_dummy,
            },
        };
        flow_span_map.insert("test_flow".to_string(), entry);

        // Spawn timeout task with 100ms timeout
        tokio::spawn(timeout_task_loop(
            "test_flow".to_string(),
            Arc::clone(&flow_span_map),
            flow_span_tx,
            Duration::from_millis(100),
            timeout_reset_rx,
        ));

        // Send reset signals periodically to keep flow alive
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            timeout_reset_tx
                .send(TimeoutUpdate::Reset(Duration::from_millis(100)))
                .await
                .unwrap();
        }

        // Verify flow still exists after multiple resets
        assert!(flow_span_map.get("test_flow").is_some());

        // Verify no timeout fired
        assert!(flow_span_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_timeout_task_ignores_zero_packet_flows() {
        let flow_span_map = Arc::new(DashMap::with_capacity_and_hasher(
            10,
            FxBuildHasher::default(),
        ));
        let (flow_span_tx, mut flow_span_rx) = mpsc::channel(10);

        // Create a flow with zero packets
        let mut flow_span = create_test_flow_span(IpProto::Tcp, 0x02);
        flow_span.attributes.flow_packets_total = 0;
        flow_span.attributes.flow_reverse_packets_total = 0;

        let (timeout_reset_tx, timeout_reset_rx) = mpsc::channel(32);
        let record_task = tokio::spawn(async {}); // Dummy task
        let timeout_task_dummy = tokio::spawn(async {}); // Placeholder

        let entry = FlowEntry {
            flow_span,
            task_handles: FlowTaskHandles {
                timeout_reset_tx,
                record_task,
                timeout_task: timeout_task_dummy,
            },
        };
        flow_span_map.insert("test_flow".to_string(), entry);

        // Spawn timeout task with short timeout
        tokio::spawn(timeout_task_loop(
            "test_flow".to_string(),
            Arc::clone(&flow_span_map),
            flow_span_tx,
            Duration::from_millis(50),
            timeout_reset_rx,
        ));

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify flow was removed but no span was sent
        assert!(flow_span_map.get("test_flow").is_none());
        assert!(flow_span_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_record_task_exits_when_flow_removed() {
        let flow_span_map = Arc::new(DashMap::with_capacity_and_hasher(
            10,
            FxBuildHasher::default(),
        ));
        let (flow_span_tx, _flow_span_rx) = mpsc::channel(10);

        // Create a flow entry
        let flow_span = create_test_flow_span(IpProto::Tcp, 0x02);
        let (timeout_reset_tx, _timeout_reset_rx) = mpsc::channel(32);
        let record_task = tokio::spawn(async {}); // Dummy task
        let timeout_task = tokio::spawn(async {}); // Dummy task

        let entry = FlowEntry {
            flow_span,
            task_handles: FlowTaskHandles {
                timeout_reset_tx,
                record_task,
                timeout_task,
            },
        };
        flow_span_map.insert("test_flow".to_string(), entry);

        // Spawn record task with short interval
        let record_handle = tokio::spawn(record_task_loop(
            "test_flow".to_string(),
            Arc::clone(&flow_span_map),
            flow_span_tx,
            Duration::from_millis(50),
        ));

        // Wait a bit, then remove the flow
        tokio::time::sleep(Duration::from_millis(25)).await;
        flow_span_map.remove("test_flow");

        // Wait for task to exit
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify task completed (would be pending if still running)
        assert!(record_handle.is_finished());
    }

    #[test]
    fn test_determine_flow_end_reason_with_fin() {
        let reason = determine_flow_end_reason(Some(TCP_FLAG_FIN), FlowEndReason::IdleTimeout);
        assert_eq!(reason, FlowEndReason::EndOfFlowDetected);
    }

    #[test]
    fn test_determine_flow_end_reason_with_rst() {
        let reason = determine_flow_end_reason(Some(TCP_FLAG_RST), FlowEndReason::ActiveTimeout);
        assert_eq!(reason, FlowEndReason::EndOfFlowDetected);
    }

    #[test]
    fn test_determine_flow_end_reason_with_both_fin_and_rst() {
        let reason = determine_flow_end_reason(
            Some(TCP_FLAG_FIN | TCP_FLAG_RST),
            FlowEndReason::IdleTimeout,
        );
        assert_eq!(reason, FlowEndReason::EndOfFlowDetected);
    }

    #[test]
    fn test_determine_flow_end_reason_no_flags() {
        let reason = determine_flow_end_reason(None, FlowEndReason::IdleTimeout);
        assert_eq!(reason, FlowEndReason::IdleTimeout);
    }

    #[test]
    fn test_determine_flow_end_reason_other_flags() {
        let reason = determine_flow_end_reason(Some(0x10), FlowEndReason::ActiveTimeout); // ACK only
        assert_eq!(reason, FlowEndReason::ActiveTimeout);
    }

    #[test]
    fn test_format_ip_ipv4() {
        let result = format_ip(IpAddrType::Ipv4, [192, 168, 1, 1], [0; 16]);
        assert_eq!(result, "192.168.1.1");
    }

    #[test]
    fn test_format_ip_ipv6() {
        let result = format_ip(
            IpAddrType::Ipv6,
            [0; 4],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        );
        assert!(result.contains("2001:db8"));
    }

    #[test]
    fn test_format_ip_unknown() {
        let result = format_ip(IpAddrType::Unknown, [0; 4], [0; 16]);
        assert_eq!(result, "unknown");
    }

    #[tokio::test]
    async fn test_tcp_connection_state_progression() {
        let (worker, _flow_span_rx) = create_test_worker();

        // SYN - initial packet
        let packet1 = create_test_packet(IpProto::Tcp, 0x02); // SYN
        worker.upsert_packet_meta(packet1).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(
            entry.flow_span.attributes.flow_connection_state,
            Some(ConnectionState::SynSent)
        );
        drop(entry);

        // SYN-ACK - response packet
        let packet2 = create_test_packet(IpProto::Tcp, 0x12); // SYN+ACK
        worker.upsert_packet_meta(packet2).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(
            entry.flow_span.attributes.flow_connection_state,
            Some(ConnectionState::SynReceived)
        );
        drop(entry);

        // ACK - established
        let packet3 = create_test_packet(IpProto::Tcp, 0x10); // ACK
        worker.upsert_packet_meta(packet3).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(
            entry.flow_span.attributes.flow_connection_state,
            Some(ConnectionState::Established)
        );
    }

    #[tokio::test]
    async fn test_tcp_rst_sets_closed_state() {
        let (worker, _flow_span_rx) = create_test_worker();

        let packet = create_test_packet(IpProto::Tcp, 0x04); // RST
        worker.upsert_packet_meta(packet).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(
            entry.flow_span.attributes.flow_connection_state,
            Some(ConnectionState::Closed)
        );
    }

    #[tokio::test]
    async fn test_icmp_type_code_names_ipv4() {
        let (worker, _flow_span_rx) = create_test_worker();

        let mut packet = create_test_packet(IpProto::Icmp, 0);
        packet.icmp_type_id = 8; // Echo Request
        packet.icmp_code_id = 0;

        worker.upsert_packet_meta(packet).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(entry.flow_span.attributes.flow_icmp_type_id, Some(8));
        assert!(entry.flow_span.attributes.flow_icmp_type_name.is_some());
    }

    #[tokio::test]
    async fn test_icmp_type_code_names_ipv6() {
        let (worker, _flow_span_rx) = create_test_worker();

        let mut packet = create_test_packet(IpProto::Ipv6Icmp, 0);
        packet.ether_type = EtherType::Ipv6;
        packet.ip_addr_type = IpAddrType::Ipv6;
        packet.src_ipv6_addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        packet.dst_ipv6_addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        packet.icmp_type_id = 128; // Echo Request
        packet.icmp_code_id = 0;

        worker.upsert_packet_meta(packet).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(entry.flow_span.attributes.flow_icmp_type_id, Some(128));
        assert!(entry.flow_span.attributes.flow_icmp_type_name.is_some());
    }

    #[tokio::test]
    async fn test_ipsec_ah_spi() {
        let (worker, _flow_span_rx) = create_test_worker();

        let mut packet = create_test_packet(IpProto::Tcp, 0);
        packet.ah_exists = true;
        packet.ipsec_ah_spi = 12345;

        worker.upsert_packet_meta(packet).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(entry.flow_span.attributes.flow_ipsec_ah_spi, Some(12345));
    }

    #[tokio::test]
    async fn test_ipsec_esp_spi() {
        let (worker, _flow_span_rx) = create_test_worker();

        let mut packet = create_test_packet(IpProto::Tcp, 0);
        packet.esp_exists = true;
        packet.ipsec_esp_spi = 67890;

        worker.upsert_packet_meta(packet).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(entry.flow_span.attributes.flow_ipsec_esp_spi, Some(67890));
    }

    #[tokio::test]
    async fn test_wireguard_indices() {
        let (worker, _flow_span_rx) = create_test_worker();

        let mut packet = create_test_packet(IpProto::Udp, 0);
        packet.wireguard_exists = true;
        packet.ipsec_sender_index = 111;
        packet.ipsec_receiver_index = 222;

        worker.upsert_packet_meta(packet).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(
            entry.flow_span.attributes.flow_ipsec_sender_index,
            Some(111)
        );
        assert_eq!(
            entry.flow_span.attributes.flow_ipsec_receiver_index,
            Some(222)
        );
    }

    #[tokio::test]
    async fn test_vxlan_tunnel() {
        let (worker, _flow_span_rx) = create_test_worker();

        let mut packet = create_test_packet(IpProto::Tcp, 0);
        packet.tunnel_type = TunnelType::Vxlan;
        packet.tunnel_ip_addr_type = IpAddrType::Ipv4;
        packet.tunnel_src_ipv4_addr = [10, 0, 0, 1];
        packet.tunnel_dst_ipv4_addr = [10, 0, 0, 2];
        packet.tunnel_ether_type = EtherType::Ipv4;
        packet.tunnel_proto = IpProto::Udp;
        packet.tunnel_id = 12345;

        worker.upsert_packet_meta(packet).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(
            entry.flow_span.attributes.tunnel_type,
            Some(TunnelType::Vxlan)
        );
        assert_eq!(entry.flow_span.attributes.tunnel_id, Some(12345));
        assert!(entry.flow_span.attributes.tunnel_source_address.is_some());
        assert!(
            entry
                .flow_span
                .attributes
                .tunnel_destination_address
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_gre_tunnel() {
        let (worker, _flow_span_rx) = create_test_worker();

        let mut packet = create_test_packet(IpProto::Tcp, 0);
        packet.tunnel_type = TunnelType::Gre;
        packet.tunnel_ip_addr_type = IpAddrType::Ipv4;
        packet.tunnel_src_ipv4_addr = [172, 16, 0, 1];
        packet.tunnel_dst_ipv4_addr = [172, 16, 0, 2];
        packet.tunnel_id = 999;

        worker.upsert_packet_meta(packet).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(
            entry.flow_span.attributes.tunnel_type,
            Some(TunnelType::Gre)
        );
        assert_eq!(entry.flow_span.attributes.tunnel_id, Some(999));
    }

    #[tokio::test]
    async fn test_tunnel_with_mac_address() {
        let (worker, _flow_span_rx) = create_test_worker();

        let mut packet = create_test_packet(IpProto::Tcp, 0);
        packet.tunnel_type = TunnelType::Vxlan;
        packet.tunnel_src_mac_addr = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        packet.tunnel_ip_addr_type = IpAddrType::Ipv4;
        packet.tunnel_src_ipv4_addr = [10, 0, 0, 1];
        packet.tunnel_dst_ipv4_addr = [10, 0, 0, 2];

        worker.upsert_packet_meta(packet).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        assert!(
            entry
                .flow_span
                .attributes
                .tunnel_network_interface_mac
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_ipip_tunnel() {
        let (worker, _flow_span_rx) = create_test_worker();

        let mut packet = create_test_packet(IpProto::Tcp, 0);
        packet.ipip_ip_addr_type = IpAddrType::Ipv4;
        packet.ipip_src_ipv4_addr = [192, 168, 100, 1];
        packet.ipip_dst_ipv4_addr = [192, 168, 100, 2];
        packet.ipip_ether_type = EtherType::Ipv4;
        packet.ipip_proto = IpProto::Tcp;

        worker.upsert_packet_meta(packet).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(
            entry.flow_span.attributes.ipip_network_type,
            Some(EtherType::Ipv4)
        );
        assert_eq!(
            entry.flow_span.attributes.ipip_network_transport,
            Some(IpProto::Tcp)
        );
        assert!(entry.flow_span.attributes.ipip_source_address.is_some());
        assert!(
            entry
                .flow_span
                .attributes
                .ipip_destination_address
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_ip_dscp_and_ecn() {
        let (worker, _flow_span_rx) = create_test_worker();

        let mut packet = create_test_packet(IpProto::Tcp, 0);
        packet.ip_dscp_id = 46; // EF (Expedited Forwarding)
        packet.ip_ecn_id = 2; // ECT(0)

        worker.upsert_packet_meta(packet).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(entry.flow_span.attributes.flow_ip_dscp_id, Some(46));
        assert!(entry.flow_span.attributes.flow_ip_dscp_name.is_some());
        assert_eq!(entry.flow_span.attributes.flow_ip_ecn_id, Some(2));
        assert!(entry.flow_span.attributes.flow_ip_ecn_name.is_some());
    }

    #[tokio::test]
    async fn test_ipv6_flow_label() {
        let (worker, _flow_span_rx) = create_test_worker();

        let mut packet = create_test_packet(IpProto::Tcp, 0);
        packet.ether_type = EtherType::Ipv6;
        packet.ip_addr_type = IpAddrType::Ipv6;
        packet.src_ipv6_addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        packet.dst_ipv6_addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        packet.ip_flow_label = 0xABCDE;

        worker.upsert_packet_meta(packet).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(entry.flow_span.attributes.flow_ip_flow_label, Some(0xABCDE));
    }

    #[tokio::test]
    async fn test_mac_address_captured() {
        let (worker, _flow_span_rx) = create_test_worker();

        let mut packet = create_test_packet(IpProto::Tcp, 0);
        packet.src_mac_addr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        worker.upsert_packet_meta(packet).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        assert!(entry.flow_span.attributes.network_interface_mac.is_some());
    }

    #[tokio::test]
    async fn test_zero_mac_address_ignored() {
        let (worker, _flow_span_rx) = create_test_worker();

        let mut packet = create_test_packet(IpProto::Tcp, 0);
        packet.src_mac_addr = [0; 6];

        worker.upsert_packet_meta(packet).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        assert!(entry.flow_span.attributes.network_interface_mac.is_none());
    }

    #[tokio::test]
    async fn test_multiple_packets_same_direction() {
        let (worker, _flow_span_rx) = create_test_worker();

        // First packet
        let mut packet1 = create_test_packet(IpProto::Tcp, 0x10);
        packet1.l3_byte_count = 100;
        worker.upsert_packet_meta(packet1).await.unwrap();

        // Second packet - same direction
        let mut packet2 = create_test_packet(IpProto::Tcp, 0x10);
        packet2.l3_byte_count = 100;
        worker.upsert_packet_meta(packet2).await.unwrap();

        // Third packet - same direction
        let mut packet3 = create_test_packet(IpProto::Tcp, 0x10);
        packet3.l3_byte_count = 100;
        worker.upsert_packet_meta(packet3).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(entry.flow_span.attributes.flow_packets_total, 3);
        assert_eq!(entry.flow_span.attributes.flow_bytes_total, 300);
        assert_eq!(entry.flow_span.attributes.flow_reverse_packets_total, 0);
    }

    #[tokio::test]
    async fn test_geneve_tunnel() {
        let (worker, _flow_span_rx) = create_test_worker();

        let mut packet = create_test_packet(IpProto::Tcp, 0);
        packet.tunnel_type = TunnelType::Geneve;
        packet.tunnel_ip_addr_type = IpAddrType::Ipv4;
        packet.tunnel_src_ipv4_addr = [10, 1, 1, 1];
        packet.tunnel_dst_ipv4_addr = [10, 1, 1, 2];
        packet.tunnel_id = 54321;

        worker.upsert_packet_meta(packet).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(
            entry.flow_span.attributes.tunnel_type,
            Some(TunnelType::Geneve)
        );
        assert_eq!(entry.flow_span.attributes.tunnel_id, Some(54321));
    }

    #[tokio::test]
    async fn test_tunnel_ipsec_ah_spi() {
        let (worker, _flow_span_rx) = create_test_worker();

        let mut packet = create_test_packet(IpProto::Tcp, 0);
        packet.tunnel_type = TunnelType::Vxlan;
        packet.tunnel_ip_addr_type = IpAddrType::Ipv4;
        packet.tunnel_src_ipv4_addr = [10, 0, 0, 1];
        packet.tunnel_dst_ipv4_addr = [10, 0, 0, 2];
        packet.tunnel_ah_exists = true;
        packet.tunnel_ipsec_ah_spi = 98765;

        worker.upsert_packet_meta(packet).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(entry.flow_span.attributes.tunnel_ipsec_ah_spi, Some(98765));
    }

    #[tokio::test]
    async fn test_ip_ttl_captured() {
        let (worker, _flow_span_rx) = create_test_worker();

        let mut packet = create_test_packet(IpProto::Tcp, 0);
        packet.ip_ttl = 64;

        worker.upsert_packet_meta(packet).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(entry.flow_span.attributes.flow_ip_ttl, Some(64));
    }

    #[tokio::test]
    async fn test_non_tcp_no_connection_state() {
        let (worker, _flow_span_rx) = create_test_worker();

        let packet = create_test_packet(IpProto::Udp, 0);
        worker.upsert_packet_meta(packet).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(entry.flow_span.attributes.flow_connection_state, None);
    }

    #[tokio::test]
    async fn test_non_tcp_no_tcp_flags() {
        let (worker, _flow_span_rx) = create_test_worker();

        let packet = create_test_packet(IpProto::Udp, 0);
        worker.upsert_packet_meta(packet).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(entry.flow_span.attributes.flow_tcp_flags_bits, None);
        assert_eq!(entry.flow_span.attributes.flow_tcp_flags_tags, None);
    }

    #[tokio::test]
    async fn test_icmp_community_id_bidirectional() {
        let (worker, _flow_span_rx) = create_test_worker();

        // Create ICMP echo request packet (type 8, code 0)
        let mut packet_request = create_test_packet(IpProto::Icmp, 0);
        packet_request.icmp_type_id = 8; // Echo Request
        packet_request.icmp_code_id = 0;
        packet_request.l3_byte_count = 100;

        worker.upsert_packet_meta(packet_request).await.unwrap();

        // Create ICMP echo reply packet (type 0, code 0) - reversed src/dst
        let mut packet_reply = create_test_packet(IpProto::Icmp, 0);
        packet_reply.icmp_type_id = 0; // Echo Reply
        packet_reply.icmp_code_id = 0;
        // Swap src and dst addresses to simulate reply direction
        packet_reply.src_ipv4_addr = [192, 168, 1, 2];
        packet_reply.dst_ipv4_addr = [192, 168, 1, 1];
        packet_reply.l3_byte_count = 100;

        worker.upsert_packet_meta(packet_reply).await.unwrap();

        // Both packets should map to the same flow (same community ID)
        assert_eq!(
            worker.flow_span_map.len(),
            1,
            "ICMP echo request and reply should create a single bidirectional flow"
        );

        // Verify the flow has packets from both directions
        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(entry.flow_span.attributes.flow_packets_total, 1);
        assert_eq!(entry.flow_span.attributes.flow_reverse_packets_total, 1);
    }

    #[tokio::test]
    async fn test_icmpv6_community_id_bidirectional() {
        let (worker, _flow_span_rx) = create_test_worker();

        // Create ICMPv6 echo request packet (type 128, code 0)
        let mut packet_request = create_test_packet(IpProto::Ipv6Icmp, 0);
        packet_request.ether_type = EtherType::Ipv6;
        packet_request.ip_addr_type = IpAddrType::Ipv6;
        packet_request.src_ipv6_addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        packet_request.dst_ipv6_addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        packet_request.icmp_type_id = 128; // Echo Request
        packet_request.icmp_code_id = 0;
        packet_request.l3_byte_count = 100;

        worker.upsert_packet_meta(packet_request).await.unwrap();

        // Create ICMPv6 echo reply packet (type 129, code 0) - reversed src/dst
        let mut packet_reply = create_test_packet(IpProto::Ipv6Icmp, 0);
        packet_reply.ether_type = EtherType::Ipv6;
        packet_reply.ip_addr_type = IpAddrType::Ipv6;
        packet_reply.src_ipv6_addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        packet_reply.dst_ipv6_addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        packet_reply.icmp_type_id = 129; // Echo Reply
        packet_reply.icmp_code_id = 0;
        packet_reply.l3_byte_count = 100;

        worker.upsert_packet_meta(packet_reply).await.unwrap();

        // Both packets should map to the same flow (same community ID)
        assert_eq!(
            worker.flow_span_map.len(),
            1,
            "ICMPv6 echo request and reply should create a single bidirectional flow"
        );

        // Verify the flow has packets from both directions
        let entry = worker.flow_span_map.iter().next().unwrap();
        assert_eq!(entry.flow_span.attributes.flow_packets_total, 1);
        assert_eq!(entry.flow_span.attributes.flow_reverse_packets_total, 1);
    }

    #[tokio::test]
    async fn test_icmp_community_id_differs_from_tcp() {
        let (worker, _flow_span_rx) = create_test_worker();

        // Create TCP packet
        let packet_tcp = create_test_packet(IpProto::Tcp, 0x02); // SYN flag
        worker.upsert_packet_meta(packet_tcp).await.unwrap();

        // Create ICMP packet with same IP addresses
        let mut packet_icmp = create_test_packet(IpProto::Icmp, 0);
        packet_icmp.icmp_type_id = 8; // Echo Request
        packet_icmp.icmp_code_id = 0;

        worker.upsert_packet_meta(packet_icmp).await.unwrap();

        // Should have 2 different flows (different protocols = different community IDs)
        assert_eq!(
            worker.flow_span_map.len(),
            2,
            "ICMP and TCP flows should have different community IDs"
        );
    }

    #[tokio::test]
    async fn test_icmp_community_id_uses_type_code() {
        let (worker, _flow_span_rx) = create_test_worker();

        // Create ICMP echo request (type 8, code 0)
        let mut packet_echo = create_test_packet(IpProto::Icmp, 0);
        packet_echo.icmp_type_id = 8; // Echo Request
        packet_echo.icmp_code_id = 0;

        worker.upsert_packet_meta(packet_echo).await.unwrap();

        // Create ICMP destination unreachable (type 3, code 0) with same IPs
        let mut packet_dest_unreach = create_test_packet(IpProto::Icmp, 0);
        packet_dest_unreach.icmp_type_id = 3; // Destination Unreachable
        packet_dest_unreach.icmp_code_id = 0;

        worker
            .upsert_packet_meta(packet_dest_unreach)
            .await
            .unwrap();

        // Different ICMP types should create different flows (different community IDs)
        assert_eq!(
            worker.flow_span_map.len(),
            2,
            "Different ICMP types should produce different community IDs"
        );
    }

    #[tokio::test]
    async fn test_icmp_community_id_baseline() {
        let (worker, _flow_span_rx) = create_test_worker();

        // Create ICMP echo request matching baseline test data
        // from community_id.rs: 1.2.3.4 -> 5.6.7.8, type 8 (echo), code 0
        let mut packet = create_test_packet(IpProto::Icmp, 0);
        packet.src_ipv4_addr = [1, 2, 3, 4];
        packet.dst_ipv4_addr = [5, 6, 7, 8];
        packet.icmp_type_id = 8;
        packet.icmp_code_id = 0;

        worker.upsert_packet_meta(packet).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        let community_id = &entry.flow_span.attributes.flow_community_id;

        // This should match the baseline test from community_id.rs
        assert_eq!(
            community_id, "1:crodRHL2FEsHjbv3UkRrfbs4bZ0=",
            "ICMP community ID should match baseline test data"
        );
    }

    #[tokio::test]
    async fn test_icmpv6_community_id_baseline() {
        let (worker, _flow_span_rx) = create_test_worker();

        // Create ICMPv6 echo request matching baseline test data
        let mut packet = create_test_packet(IpProto::Ipv6Icmp, 0);
        packet.ether_type = EtherType::Ipv6;
        packet.ip_addr_type = IpAddrType::Ipv6;
        packet.src_ipv6_addr = [
            0xfe, 0x80, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D,
        ];
        packet.dst_ipv6_addr = [
            0xfe, 0x80, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D,
        ];
        packet.icmp_type_id = 128; // Echo Request
        packet.icmp_code_id = 0;

        worker.upsert_packet_meta(packet).await.unwrap();

        let entry = worker.flow_span_map.iter().next().unwrap();
        let community_id = &entry.flow_span.attributes.flow_community_id;

        // This should match the baseline test from community_id.rs
        assert_eq!(
            community_id, "1:0bf7hyMJUwt3fMED7z8LIfRpBeo=",
            "ICMPv6 community ID should match baseline test data"
        );
    }

    /// Comprehensive end-to-end test that simulates a complete TCP flow lifecycle:
    /// 1. Initialize FlowSpanProducer components
    /// 2. Process multiple TCP packets (SYN, SYN-ACK, ACK, data packets)
    /// 3. Verify periodic flow span recording (active timeout)
    /// 4. Verify flow span timeout and removal (idle timeout)
    #[tokio::test]
    async fn test_flow_span_producer_full_lifecycle() {
        // Create a custom SpanOptions with shorter timeouts for faster testing
        let span_opts = SpanOptions {
            max_record_interval: Duration::from_millis(200), // Record every 200ms
            generic_timeout: Duration::from_secs(30),
            icmp_timeout: Duration::from_secs(10),
            tcp_timeout: Duration::from_millis(500), // Timeout after 500ms of inactivity
            tcp_fin_timeout: Duration::from_millis(100),
            tcp_rst_timeout: Duration::from_millis(100),
            udp_timeout: Duration::from_secs(60),
            community_id_seed: 0, // Use default seed for testing
        };

        let (packet_tx, packet_rx) = mpsc::channel(100);
        let (flow_span_tx, mut flow_span_rx) = mpsc::channel(100);
        let flow_span_map = Arc::new(DashMap::with_capacity_and_hasher(
            100,
            FxBuildHasher::default(),
        ));
        let community_id_generator = CommunityIdGenerator::new(span_opts.community_id_seed);
        let iface_map = HashMap::new();

        // Create the packet worker
        let worker = PacketWorker {
            max_record_interval: span_opts.max_record_interval,
            generic_timeout: span_opts.generic_timeout,
            icmp_timeout: span_opts.icmp_timeout,
            tcp_timeout: span_opts.tcp_timeout,
            tcp_fin_timeout: span_opts.tcp_fin_timeout,
            tcp_rst_timeout: span_opts.tcp_rst_timeout,
            udp_timeout: span_opts.udp_timeout,
            community_id_generator,
            iface_map,
            flow_span_map: Arc::clone(&flow_span_map),
            packet_meta_rx: packet_rx,
            flow_span_tx: flow_span_tx.clone(),
            boot_time_offset_nanos: 0, // For tests, assume capture_time is already wall clock
        };

        // Spawn the worker task
        tokio::spawn(async move {
            worker.run().await;
        });

        // === Phase 1: Process multiple TCP packets ===

        // Packet 1: SYN (connection initiation)
        let mut packet1 = create_test_packet(IpProto::Tcp, 0x02); // SYN
        packet1.l3_byte_count = 60;
        packet1.capture_time = 1_000_000_000; // 1 second
        packet_tx.send(packet1).await.unwrap();

        // Give time for packet to be processed
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Verify flow was created
        assert_eq!(flow_span_map.len(), 1, "Flow should be created after SYN");

        // Packet 2: SYN-ACK (response from server)
        let mut packet2 = create_test_packet(IpProto::Tcp, 0x12); // SYN+ACK
        packet2.l3_byte_count = 60;
        packet2.capture_time = 1_050_000_000; // 1.05 seconds
        // Reverse direction
        packet2.src_ipv4_addr = [192, 168, 1, 2];
        packet2.dst_ipv4_addr = [192, 168, 1, 1];
        packet2.src_port = 80_u16.to_be_bytes();
        packet2.dst_port = 12345_u16.to_be_bytes();
        packet_tx.send(packet2).await.unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Packet 3: ACK (connection established)
        let mut packet3 = create_test_packet(IpProto::Tcp, 0x10); // ACK
        packet3.l3_byte_count = 52;
        packet3.capture_time = 1_100_000_000; // 1.1 seconds
        packet_tx.send(packet3).await.unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Packet 4: PSH+ACK (data transfer)
        let mut packet4 = create_test_packet(IpProto::Tcp, 0x18); // PSH+ACK
        packet4.l3_byte_count = 1500;
        packet4.capture_time = 1_150_000_000; // 1.15 seconds
        packet_tx.send(packet4).await.unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Packet 5: ACK (acknowledgment)
        let mut packet5 = create_test_packet(IpProto::Tcp, 0x10); // ACK
        packet5.l3_byte_count = 52;
        packet5.capture_time = 1_200_000_000; // 1.2 seconds
        // Reverse direction
        packet5.src_ipv4_addr = [192, 168, 1, 2];
        packet5.dst_ipv4_addr = [192, 168, 1, 1];
        packet5.src_port = 80_u16.to_be_bytes();
        packet5.dst_port = 12345_u16.to_be_bytes();
        packet_tx.send(packet5).await.unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Verify flow metrics after all packets
        {
            let entry = flow_span_map.iter().next().unwrap();
            let attrs = &entry.flow_span.attributes;

            // Should have 3 packets in forward direction (SYN, ACK, PSH+ACK)
            // and 2 packets in reverse direction (SYN-ACK, ACK)
            assert_eq!(
                attrs.flow_packets_total, 3,
                "Forward packets total should be 3"
            );
            assert_eq!(
                attrs.flow_reverse_packets_total, 2,
                "Reverse packets total should be 2"
            );

            // Verify TCP flags accumulated (SYN | ACK | PSH)
            let expected_flags = 0x02 | 0x10 | 0x08; // SYN | ACK | PSH
            assert_eq!(
                attrs.flow_tcp_flags_bits,
                Some(expected_flags),
                "TCP flags should accumulate all seen flags"
            );

            // Verify connection state progression
            assert_eq!(
                attrs.flow_connection_state,
                Some(ConnectionState::Established),
                "Connection should be in Established state"
            );
        }

        // === Phase 2: Wait for periodic recording (ActiveTimeout) ===

        // The record task should fire after max_record_interval (200ms)
        let recorded_span = tokio::time::timeout(Duration::from_millis(500), flow_span_rx.recv())
            .await
            .expect("Should receive recorded span within timeout")
            .expect("Channel should not be closed");

        // Verify the recorded span has ActiveTimeout reason
        assert_eq!(
            recorded_span.attributes.flow_end_reason,
            Some(FlowEndReason::ActiveTimeout),
            "Periodic recording should have ActiveTimeout reason"
        );

        // Verify packet counts are correct in the recorded span
        assert_eq!(
            recorded_span.attributes.flow_packets_total, 3,
            "Recorded span should have correct forward packet count"
        );
        assert_eq!(
            recorded_span.attributes.flow_reverse_packets_total, 2,
            "Recorded span should have correct reverse packet count"
        );

        // Verify delta counters were reset after recording
        tokio::time::sleep(Duration::from_millis(50)).await;
        {
            let entry = flow_span_map.iter().next().unwrap();
            assert_eq!(
                entry.flow_span.attributes.flow_packets_delta, 0,
                "Delta counters should be reset after recording"
            );
        }

        // === Phase 3: Wait for flow timeout (IdleTimeout) ===

        // Don't send any more packets - flow should timeout after tcp_timeout (500ms)
        // Note: We might receive more ActiveTimeout recordings before the IdleTimeout
        let mut timeout_span = None;
        for _ in 0..5 {
            match tokio::time::timeout(Duration::from_millis(1000), flow_span_rx.recv()).await {
                Ok(Some(span)) => {
                    if span.attributes.flow_end_reason == Some(FlowEndReason::IdleTimeout) {
                        timeout_span = Some(span);
                        break;
                    }
                    // Otherwise it's another ActiveTimeout recording, continue waiting
                }
                Ok(None) => panic!("Channel closed unexpectedly"),
                Err(_) => panic!("Timeout waiting for IdleTimeout span"),
            }
        }

        let timeout_span = timeout_span.expect("Should eventually receive IdleTimeout span");

        // Verify the timeout span has IdleTimeout reason
        assert_eq!(
            timeout_span.attributes.flow_end_reason,
            Some(FlowEndReason::IdleTimeout),
            "Flow timeout should have IdleTimeout reason"
        );

        // Verify flow was removed from map
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            flow_span_map.len(),
            0,
            "Flow should be removed from map after timeout"
        );

        // Verify total metrics in the final timeout span
        assert_eq!(
            timeout_span.attributes.flow_packets_total, 3,
            "Final span should have all forward packets"
        );
        assert_eq!(
            timeout_span.attributes.flow_reverse_packets_total, 2,
            "Final span should have all reverse packets"
        );

        // === Phase 4: Verify multiple recordings scenario ===

        // Send a new packet to create a new flow
        let mut packet6 = create_test_packet(IpProto::Tcp, 0x02); // SYN
        packet6.l3_byte_count = 60;
        packet6.capture_time = 2_000_000_000; // 2 seconds
        // Use different port to create different flow
        packet6.src_port = 54321_u16.to_be_bytes();
        packet_tx.send(packet6).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify new flow created
        assert_eq!(flow_span_map.len(), 1, "New flow should be created");

        // Wait for first recording
        let first_recording = tokio::time::timeout(Duration::from_millis(400), flow_span_rx.recv())
            .await
            .expect("Should receive first recording")
            .expect("Channel should not be closed");

        assert_eq!(
            first_recording.attributes.flow_end_reason,
            Some(FlowEndReason::ActiveTimeout),
            "First recording should be ActiveTimeout"
        );

        // Wait for second recording (flow still active)
        let second_recording =
            tokio::time::timeout(Duration::from_millis(400), flow_span_rx.recv())
                .await
                .expect("Should receive second recording")
                .expect("Channel should not be closed");

        assert_eq!(
            second_recording.attributes.flow_end_reason,
            Some(FlowEndReason::ActiveTimeout),
            "Second recording should also be ActiveTimeout"
        );

        // Eventually the flow will timeout
        let final_timeout = tokio::time::timeout(Duration::from_millis(1000), flow_span_rx.recv())
            .await
            .expect("Should receive final timeout")
            .expect("Channel should not be closed");

        assert_eq!(
            final_timeout.attributes.flow_end_reason,
            Some(FlowEndReason::IdleTimeout),
            "Final span should have IdleTimeout"
        );

        // Clean up
        drop(packet_tx);
    }
}
