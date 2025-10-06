use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};

use dashmap::DashMap;
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
    community_id::CommunityIdGenerator,
    span::{
        flow::{FlowEndReason, FlowSpan, SpanAttributes},
        opts::SpanOptions,
        tcp::{ConnectionState, TcpFlags},
    },
};

/// Task handles and communication channels for managing a flow's lifecycle.
///
/// ## Task Lifecycle
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
/// ## Concurrency & Cleanup
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

/// Entry in the flow map containing both the flow span and its task handles
pub struct FlowEntry {
    pub flow_span: FlowSpan,
    pub task_handles: FlowTaskHandles,
}

pub type FlowSpanMap = Arc<DashMap<String, FlowEntry, FxBuildHasher>>;

pub struct FlowSpanProducer {
    span_opts: SpanOptions,
    packet_channel_capacity: usize,
    packet_worker_count: usize,
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
    ) -> Self {
        let flow_span_map_capacity = packet_channel_capacity * 8;
        let flow_span_map = Arc::new(DashMap::with_capacity_and_hasher(
            flow_span_map_capacity,
            FxBuildHasher::default(),
        ));
        let community_id_generator = CommunityIdGenerator::new(0);

        Self {
            span_opts,
            packet_channel_capacity,
            packet_worker_count,
            community_id_generator,
            iface_map,
            flow_span_map,
            packet_meta_rx,
            flow_span_tx,
        }
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
    community_id_generator: CommunityIdGenerator,
    iface_map: HashMap<u32, String>,
    flow_span_map: FlowSpanMap,
    packet_meta_rx: mpsc::Receiver<PacketMeta>,
    flow_span_tx: mpsc::Sender<FlowSpan>,
}

impl PacketWorker {
    pub fn new(
        span_opts: SpanOptions,
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
        let (src_addr, dst_addr) = match extract_ip_addresses(
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

        // TODO: Handle icmp and icmpv6
        let community_id = self
            .community_id_generator
            .generate(src_addr, dst_addr, src_port, dst_port, packet.proto)
            .clone();

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
            extract_ip_addresses(
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
            extract_ip_addresses(
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

        // Check if this is a new flow or an existing one
        let is_new_flow = !self.flow_span_map.contains_key(community_id.as_str());

        if is_new_flow {
            // Create new flow span
            let flow_span = FlowSpan {
                start_time: UNIX_EPOCH + Duration::from_nanos(packet.capture_time),
                end_time: UNIX_EPOCH,
                span_kind: SpanKind::Internal,
                attributes: SpanAttributes {
                    // General flow attributes
                    flow_community_id: community_id.clone(),
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

                    // All other attributes default to None
                    ..Default::default()
                },
            };

            // Calculate initial timeout for this flow
            let initial_timeout = self.calculate_timeout(&packet, &flow_span);

            // Spawn tasks for this new flow
            // Note: Under extremely high packet rates with many short-lived flows,
            // task spawning overhead could become significant. Future optimization
            // could use a task pool pattern if this becomes a bottleneck.
            // Channel capacity of 32 handles bursts of packets without blocking/dropping
            let (timeout_reset_tx, timeout_reset_rx) = mpsc::channel(32);

            let record_task = tokio::spawn(record_task_loop(
                community_id.clone(),
                Arc::clone(&self.flow_span_map),
                self.flow_span_tx.clone(),
                self.max_record_interval,
            ));

            let timeout_task = tokio::spawn(timeout_task_loop(
                community_id.clone(),
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

            // Insert the new flow entry into the map
            let flow_entry = FlowEntry {
                flow_span,
                task_handles,
            };

            self.flow_span_map
                .insert(community_id.to_string(), flow_entry);
        } else {
            // Update existing flow
            if let Some(mut entry) = self.flow_span_map.get_mut(community_id.as_str()) {
                let flow_span = &mut entry.flow_span;

                // Update end time
                flow_span.end_time = UNIX_EPOCH + Duration::from_nanos(packet.capture_time);

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

                    // Update connection state based on the new packet
                    if let Some(new_state) = ConnectionState::from_packet(&packet) {
                        flow_span.attributes.flow_connection_state = Some(new_state);
                    }
                }

                // Calculate new timeout (might have changed due to TCP state)
                let new_timeout = self.calculate_timeout(&packet, flow_span);

                // Signal timeout task to reset with potentially new duration
                // Note: If the channel is full, this will drop the timeout update.
                // This is acceptable as it means the timeout task is processing updates,
                // and a subsequent packet will trigger another reset attempt.
                if entry
                    .task_handles
                    .timeout_reset_tx
                    .try_send(TimeoutUpdate::Reset(new_timeout))
                    .is_err()
                {
                    debug!(
                        "timeout reset channel full or closed for flow {}",
                        community_id
                    );
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    UnknownIpAddrType,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnknownIpAddrType => write!(f, "unknown IP address type"),
        }
    }
}

impl std::error::Error for Error {}

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

fn extract_ip_addresses(
    ip_addr_type: IpAddrType,
    src_ipv4_addr: [u8; 4],
    dst_ipv4_addr: [u8; 4],
    src_ipv6_addr: [u8; 16],
    dst_ipv6_addr: [u8; 16],
) -> Result<(IpAddr, IpAddr), Error> {
    match ip_addr_type {
        IpAddrType::Unknown => Err(Error::UnknownIpAddrType),
        IpAddrType::Ipv4 => {
            let src = IpAddr::V4(std::net::Ipv4Addr::from(src_ipv4_addr));
            let dst = IpAddr::V4(std::net::Ipv4Addr::from(dst_ipv4_addr));
            Ok((src, dst))
        }
        IpAddrType::Ipv6 => {
            let src = IpAddr::V6(std::net::Ipv6Addr::from(src_ipv6_addr));
            let dst = IpAddr::V6(std::net::Ipv6Addr::from(dst_ipv6_addr));
            Ok((src, dst))
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
        let community_id_generator = CommunityIdGenerator::new(0);
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
                flow_connection_state: None,
                flow_end_reason: None,
                source_address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                source_port: 12345,
                destination_address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
                destination_port: 80,
                network_transport: proto,
                network_type: EtherType::Ipv4,
                network_interface_index: Some(1),
                network_interface_name: None,
                network_interface_mac: None,
                flow_ip_dscp_id: None,
                flow_ip_dscp_name: None,
                flow_ip_ecn_id: None,
                flow_ip_ecn_name: None,
                flow_ip_ttl: None,
                flow_ip_flow_label: None,
                flow_icmp_type_id: None,
                flow_icmp_type_name: None,
                flow_icmp_code_id: None,
                flow_icmp_code_name: None,
                flow_tcp_flags_bits: Some(tcp_flags),
                flow_tcp_flags_tags: None,
                flow_ipsec_ah_spi: None,
                flow_ipsec_esp_spi: None,
                flow_ipsec_sender_index: None,
                flow_ipsec_receiver_index: None,
                flow_bytes_delta: 100,
                flow_bytes_total: 100,
                flow_packets_delta: 1,
                flow_packets_total: 1,
                flow_reverse_bytes_delta: 0,
                flow_reverse_bytes_total: 0,
                flow_reverse_packets_delta: 0,
                flow_reverse_packets_total: 0,
                flow_tcp_handshake_snd_latency: None,
                flow_tcp_handshake_snd_jitter: None,
                flow_tcp_handshake_cnd_latency: None,
                flow_tcp_handshake_cnd_jitter: None,
                flow_tcp_svc_latency: None,
                flow_tcp_svc_jitter: None,
                flow_tcp_rndtrip_latency: None,
                flow_tcp_rndtrip_jitter: None,
                ipip_network_type: None,
                ipip_network_transport: None,
                ipip_source_address: None,
                ipip_destination_address: None,
                tunnel_type: None,
                tunnel_network_interface_mac: None,
                tunnel_network_type: None,
                tunnel_network_transport: None,
                tunnel_source_address: None,
                tunnel_source_port: None,
                tunnel_destination_address: None,
                tunnel_destination_port: None,
                tunnel_id: None,
                tunnel_ipsec_ah_spi: None,
                source_k8s_cluster_name: None,
                source_k8s_cluster_uid: None,
                source_k8s_node_name: None,
                source_k8s_node_uid: None,
                source_k8s_namespace_name: None,
                source_k8s_pod_name: None,
                source_k8s_pod_uid: None,
                source_k8s_container_name: None,
                source_k8s_deployment_name: None,
                source_k8s_deployment_uid: None,
                source_k8s_replicaset_name: None,
                source_k8s_replicaset_uid: None,
                source_k8s_statefulset_name: None,
                source_k8s_statefulset_uid: None,
                source_k8s_daemonset_name: None,
                source_k8s_daemonset_uid: None,
                source_k8s_job_name: None,
                source_k8s_job_uid: None,
                source_k8s_cronjob_name: None,
                source_k8s_cronjob_uid: None,
                source_k8s_service_name: None,
                source_k8s_service_uid: None,
                destination_k8s_cluster_name: None,
                destination_k8s_cluster_uid: None,
                destination_k8s_node_name: None,
                destination_k8s_node_uid: None,
                destination_k8s_namespace_name: None,
                destination_k8s_pod_name: None,
                destination_k8s_pod_uid: None,
                destination_k8s_container_name: None,
                destination_k8s_deployment_name: None,
                destination_k8s_deployment_uid: None,
                destination_k8s_replicaset_name: None,
                destination_k8s_replicaset_uid: None,
                destination_k8s_statefulset_name: None,
                destination_k8s_statefulset_uid: None,
                destination_k8s_daemonset_name: None,
                destination_k8s_daemonset_uid: None,
                destination_k8s_job_name: None,
                destination_k8s_job_uid: None,
                destination_k8s_cronjob_name: None,
                destination_k8s_cronjob_uid: None,
                destination_k8s_service_name: None,
                destination_k8s_service_uid: None,
                network_policies_ingress: None,
                network_policies_egress: None,
                process_executable_name: None,
                container_image_name: None,
                container_name: None,
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
    fn test_extract_ip_addresses_ipv4() {
        let result = extract_ip_addresses(
            IpAddrType::Ipv4,
            [192, 168, 1, 1],
            [192, 168, 1, 2],
            [0; 16],
            [0; 16],
        );

        assert!(result.is_ok());
        let (src, dst) = result.unwrap();
        assert_eq!(src, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(dst, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
    }

    #[test]
    fn test_extract_ip_addresses_ipv6() {
        let result = extract_ip_addresses(
            IpAddrType::Ipv6,
            [0; 4],
            [0; 4],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        );

        assert!(result.is_ok());
        let (src, dst) = result.unwrap();
        match src {
            IpAddr::V6(addr) => assert!(addr.to_string().starts_with("2001:db8")),
            _ => panic!("Expected IPv6 address"),
        }
        match dst {
            IpAddr::V6(addr) => assert!(addr.to_string().starts_with("2001:db8")),
            _ => panic!("Expected IPv6 address"),
        }
    }

    #[test]
    fn test_extract_ip_addresses_unknown() {
        let result = extract_ip_addresses(
            IpAddrType::Unknown,
            [192, 168, 1, 1],
            [192, 168, 1, 2],
            [0; 16],
            [0; 16],
        );

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::UnknownIpAddrType);
    }
}
