use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use dashmap::DashMap;
use fxhash::FxBuildHasher;
use mermin_common::PacketMeta;
use network_types::{
    eth::EtherType,
    ip::{IpDscp, IpEcn, IpProto},
};
use opentelemetry::trace::SpanKind;
use pnet::datalink::MacAddr;
use tokio::sync::mpsc;

use crate::{
    community_id::CommunityIdGenerator,
    span::{
        flow::{FlowSpan, FlowSpanMap, SpanAttributes},
        opts::SpanOptions,
        tcp::{ConnectionState, TcpFlags},
    },
};

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
                // TODO: remove this once we have a better way to handle this
                #[allow(clippy::redundant_pattern_matching)]
                if let Err(_) = worker_tx.send(packet).await {
                    // Worker channel is closed, handle gracefully
                    continue;
                }
                worker_index = (worker_index + 1) % worker_count;
            }
        }
    }
}

pub struct PacketWorker {
    #[allow(dead_code)] // TODO: Use in timeout logic
    max_record_interval: Duration,
    #[allow(dead_code)] // TODO: Use in timeout logic
    generic_timeout: Duration,
    #[allow(dead_code)] // TODO: Use in timeout logic
    icmp_timeout: Duration,
    #[allow(dead_code)] // TODO: Use in timeout logic
    tcp_timeout: Duration,
    #[allow(dead_code)] // TODO: Use in timeout logic
    tcp_fin_timeout: Duration,
    #[allow(dead_code)] // TODO: Use in timeout logic
    tcp_rst_timeout: Duration,
    #[allow(dead_code)] // TODO: Use in timeout logic
    udp_timeout: Duration,
    community_id_generator: CommunityIdGenerator,
    iface_map: HashMap<u32, String>,
    #[allow(dead_code)] // TODO: Use in flow mapping
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

    fn extract_ip_addresses(
        ip_addr_type: mermin_common::IpAddrType,
        src_ipv4_addr: [u8; 4],
        dst_ipv4_addr: [u8; 4],
        src_ipv6_addr: [u8; 16],
        dst_ipv6_addr: [u8; 16],
    ) -> (IpAddr, IpAddr) {
        match ip_addr_type {
            mermin_common::IpAddrType::Ipv4 => {
                let src = IpAddr::V4(std::net::Ipv4Addr::from(src_ipv4_addr));
                let dst = IpAddr::V4(std::net::Ipv4Addr::from(dst_ipv4_addr));
                (src, dst)
            }
            mermin_common::IpAddrType::Ipv6 => {
                let src = IpAddr::V6(std::net::Ipv6Addr::from(src_ipv6_addr));
                let dst = IpAddr::V6(std::net::Ipv6Addr::from(dst_ipv6_addr));
                (src, dst)
            }
        }
    }

    pub async fn run(mut self) {
        while let Some(packet) = self.packet_meta_rx.recv().await {
            let now = SystemTime::now();
            let duration_since_epoch = now.duration_since(UNIX_EPOCH).expect("time went backwards");
            let timestamp_nanos = duration_since_epoch.as_nanos() as u64;

            let (src_addr, dst_addr) = Self::extract_ip_addresses(
                packet.ip_addr_type,
                packet.src_ipv4_addr,
                packet.dst_ipv4_addr,
                packet.src_ipv6_addr,
                packet.dst_ipv6_addr,
            );
            let src_port = packet.src_port();
            let dst_port = packet.dst_port();

            let is_tunneled =
                packet.tunnel_src_ipv4_addr != [0; 4] || packet.tunnel_src_ipv6_addr != [0; 16];
            let tunnel_addresses = if is_tunneled {
                Some(Self::extract_ip_addresses(
                    packet.tunnel_ip_addr_type,
                    packet.tunnel_src_ipv4_addr,
                    packet.tunnel_dst_ipv4_addr,
                    packet.tunnel_src_ipv6_addr,
                    packet.tunnel_dst_ipv6_addr,
                ))
            } else {
                None
            };

            // Pre-calculate commonly used conditions for readability
            let is_icmp = packet.proto == IpProto::Icmp;
            let is_icmpv6 = packet.proto == IpProto::Ipv6Icmp;
            let is_icmp_any = is_icmp || is_icmpv6;
            let is_ip_flow =
                packet.ether_type == EtherType::Ipv4 || packet.ether_type == EtherType::Ipv6;
            let is_ipv6 = packet.ether_type == EtherType::Ipv6;
            let is_tcp = packet.proto == IpProto::Tcp;

            let attrs = FlowSpan {
                start_time: timestamp_nanos,
                end_time: 0,
                span_kind: SpanKind::Internal,
                attributes: SpanAttributes {
                    // General flow attributes
                    flow_community_id: self
                        .community_id_generator
                        .generate(src_addr, dst_addr, src_port, dst_port, packet.proto)
                        .clone(),
                    flow_connection_state: is_tcp.then(|| ConnectionState::from_packet(&packet)),
                    flow_end_reason: None,

                    // Network endpoints
                    source_address: src_addr,
                    source_port: src_port,
                    destination_address: dst_addr,
                    destination_port: dst_port,

                    // Network layer info
                    network_transport: packet.proto,
                    network_type: packet.ether_type,
                    network_interface_index: Some(packet.ifindex),
                    network_interface_name: self.iface_map.get(&packet.ifindex).cloned(),
                    network_interface_mac: Some(MacAddr::new(
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

                    // Flow metrics
                    flow_bytes_delta: packet.l3_octet_count as i64, // TODO: check this for all types of packets
                    flow_bytes_total: packet.l3_octet_count as i64, // TODO: check this for all types of packets
                    flow_packets_delta: 1,
                    flow_packets_total: 1,
                    flow_reverse_bytes_delta: 0,
                    flow_reverse_bytes_total: 0,
                    flow_reverse_packets_delta: 0,
                    flow_reverse_packets_total: 0,

                    // TCP performance metrics (not yet implemented)
                    flow_tcp_handshake_snd_latency: None,
                    flow_tcp_handshake_snd_jitter: None,
                    flow_tcp_handshake_cnd_latency: None,
                    flow_tcp_handshake_cnd_jitter: None,
                    flow_tcp_svc_latency: None,
                    flow_tcp_svc_jitter: None,
                    flow_tcp_rndtrip_latency: None,
                    flow_tcp_rndtrip_jitter: None,

                    // Tunnel attributes (populated when traffic is encapsulated)
                    tunnel_type: None,
                    tunnel_source_address: tunnel_addresses.map(|(src, _)| src),
                    tunnel_source_port: is_tunneled.then(|| packet.tunnel_src_port()),
                    tunnel_destination_address: tunnel_addresses.map(|(_, dst)| dst),
                    tunnel_destination_port: is_tunneled.then(|| packet.tunnel_dst_port()),
                    tunnel_network_transport: is_tunneled.then_some(packet.tunnel_proto),
                    tunnel_network_type: is_tunneled.then_some(packet.tunnel_ether_type),
                    tunnel_id: None,
                    tunnel_key: None,
                    tunnel_sender_index: None,
                    tunnel_receiver_index: None,
                    tunnel_spi: None,

                    // Kubernetes source attributes (not yet implemented)
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

                    // Kubernetes destination attributes (not yet implemented)
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

                    // Application and policy attributes (not yet implemented)
                    network_policies_ingress: None,
                    network_policies_egress: None,
                    process_executable_name: None,
                    container_image_name: None,
                    container_name: None,
                },
            };

            // TODO: REMOVE this is just for testing sending all flows to the exporter
            let _ = self.flow_span_tx.send(attrs).await;
        }
    }
}
