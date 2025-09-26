use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use dashmap::DashMap;
use fxhash::FxBuildHasher;
use mermin_common::PacketMeta;
use opentelemetry::trace::SpanKind;
use tokio::sync::mpsc;

use crate::{
    community_id::CommunityIdGenerator,
    span::{
        flow::{FlowSpan, FlowSpanMap, SpanAttributes},
        opts::SpanOptions,
    },
};

pub struct FlowSpanProducer {
    span_opts: SpanOptions,
    packet_channel_capacity: usize,
    packet_worker_count: usize,
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
                Arc::clone(&self.flow_span_map),
                self.community_id_generator.clone(),
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
    #[allow(dead_code)] // TODO: Use in flow management
    flow_span_map: FlowSpanMap,
    community_id_generator: CommunityIdGenerator,
    packet_meta_rx: mpsc::Receiver<PacketMeta>,
    flow_span_tx: mpsc::Sender<FlowSpan>,
}

impl PacketWorker {
    pub fn new(
        span_opts: SpanOptions,
        flow_span_map: FlowSpanMap,
        community_id_generator: CommunityIdGenerator,
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
            packet_meta_rx,
            flow_span_tx,
            flow_span_map,
            community_id_generator,
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
            let (src_addr, dst_addr) = Self::extract_ip_addresses(
                packet.ip_addr_type,
                packet.src_ipv4_addr,
                packet.dst_ipv4_addr,
                packet.src_ipv6_addr,
                packet.dst_ipv6_addr,
            );

            // Check if this is actually tunneled traffic
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

            let src_port = packet.src_port();
            let dst_port = packet.dst_port();
            let community_id = self.community_id_generator.generate(
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                packet.proto,
            );

            let now = SystemTime::now();
            let duration_since_epoch = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
            let timestamp_nanos = duration_since_epoch.as_nanos() as u64;

            let attrs = FlowSpan {
                start_time: timestamp_nanos,
                end_time: timestamp_nanos,
                span_kind: SpanKind::Internal,
                attributes: SpanAttributes {
                    flow_community_id: community_id.clone(),
                    flow_connection_state: None,
                    flow_end_reason: "".to_string(),
                    source_address: src_addr,
                    source_port: src_port,
                    destination_address: dst_addr,
                    destination_port: dst_port,
                    network_transport: packet.proto,
                    network_type: packet.ether_type,
                    network_interface_index: None,
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
                    flow_tcp_flags_bits: None,
                    flow_tcp_flags_tags: None,
                    flow_bytes_delta: packet.l3_octet_count as i64,
                    flow_bytes_total: packet.l3_octet_count as i64,
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
                    tunnel_type: None,
                    tunnel_source_address: tunnel_addresses.map(|(src, _)| src),
                    tunnel_source_port: if is_tunneled {
                        Some(packet.tunnel_src_port())
                    } else {
                        None
                    },
                    tunnel_destination_address: tunnel_addresses.map(|(_, dst)| dst),
                    tunnel_destination_port: if is_tunneled {
                        Some(packet.tunnel_dst_port())
                    } else {
                        None
                    },
                    tunnel_network_transport: if is_tunneled {
                        Some(packet.tunnel_proto)
                    } else {
                        None
                    },
                    tunnel_network_type: if is_tunneled {
                        Some(packet.tunnel_ether_type)
                    } else {
                        None
                    },
                    tunnel_id: None,
                    tunnel_key: None,
                    tunnel_sender_index: None,
                    tunnel_receiver_index: None,
                    tunnel_spi: None,
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
            };

            // TODO: REMOVE this is just for testing sending all flows to the exporter
            let _ = self.flow_span_tx.send(attrs).await;
        }
    }
}
