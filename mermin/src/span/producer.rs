use std::{net::IpAddr, sync::Arc, time::Duration};

use dashmap::DashMap;
use fxhash::FxBuildHasher;
use mermin_common::PacketMeta;
use tokio::sync::mpsc;

use crate::{
    community_id::CommunityIdGenerator,
    span::{
        flow::{FlowSpan, FlowSpanMap},
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
            let (tunnel_src_addr, tunnel_dst_addr) = Self::extract_ip_addresses(
                packet.tunnel_ip_addr_type,
                packet.tunnel_src_ipv4_addr,
                packet.tunnel_dst_ipv4_addr,
                packet.tunnel_src_ipv6_addr,
                packet.tunnel_dst_ipv6_addr,
            );
            let src_port = packet.src_port();
            let dst_port = packet.dst_port();
            let community_id = self.community_id_generator.generate(
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                packet.proto,
            );

            let attrs = FlowSpan {
                community_id: community_id.clone(),
                // network_interface_name: packet.ifindex,
                source_address: src_addr,
                source_port: src_port,
                destination_address: dst_addr,
                destination_port: dst_port,
                network_transport: packet.proto,
                network_type: packet.ether_type,
                tunnel_source_address: tunnel_src_addr,
                tunnel_source_port: packet.tunnel_src_port(),
                tunnel_destination_address: tunnel_dst_addr,
                tunnel_destination_port: packet.tunnel_dst_port(),
                tunnel_network_transport: packet.tunnel_proto,
                tunnel_network_type: packet.tunnel_ether_type,
                // Source Kubernetes attributes - will be attributed later
                source_k8s_cluster_name: None,
                source_k8s_namespace_name: None,
                source_k8s_node_name: None,
                source_k8s_pod_name: None,
                source_k8s_container_name: None,
                source_k8s_deployment_name: None,
                source_k8s_replicaset_name: None,
                source_k8s_statefulset_name: None,
                source_k8s_daemonset_name: None,
                source_k8s_job_name: None,
                source_k8s_cronjob_name: None,
                source_k8s_service_name: None,
                // Destination Kubernetes attributes - will be attributed later
                destination_k8s_cluster_name: None,
                destination_k8s_namespace_name: None,
                destination_k8s_node_name: None,
                destination_k8s_pod_name: None,
                destination_k8s_container_name: None,
                destination_k8s_deployment_name: None,
                destination_k8s_replicaset_name: None,
                destination_k8s_statefulset_name: None,
                destination_k8s_daemonset_name: None,
                destination_k8s_job_name: None,
                destination_k8s_cronjob_name: None,
                destination_k8s_service_name: None,
                // Network Policy attribution - will be populated during attribution
                network_policies_ingress: None,
                network_policies_egress: None,
                network_byte_count: packet.l3_octet_count, // TODO: should this be l3_octet_count or full byte count?
                network_packet_count: 1,
                network_reverse_byte_count: 0,
                network_reverse_packet_count: 0,
            };

            // TODO: REMOVE this is just for testing sending all flows to the exporter
            let _ = self.flow_span_tx.send(attrs).await;
        }
    }
}
