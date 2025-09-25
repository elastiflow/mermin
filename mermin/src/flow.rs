use std::{net::IpAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use dashmap::DashMap;
use fxhash::FxBuildHasher;
use mermin_common::PacketMeta;
use network_types::{eth::EtherType, ip::IpProto};
use serde::Serialize;
use tokio::sync::mpsc;
use tracing::{Span, info_span};

use crate::{
    community_id::CommunityIdGenerator,
    otlp::{opts::SpanOptions, trace::lib::Traceable},
};

type FlowAttrMap = Arc<DashMap<String, FlowAttributes, FxBuildHasher>>;

#[async_trait]
pub trait FlowAttributesExporter: Send + Sync {
    async fn export(&self, attrs: FlowAttributes);
    async fn shutdown(&self) -> anyhow::Result<()>;
}

// TODO: Draw inspiration from the following:
// - https://opentelemetry.io/docs/specs/semconv/system/system-metrics/#network-metrics
// - https://opentelemetry.io/docs/specs/semconv/registry/attributes/network/
#[derive(Debug, Clone, Serialize)]
pub struct FlowAttributes {
    pub community_id: String,

    // TODO: can we get the name from the packet and not just the index?
    // TODO: does this need an observer prefix? what is a good prefix for this?
    // pub network_interface_name: u32,

    // TODO: we need to get the direction based on if it's an ingress or egress flow and based on the source and destination addresses
    // TODO: is this relevant?
    // pub network_io_direction
    pub source_address: IpAddr,
    pub source_port: u16,
    pub destination_address: IpAddr,
    pub destination_port: u16,
    #[serde(serialize_with = "serialize_ip_proto")]
    pub network_transport: IpProto,
    #[serde(serialize_with = "serialize_ether_type")]
    pub network_type: EtherType,

    // Tunnel
    // TODO: should this be <source/destination/network>.tunnel.<attribute>?
    pub tunnel_source_address: IpAddr,
    pub tunnel_source_port: u16,
    pub tunnel_destination_address: IpAddr,
    pub tunnel_destination_port: u16,
    #[serde(serialize_with = "serialize_ip_proto")]
    pub tunnel_network_transport: IpProto,
    #[serde(serialize_with = "serialize_ether_type")]
    pub tunnel_network_type: EtherType,

    // Source Kubernetes attributes
    pub source_k8s_cluster_name: Option<String>,
    pub source_k8s_namespace_name: Option<String>,
    pub source_k8s_node_name: Option<String>,
    pub source_k8s_pod_name: Option<String>,
    pub source_k8s_container_name: Option<String>,
    pub source_k8s_deployment_name: Option<String>,
    pub source_k8s_replicaset_name: Option<String>,
    pub source_k8s_statefulset_name: Option<String>,
    pub source_k8s_daemonset_name: Option<String>,
    pub source_k8s_job_name: Option<String>,
    pub source_k8s_cronjob_name: Option<String>,
    pub source_k8s_service_name: Option<String>,

    // Destination Kubernetes attributes
    pub destination_k8s_cluster_name: Option<String>,
    pub destination_k8s_namespace_name: Option<String>,
    pub destination_k8s_node_name: Option<String>,
    pub destination_k8s_pod_name: Option<String>,
    pub destination_k8s_container_name: Option<String>,
    pub destination_k8s_deployment_name: Option<String>,
    pub destination_k8s_replicaset_name: Option<String>,
    pub destination_k8s_statefulset_name: Option<String>,
    pub destination_k8s_daemonset_name: Option<String>,
    pub destination_k8s_job_name: Option<String>,
    pub destination_k8s_cronjob_name: Option<String>,
    pub destination_k8s_service_name: Option<String>,

    // Network Policy attribution
    /// NetworkPolicies affecting ingress traffic to the destination pod (comma-separated policy names)
    pub network_policies_ingress: Option<String>,
    /// NetworkPolicies affecting egress traffic from the source pod (comma-separated policy names)  
    pub network_policies_egress: Option<String>,

    // Flow aggregates
    pub network_byte_count: u32,
    pub network_packet_count: u32,
    // Reverse flow aggregates
    pub network_reverse_byte_count: u32,
    pub network_reverse_packet_count: u32,
    // /// Total number of packets observed for this flow since its start.
    // pub packet_total_count: u64,
    // /// Total number of bytes (octets) observed for this flow since its start.
    // pub octet_total_count: u64,
    // /// Number of packets observed in the last measurement interval.
    // pub packet_delta_count: u64,
    // /// Number of bytes (octets) observed in the last measurement interval.
    // pub octet_delta_count: u64,

    // // Fields with 4-byte alignment
    // /// Timestamp (seconds since epoch) when the flow was first observed.
    // pub flow_start_seconds: u32,
    // /// Timestamp (seconds since epoch) when the flow was last observed or ended.
    // pub flow_end_seconds: u32,
    // /// Reason code indicating why the flow record was generated or ended.
    // /// (e.g., 1 = Active Timeout, 2 = End of Flow detected, etc. - specific values depend on the system).
    // pub flow_end_reason: u8,
    // // Implicit padding (2 bytes) is added here by the compiler to ensure
    // // the total struct size (88 bytes) is a multiple of the maximum alignment (8 bytes).
}

// Helpers to serialize the IP protocol and EtherType which do not natively implement Serialize
fn serialize_ip_proto<S>(proto: &IpProto, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&proto.to_string())
}

fn serialize_ether_type<S>(ether_type: &EtherType, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(ether_type.as_str())
}

impl Traceable for FlowAttributes {
    fn to_span(&self) -> Span {
        info_span!(
            "network.flow",
            "flow.community_id" = self.community_id.as_str(),
            "network.source.address" = self.source_address.to_string(),
            "network.source.port" = self.source_port,
            "network.destination.address" = self.destination_address.to_string(),
            "network.destination.port" = self.destination_port,
            "network.transport" = self.network_transport.to_string(),
            "network.type" = self.network_type.as_str().to_string(),
            "network.tunnel.source.address" = self.tunnel_source_address.to_string(),
            "network.tunnel.source.port" = self.tunnel_source_port,
            "network.tunnel.destination.address" = self.tunnel_destination_address.to_string(),
            "network.tunnel.destination.port" = self.tunnel_destination_port,
            "network.tunnel.transport" = self.tunnel_network_transport.to_string(),
            "network.tunnel.type" = self.tunnel_network_type.as_str().to_string(),
            "network.byte_count" = self.network_byte_count,
            "network.packet_count" = self.network_packet_count,
            "network.reverse.byte_count" = self.network_reverse_byte_count,
            "network.reverse.packet_count" = self.network_reverse_packet_count,
            // Source Kubernetes attributes
            "source.k8s.cluster.name" = self.source_k8s_cluster_name.as_deref().unwrap_or(""),
            "source.k8s.namespace.name" = self.source_k8s_namespace_name.as_deref().unwrap_or(""),
            "source.k8s.node.name" = self.source_k8s_node_name.as_deref().unwrap_or(""),
            "source.k8s.pod.name" = self.source_k8s_pod_name.as_deref().unwrap_or(""),
            "source.k8s.container.name" = self.source_k8s_container_name.as_deref().unwrap_or(""),
            "source.k8s.deployment.name" = self.source_k8s_deployment_name.as_deref().unwrap_or(""),
            "source.k8s.replicaset.name" = self.source_k8s_replicaset_name.as_deref().unwrap_or(""),
            "source.k8s.statefulset.name" =
                self.source_k8s_statefulset_name.as_deref().unwrap_or(""),
            "source.k8s.daemonset.name" = self.source_k8s_daemonset_name.as_deref().unwrap_or(""),
            "source.k8s.job.name" = self.source_k8s_job_name.as_deref().unwrap_or(""),
            "source.k8s.cronjob.name" = self.source_k8s_cronjob_name.as_deref().unwrap_or(""),
            "source.k8s.service.name" = self.source_k8s_service_name.as_deref().unwrap_or(""),
            // Destination Kubernetes attributes
            "destination.k8s.cluster.name" =
                self.destination_k8s_cluster_name.as_deref().unwrap_or(""),
            "destination.k8s.namespace.name" =
                self.destination_k8s_namespace_name.as_deref().unwrap_or(""),
            "destination.k8s.node.name" = self.destination_k8s_node_name.as_deref().unwrap_or(""),
            "destination.k8s.pod.name" = self.destination_k8s_pod_name.as_deref().unwrap_or(""),
            "destination.k8s.container.name" =
                self.destination_k8s_container_name.as_deref().unwrap_or(""),
            "destination.k8s.deployment.name" = self
                .destination_k8s_deployment_name
                .as_deref()
                .unwrap_or(""),
            "destination.k8s.replicaset.name" = self
                .destination_k8s_replicaset_name
                .as_deref()
                .unwrap_or(""),
            "destination.k8s.statefulset.name" = self
                .destination_k8s_statefulset_name
                .as_deref()
                .unwrap_or(""),
            "destination.k8s.daemonset.name" =
                self.destination_k8s_daemonset_name.as_deref().unwrap_or(""),
            "destination.k8s.job.name" = self.destination_k8s_job_name.as_deref().unwrap_or(""),
            "destination.k8s.cronjob.name" =
                self.destination_k8s_cronjob_name.as_deref().unwrap_or(""),
            "destination.k8s.service.name" =
                self.destination_k8s_service_name.as_deref().unwrap_or(""),
            // Network Policy attribution
            "network.policies.ingress" = self.network_policies_ingress.as_deref().unwrap_or(""),
            "network.policies.egress" = self.network_policies_egress.as_deref().unwrap_or("")
        )
    }
}

/// Flow direction for policy evaluation
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FlowDirection {
    Ingress,
    Egress,
}

pub struct FlowAttributesProducer {
    span_opts: SpanOptions,
    packet_channel_capacity: usize,
    packet_worker_count: usize,
    flow_attrs_map: FlowAttrMap,
    community_id_generator: CommunityIdGenerator,
    packet_meta_rx: mpsc::Receiver<PacketMeta>,
    flow_attrs_tx: mpsc::Sender<FlowAttributes>,
}

impl FlowAttributesProducer {
    pub fn new(
        span_opts: SpanOptions,
        packet_channel_capacity: usize,
        packet_worker_count: usize,
        packet_meta_rx: mpsc::Receiver<PacketMeta>,
        flow_attrs_tx: mpsc::Sender<FlowAttributes>,
    ) -> Self {
        let flow_attrs_map_capacity = packet_channel_capacity * 8;
        let flow_attrs_map = Arc::new(DashMap::with_capacity_and_hasher(
            flow_attrs_map_capacity,
            FxBuildHasher::default(),
        ));
        let community_id_generator = CommunityIdGenerator::new(0);

        Self {
            span_opts,
            packet_channel_capacity,
            packet_worker_count,
            community_id_generator,
            flow_attrs_map,
            packet_meta_rx,
            flow_attrs_tx,
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
                Arc::clone(&self.flow_attrs_map),
                self.community_id_generator.clone(),
                worker_rx,
                self.flow_attrs_tx.clone(),
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
    flow_attrs_map: FlowAttrMap,
    community_id_generator: CommunityIdGenerator,
    packet_meta_rx: mpsc::Receiver<PacketMeta>,
    flow_attrs_tx: mpsc::Sender<FlowAttributes>,
}

impl PacketWorker {
    pub fn new(
        span_opts: SpanOptions,
        flow_attrs_map: FlowAttrMap,
        community_id_generator: CommunityIdGenerator,
        packet_meta_rx: mpsc::Receiver<PacketMeta>,
        flow_attrs_tx: mpsc::Sender<FlowAttributes>,
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
            flow_attrs_tx,
            flow_attrs_map,
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

            let attrs = FlowAttributes {
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
            let _ = self.flow_attrs_tx.send(attrs).await;
        }
    }
}
