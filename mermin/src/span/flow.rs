use std::{net::IpAddr, sync::Arc};

use async_trait::async_trait;
use dashmap::DashMap;
use fxhash::FxBuildHasher;
use network_types::{eth::EtherType, ip::IpProto};
use opentelemetry::trace::SpanKind;
use serde::Serialize;
use tracing::{Span, info_span};

use crate::otlp::trace::lib::Traceable;

#[derive(Debug, Clone, Serialize)]
pub struct FlowSpan {
    pub start_time: u64,
    pub end_time: u64,
    #[serde(serialize_with = "serialize_span_kind")]
    pub span_kind: SpanKind,
    pub attributes: SpanAttributes,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpanAttributes {
    // General Flow Attribute
    pub flow_community_id: String,
    pub flow_connection_state: Option<String>, // TODO: enum
    pub flow_end_reason: String,               // TODO: enum

    // L2-L4 Attributes
    pub source_address: IpAddr,
    pub source_port: u16,
    pub destination_address: IpAddr,
    pub destination_port: u16,
    #[serde(serialize_with = "serialize_ip_proto")]
    pub network_transport: IpProto,
    #[serde(serialize_with = "serialize_ether_type")]
    pub network_type: EtherType,
    pub network_interface_index: Option<u32>,
    pub network_interface_name: Option<String>,
    pub network_interface_mac: Option<String>, // TODO: is there a better type?
    pub flow_ip_dscp_id: Option<u8>,           // TODO: enum
    pub flow_ip_dscp_name: Option<String>,     // TODO: enum
    pub flow_ip_ecn_id: Option<u8>,            // TODO: enum
    pub flow_ip_ecn_name: Option<String>,      // TODO: enum
    pub flow_ip_ttl: Option<u8>,
    pub flow_ip_flow_label: Option<u32>,
    pub flow_icmp_type_id: Option<u8>,       // TODO: enum
    pub flow_icmp_type_name: Option<String>, // TODO: enum
    pub flow_icmp_code_id: Option<u8>,       // TODO: enum
    pub flow_icmp_code_name: Option<String>, // TODO: enum
    pub flow_tcp_flags_bits: Option<u8>,
    pub flow_tcp_flags_tags: Option<Vec<String>>, // TODO: enum

    // Flow Metrics
    pub flow_bytes_delta: i64,
    pub flow_bytes_total: i64,
    pub flow_packets_delta: i64,
    pub flow_packets_total: i64,
    pub flow_reverse_bytes_delta: i64,
    pub flow_reverse_bytes_total: i64,
    pub flow_reverse_packets_delta: i64,
    pub flow_reverse_packets_total: i64,

    // Performance Metrics
    pub flow_tcp_handshake_snd_latency: Option<i64>,
    pub flow_tcp_handshake_snd_jitter: Option<i64>,
    pub flow_tcp_handshake_cnd_latency: Option<i64>,
    pub flow_tcp_handshake_cnd_jitter: Option<i64>,
    pub flow_tcp_svc_latency: Option<i64>,
    pub flow_tcp_svc_jitter: Option<i64>,
    pub flow_tcp_rndtrip_latency: Option<i64>,
    pub flow_tcp_rndtrip_jitter: Option<i64>,

    // Tunnel Attributes
    pub tunnel_type: Option<String>, // TODO: enum
    pub tunnel_source_address: Option<IpAddr>,
    pub tunnel_source_port: Option<u16>,
    pub tunnel_destination_address: Option<IpAddr>,
    pub tunnel_destination_port: Option<u16>,
    #[serde(serialize_with = "serialize_option_ip_proto")]
    pub tunnel_network_transport: Option<IpProto>,
    #[serde(serialize_with = "serialize_option_ether_type")]
    pub tunnel_network_type: Option<EtherType>,
    pub tunnel_id: Option<String>,
    pub tunnel_key: Option<u32>,
    pub tunnel_sender_index: Option<u32>,
    pub tunnel_receiver_index: Option<u32>,
    pub tunnel_spi: Option<u32>,

    // Kubernetes & Application Attributes
    pub source_k8s_cluster_name: Option<String>,
    pub source_k8s_cluster_uid: Option<String>,
    pub source_k8s_node_name: Option<String>,
    pub source_k8s_node_uid: Option<String>,
    pub source_k8s_namespace_name: Option<String>,
    pub source_k8s_pod_name: Option<String>,
    pub source_k8s_pod_uid: Option<String>,
    pub source_k8s_container_name: Option<String>,
    pub source_k8s_deployment_name: Option<String>,
    pub source_k8s_deployment_uid: Option<String>,
    pub source_k8s_replicaset_name: Option<String>,
    pub source_k8s_replicaset_uid: Option<String>,
    pub source_k8s_statefulset_name: Option<String>,
    pub source_k8s_statefulset_uid: Option<String>,
    pub source_k8s_daemonset_name: Option<String>,
    pub source_k8s_daemonset_uid: Option<String>,
    pub source_k8s_job_name: Option<String>,
    pub source_k8s_job_uid: Option<String>,
    pub source_k8s_cronjob_name: Option<String>,
    pub source_k8s_cronjob_uid: Option<String>,
    pub source_k8s_service_name: Option<String>,
    pub source_k8s_service_uid: Option<String>,
    pub destination_k8s_cluster_name: Option<String>,
    pub destination_k8s_cluster_uid: Option<String>,
    pub destination_k8s_node_name: Option<String>,
    pub destination_k8s_node_uid: Option<String>,
    pub destination_k8s_namespace_name: Option<String>,
    pub destination_k8s_pod_name: Option<String>,
    pub destination_k8s_pod_uid: Option<String>,
    pub destination_k8s_container_name: Option<String>,
    pub destination_k8s_deployment_name: Option<String>,
    pub destination_k8s_deployment_uid: Option<String>,
    pub destination_k8s_replicaset_name: Option<String>,
    pub destination_k8s_replicaset_uid: Option<String>,
    pub destination_k8s_statefulset_name: Option<String>,
    pub destination_k8s_statefulset_uid: Option<String>,
    pub destination_k8s_daemonset_name: Option<String>,
    pub destination_k8s_daemonset_uid: Option<String>,
    pub destination_k8s_job_name: Option<String>,
    pub destination_k8s_job_uid: Option<String>,
    pub destination_k8s_cronjob_name: Option<String>,
    pub destination_k8s_cronjob_uid: Option<String>,
    pub destination_k8s_service_name: Option<String>,
    pub destination_k8s_service_uid: Option<String>,
    pub network_policies_ingress: Option<Vec<String>>,
    pub network_policies_egress: Option<Vec<String>>,
    pub process_executable_name: Option<String>,
    pub container_image_name: Option<String>,
    pub container_name: Option<String>,
}

impl Traceable for FlowSpan {
    fn to_span(&self) -> Span {
        #[allow(unused_variables)]
        let span_name = format!(
            "flow_{}_{}",
            self.attributes.network_type.as_str(),
            self.attributes.network_transport.to_string().as_str()
        );

        // Create span with required fields and placeholders for optional fields
        // TODO: replace with span! macro once we migrate away from using tracing here.
        // TODO: tracing::field::Empty should not be added in the future when migrating away from using tracing here.
        let span = info_span!(
            "flow_span", // TODO: replace with span_name once we migrate away from using tracing here.
            "flow.community_id" = self.attributes.flow_community_id,
            "flow.connection_state" = tracing::field::Empty,
            "flow.end_reason" = self.attributes.flow_end_reason,
            "network.source.address" = self.attributes.source_address.to_string(),
            "network.source.port" = self.attributes.source_port,
            "network.destination.address" = self.attributes.destination_address.to_string(),
            "network.destination.port" = self.attributes.destination_port,
            "network.transport" = self.attributes.network_transport.to_string(),
            "network.type" = self.attributes.network_type.as_str().to_string(),
            "network.interface.index" = tracing::field::Empty,
            "network.interface.name" = tracing::field::Empty,
            "network.interface.mac" = tracing::field::Empty,
            "flow.ip.dscp.id" = tracing::field::Empty,
            "flow.ip.dscp.name" = tracing::field::Empty,
            "flow.ip.ecn.id" = tracing::field::Empty,
            "flow.ip.ecn.name" = tracing::field::Empty,
            "flow.ip.ttl" = tracing::field::Empty,
            "flow.ip.flow_label" = tracing::field::Empty,
            "flow.icmp.type.id" = tracing::field::Empty,
            "flow.icmp.type.name" = tracing::field::Empty,
            "flow.icmp.code.id" = tracing::field::Empty,
            "flow.icmp.code.name" = tracing::field::Empty,
            "flow.tcp.flags.bits" = tracing::field::Empty,
            "flow.tcp.flags.tags" = tracing::field::Empty,
            "flow.bytes.delta" = self.attributes.flow_bytes_delta,
            "flow.bytes.total" = self.attributes.flow_bytes_total,
            "flow.packets.delta" = self.attributes.flow_packets_delta,
            "flow.packets.total" = self.attributes.flow_packets_total,
            "flow.reverse.bytes.delta" = self.attributes.flow_reverse_bytes_delta,
            "flow.reverse.bytes.total" = self.attributes.flow_reverse_bytes_total,
            "flow.reverse.packets.delta" = self.attributes.flow_reverse_packets_delta,
            "flow.reverse.packets.total" = self.attributes.flow_reverse_packets_total,
            "flow.tcp.handshake.snd.latency" = tracing::field::Empty,
            "flow.tcp.handshake.snd.jitter" = tracing::field::Empty,
            "flow.tcp.handshake.cnd.latency" = tracing::field::Empty,
            "flow.tcp.handshake.cnd.jitter" = tracing::field::Empty,
            "flow.tcp.svc.latency" = tracing::field::Empty,
            "flow.tcp.svc.jitter" = tracing::field::Empty,
            "flow.tcp.rndtrip.latency" = tracing::field::Empty,
            "flow.tcp.rndtrip.jitter" = tracing::field::Empty,
            "tunnel.type" = tracing::field::Empty,
            "tunnel.source.address" = tracing::field::Empty,
            "tunnel.source.port" = tracing::field::Empty,
            "tunnel.destination.address" = tracing::field::Empty,
            "tunnel.destination.port" = tracing::field::Empty,
            "tunnel.network.transport" = tracing::field::Empty,
            "tunnel.network.type" = tracing::field::Empty,
            "tunnel.id" = tracing::field::Empty,
            "tunnel.key" = tracing::field::Empty,
            "tunnel.sender_index" = tracing::field::Empty,
            "tunnel.receiver_index" = tracing::field::Empty,
            "tunnel.spi" = tracing::field::Empty,
            "source.k8s.cluster.name" = tracing::field::Empty,
            "source.k8s.cluster.uid" = tracing::field::Empty,
            "source.k8s.node.name" = tracing::field::Empty,
            "source.k8s.node.uid" = tracing::field::Empty,
            "source.k8s.namespace.name" = tracing::field::Empty,
            "source.k8s.pod.name" = tracing::field::Empty,
            "source.k8s.pod.uid" = tracing::field::Empty,
            "source.k8s.container.name" = tracing::field::Empty,
            "source.k8s.deployment.name" = tracing::field::Empty,
            "source.k8s.deployment.uid" = tracing::field::Empty,
            "source.k8s.replicaset.name" = tracing::field::Empty,
            "source.k8s.replicaset.uid" = tracing::field::Empty,
            "source.k8s.statefulset.name" = tracing::field::Empty,
            "source.k8s.statefulset.uid" = tracing::field::Empty,
            "source.k8s.daemonset.name" = tracing::field::Empty,
            "source.k8s.daemonset.uid" = tracing::field::Empty,
            "source.k8s.job.name" = tracing::field::Empty,
            "source.k8s.job.uid" = tracing::field::Empty,
            "source.k8s.cronjob.name" = tracing::field::Empty,
            "source.k8s.cronjob.uid" = tracing::field::Empty,
            "source.k8s.service.name" = tracing::field::Empty,
            "source.k8s.service.uid" = tracing::field::Empty,
            "destination.k8s.cluster.name" = tracing::field::Empty,
            "destination.k8s.cluster.uid" = tracing::field::Empty,
            "destination.k8s.node.name" = tracing::field::Empty,
            "destination.k8s.node.uid" = tracing::field::Empty,
            "destination.k8s.namespace.name" = tracing::field::Empty,
            "destination.k8s.pod.name" = tracing::field::Empty,
            "destination.k8s.pod.uid" = tracing::field::Empty,
            "destination.k8s.container.name" = tracing::field::Empty,
            "destination.k8s.deployment.name" = tracing::field::Empty,
            "destination.k8s.deployment.uid" = tracing::field::Empty,
            "destination.k8s.replicaset.name" = tracing::field::Empty,
            "destination.k8s.replicaset.uid" = tracing::field::Empty,
            "destination.k8s.statefulset.name" = tracing::field::Empty,
            "destination.k8s.statefulset.uid" = tracing::field::Empty,
            "destination.k8s.daemonset.name" = tracing::field::Empty,
            "destination.k8s.daemonset.uid" = tracing::field::Empty,
            "destination.k8s.job.name" = tracing::field::Empty,
            "destination.k8s.job.uid" = tracing::field::Empty,
            "destination.k8s.cronjob.name" = tracing::field::Empty,
            "destination.k8s.cronjob.uid" = tracing::field::Empty,
            "destination.k8s.service.name" = tracing::field::Empty,
            "destination.k8s.service.uid" = tracing::field::Empty,
            "network.policies.ingress" = tracing::field::Empty,
            "network.policies.egress" = tracing::field::Empty,
            "process.executable.name" = tracing::field::Empty,
            "container.image.name" = tracing::field::Empty,
            "container.name" = tracing::field::Empty,
        );

        // Record optional fields only if they have values
        if let Some(ref value) = self.attributes.flow_connection_state {
            span.record("flow.connection_state", value);
        }
        if let Some(value) = self.attributes.network_interface_index {
            span.record("network.interface.index", value);
        }
        if let Some(ref value) = self.attributes.network_interface_name {
            span.record("network.interface.name", value);
        }
        if let Some(ref value) = self.attributes.network_interface_mac {
            span.record("network.interface.mac", value);
        }
        if let Some(value) = self.attributes.flow_ip_dscp_id {
            span.record("flow.ip.dscp.id", value);
        }
        if let Some(ref value) = self.attributes.flow_ip_dscp_name {
            span.record("flow.ip.dscp.name", value);
        }
        if let Some(value) = self.attributes.flow_ip_ecn_id {
            span.record("flow.ip.ecn.id", value);
        }
        if let Some(ref value) = self.attributes.flow_ip_ecn_name {
            span.record("flow.ip.ecn.name", value);
        }
        if let Some(value) = self.attributes.flow_ip_ttl {
            span.record("flow.ip.ttl", value);
        }
        if let Some(value) = self.attributes.flow_ip_flow_label {
            span.record("flow.ip.flow_label", value);
        }
        if let Some(value) = self.attributes.flow_icmp_type_id {
            span.record("flow.icmp.type.id", value);
        }
        if let Some(ref value) = self.attributes.flow_icmp_type_name {
            span.record("flow.icmp.type.name", value);
        }
        if let Some(value) = self.attributes.flow_icmp_code_id {
            span.record("flow.icmp.code.id", value);
        }
        if let Some(ref value) = self.attributes.flow_icmp_code_name {
            span.record("flow.icmp.code.name", value);
        }
        if let Some(value) = self.attributes.flow_tcp_flags_bits {
            span.record("flow.tcp.flags.bits", value);
        }
        if let Some(ref value) = self.attributes.flow_tcp_flags_tags {
            span.record("flow.tcp.flags.tags", format!("{value:?}"));
        }
        if let Some(value) = self.attributes.flow_tcp_handshake_snd_latency {
            span.record("flow.tcp.handshake.snd.latency", value);
        }
        if let Some(value) = self.attributes.flow_tcp_handshake_snd_jitter {
            span.record("flow.tcp.handshake.snd.jitter", value);
        }
        if let Some(value) = self.attributes.flow_tcp_handshake_cnd_latency {
            span.record("flow.tcp.handshake.cnd.latency", value);
        }
        if let Some(value) = self.attributes.flow_tcp_handshake_cnd_jitter {
            span.record("flow.tcp.handshake.cnd.jitter", value);
        }
        if let Some(value) = self.attributes.flow_tcp_svc_latency {
            span.record("flow.tcp.svc.latency", value);
        }
        if let Some(value) = self.attributes.flow_tcp_svc_jitter {
            span.record("flow.tcp.svc.jitter", value);
        }
        if let Some(value) = self.attributes.flow_tcp_rndtrip_latency {
            span.record("flow.tcp.rndtrip.latency", value);
        }
        if let Some(value) = self.attributes.flow_tcp_rndtrip_jitter {
            span.record("flow.tcp.rndtrip.jitter", value);
        }
        if let Some(ref value) = self.attributes.tunnel_type {
            span.record("tunnel.type", value);
        }
        if let Some(value) = self.attributes.tunnel_source_address {
            span.record("tunnel.source.address", value.to_string());
        }
        if let Some(value) = self.attributes.tunnel_source_port {
            span.record("tunnel.source.port", value);
        }
        if let Some(value) = self.attributes.tunnel_destination_address {
            span.record("tunnel.destination.address", value.to_string());
        }
        if let Some(value) = self.attributes.tunnel_destination_port {
            span.record("tunnel.destination.port", value);
        }
        if let Some(value) = self.attributes.tunnel_network_transport {
            span.record("tunnel.network.transport", value.to_string());
        }
        if let Some(value) = self.attributes.tunnel_network_type {
            span.record("tunnel.network.type", value.as_str().to_string());
        }
        if let Some(ref value) = self.attributes.tunnel_id {
            span.record("tunnel.id", value);
        }
        if let Some(value) = self.attributes.tunnel_key {
            span.record("tunnel.key", value);
        }
        if let Some(value) = self.attributes.tunnel_sender_index {
            span.record("tunnel.sender_index", value);
        }
        if let Some(value) = self.attributes.tunnel_receiver_index {
            span.record("tunnel.receiver_index", value);
        }
        if let Some(value) = self.attributes.tunnel_spi {
            span.record("tunnel.spi", value);
        }
        if let Some(ref value) = self.attributes.source_k8s_cluster_name {
            span.record("source.k8s.cluster.name", value);
        }
        if let Some(ref value) = self.attributes.source_k8s_cluster_uid {
            span.record("source.k8s.cluster.uid", value);
        }
        if let Some(ref value) = self.attributes.source_k8s_node_name {
            span.record("source.k8s.node.name", value);
        }
        if let Some(ref value) = self.attributes.source_k8s_node_uid {
            span.record("source.k8s.node.uid", value);
        }
        if let Some(ref value) = self.attributes.source_k8s_namespace_name {
            span.record("source.k8s.namespace.name", value);
        }
        if let Some(ref value) = self.attributes.source_k8s_pod_name {
            span.record("source.k8s.pod.name", value);
        }
        if let Some(ref value) = self.attributes.source_k8s_pod_uid {
            span.record("source.k8s.pod.uid", value);
        }
        if let Some(ref value) = self.attributes.source_k8s_container_name {
            span.record("source.k8s.container.name", value);
        }
        if let Some(ref value) = self.attributes.source_k8s_deployment_name {
            span.record("source.k8s.deployment.name", value);
        }
        if let Some(ref value) = self.attributes.source_k8s_deployment_uid {
            span.record("source.k8s.deployment.uid", value);
        }
        if let Some(ref value) = self.attributes.source_k8s_replicaset_name {
            span.record("source.k8s.replicaset.name", value);
        }
        if let Some(ref value) = self.attributes.source_k8s_replicaset_uid {
            span.record("source.k8s.replicaset.uid", value);
        }
        if let Some(ref value) = self.attributes.source_k8s_statefulset_name {
            span.record("source.k8s.statefulset.name", value);
        }
        if let Some(ref value) = self.attributes.source_k8s_statefulset_uid {
            span.record("source.k8s.statefulset.uid", value);
        }
        if let Some(ref value) = self.attributes.source_k8s_daemonset_name {
            span.record("source.k8s.daemonset.name", value);
        }
        if let Some(ref value) = self.attributes.source_k8s_daemonset_uid {
            span.record("source.k8s.daemonset.uid", value);
        }
        if let Some(ref value) = self.attributes.source_k8s_job_name {
            span.record("source.k8s.job.name", value);
        }
        if let Some(ref value) = self.attributes.source_k8s_job_uid {
            span.record("source.k8s.job.uid", value);
        }
        if let Some(ref value) = self.attributes.source_k8s_cronjob_name {
            span.record("source.k8s.cronjob.name", value);
        }
        if let Some(ref value) = self.attributes.source_k8s_cronjob_uid {
            span.record("source.k8s.cronjob.uid", value);
        }
        if let Some(ref value) = self.attributes.source_k8s_service_name {
            span.record("source.k8s.service.name", value);
        }
        if let Some(ref value) = self.attributes.source_k8s_service_uid {
            span.record("source.k8s.service.uid", value);
        }
        if let Some(ref value) = self.attributes.destination_k8s_cluster_name {
            span.record("destination.k8s.cluster.name", value);
        }
        if let Some(ref value) = self.attributes.destination_k8s_cluster_uid {
            span.record("destination.k8s.cluster.uid", value);
        }
        if let Some(ref value) = self.attributes.destination_k8s_node_name {
            span.record("destination.k8s.node.name", value);
        }
        if let Some(ref value) = self.attributes.destination_k8s_node_uid {
            span.record("destination.k8s.node.uid", value);
        }
        if let Some(ref value) = self.attributes.destination_k8s_namespace_name {
            span.record("destination.k8s.namespace.name", value);
        }
        if let Some(ref value) = self.attributes.destination_k8s_pod_name {
            span.record("destination.k8s.pod.name", value);
        }
        if let Some(ref value) = self.attributes.destination_k8s_pod_uid {
            span.record("destination.k8s.pod.uid", value);
        }
        if let Some(ref value) = self.attributes.destination_k8s_container_name {
            span.record("destination.k8s.container.name", value);
        }
        if let Some(ref value) = self.attributes.destination_k8s_deployment_name {
            span.record("destination.k8s.deployment.name", value);
        }
        if let Some(ref value) = self.attributes.destination_k8s_deployment_uid {
            span.record("destination.k8s.deployment.uid", value);
        }
        if let Some(ref value) = self.attributes.destination_k8s_replicaset_name {
            span.record("destination.k8s.replicaset.name", value);
        }
        if let Some(ref value) = self.attributes.destination_k8s_replicaset_uid {
            span.record("destination.k8s.replicaset.uid", value);
        }
        if let Some(ref value) = self.attributes.destination_k8s_statefulset_name {
            span.record("destination.k8s.statefulset.name", value);
        }
        if let Some(ref value) = self.attributes.destination_k8s_statefulset_uid {
            span.record("destination.k8s.statefulset.uid", value);
        }
        if let Some(ref value) = self.attributes.destination_k8s_daemonset_name {
            span.record("destination.k8s.daemonset.name", value);
        }
        if let Some(ref value) = self.attributes.destination_k8s_daemonset_uid {
            span.record("destination.k8s.daemonset.uid", value);
        }
        if let Some(ref value) = self.attributes.destination_k8s_job_name {
            span.record("destination.k8s.job.name", value);
        }
        if let Some(ref value) = self.attributes.destination_k8s_job_uid {
            span.record("destination.k8s.job.uid", value);
        }
        if let Some(ref value) = self.attributes.destination_k8s_cronjob_name {
            span.record("destination.k8s.cronjob.name", value);
        }
        if let Some(ref value) = self.attributes.destination_k8s_cronjob_uid {
            span.record("destination.k8s.cronjob.uid", value);
        }
        if let Some(ref value) = self.attributes.destination_k8s_service_name {
            span.record("destination.k8s.service.name", value);
        }
        if let Some(ref value) = self.attributes.destination_k8s_service_uid {
            span.record("destination.k8s.service.uid", value);
        }
        if let Some(ref value) = self.attributes.network_policies_ingress {
            span.record("network.policies.ingress", value.join(","));
        }
        if let Some(ref value) = self.attributes.network_policies_egress {
            span.record("network.policies.egress", value.join(","));
        }
        if let Some(ref value) = self.attributes.process_executable_name {
            span.record("process.executable.name", value);
        }
        if let Some(ref value) = self.attributes.container_image_name {
            span.record("container.image.name", value);
        }
        if let Some(ref value) = self.attributes.container_name {
            span.record("container.name", value);
        }

        span
    }
}

pub type FlowSpanMap = Arc<DashMap<String, FlowSpan, FxBuildHasher>>;

#[async_trait]
pub trait FlowSpanExporter: Send + Sync {
    async fn export(&self, flow_span: FlowSpan);
    async fn shutdown(&self) -> anyhow::Result<()>;
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

fn serialize_option_ip_proto<S>(proto: &Option<IpProto>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match proto {
        Some(p) => serializer.serialize_some(&p.to_string()),
        None => serializer.serialize_none(),
    }
}

fn serialize_option_ether_type<S>(
    ether_type: &Option<EtherType>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match ether_type {
        Some(et) => serializer.serialize_some(et.as_str()),
        None => serializer.serialize_none(),
    }
}

fn serialize_span_kind<S>(span_kind: &SpanKind, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let kind_str = match span_kind {
        SpanKind::Client => "CLIENT",
        SpanKind::Server => "SERVER",
        SpanKind::Producer => "PRODUCER",
        SpanKind::Consumer => "CONSUMER",
        SpanKind::Internal => "INTERNAL",
    };
    serializer.serialize_str(kind_str)
}
