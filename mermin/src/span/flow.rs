use dashmap::DashMap;
use fxhash::FxBuildHasher;
use k8s_openapi::chrono;
use network_types::{eth::EtherType, ip::IpProto};
use serde::{Serialize, Serializer};
use opentelemetry::KeyValue;
use opentelemetry::trace::{Span, SpanKind};
use std::{net::IpAddr, sync::Arc, time::SystemTime};

use crate::{otlp::trace::Traceable, span::tcp::ConnectionState};

/// Flow End Reason based on RFC 5102 IPFIX Information Model
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum FlowEndReason {
    /// 0x01: The Flow was terminated because it was considered to be idle
    IdleTimeout,
    /// 0x02: The Flow was terminated for reporting purposes while it was still active
    ActiveTimeout,
    /// 0x03: The Flow was terminated because signals indicating the end of the Flow were detected (e.g., TCP FIN flag)
    EndOfFlowDetected,
    /// 0x04: The Flow was terminated because of some external event (e.g., shutdown of the Metering Process)
    ForcedEnd,
    /// 0x05: The Flow was terminated because of lack of resources available to the Metering Process and/or the Exporting Process
    LackOfResources,
}

#[allow(dead_code)]
impl FlowEndReason {
    /// Convert the enum variant to its string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            FlowEndReason::IdleTimeout => "idle timeout",
            FlowEndReason::ActiveTimeout => "active timeout",
            FlowEndReason::EndOfFlowDetected => "end of Flow detected",
            FlowEndReason::ForcedEnd => "forced end",
            FlowEndReason::LackOfResources => "lack of resources",
        }
    }

    /// Convert the enum variant to its numeric value as specified in RFC 5102
    pub fn to_u8(self) -> u8 {
        match self {
            FlowEndReason::IdleTimeout => 0x01,
            FlowEndReason::ActiveTimeout => 0x02,
            FlowEndReason::EndOfFlowDetected => 0x03,
            FlowEndReason::ForcedEnd => 0x04,
            FlowEndReason::LackOfResources => 0x05,
        }
    }

    /// Create FlowEndReason from a numeric value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(FlowEndReason::IdleTimeout),
            0x02 => Some(FlowEndReason::ActiveTimeout),
            0x03 => Some(FlowEndReason::EndOfFlowDetected),
            0x04 => Some(FlowEndReason::ForcedEnd),
            0x05 => Some(FlowEndReason::LackOfResources),
            _ => None,
        }
    }
}

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
    #[serde(serialize_with = "serialize_connection_state")]
    pub flow_connection_state: Option<ConnectionState>,
    #[serde(serialize_with = "serialize_flow_end_reason")]
    pub flow_end_reason: Option<FlowEndReason>,

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
    #[serde(serialize_with = "serialize_option_mac_addr")]
    pub network_interface_mac: Option<pnet::datalink::MacAddr>,
    pub flow_ip_dscp_id: Option<u8>,
    pub flow_ip_dscp_name: Option<String>,
    pub flow_ip_ecn_id: Option<u8>,
    pub flow_ip_ecn_name: Option<String>,
    pub flow_ip_ttl: Option<u8>,
    pub flow_ip_flow_label: Option<u32>,
    pub flow_icmp_type_id: Option<u8>,
    pub flow_icmp_type_name: Option<String>,
    pub flow_icmp_code_id: Option<u8>,
    pub flow_icmp_code_name: Option<String>,
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
    fn start_time(&self) -> SystemTime {
        chrono::DateTime::from_timestamp_nanos(self.start_time as i64).into()
    }

    fn end_time(&self) -> SystemTime {
        chrono::DateTime::from_timestamp_nanos(self.end_time as i64).into()
    }

    fn name(&self) -> Option<String> {
        Some(format!(
            "flow_{}_{}",
            self.attributes.network_type.as_str(),
            self.attributes.network_transport.to_string().as_str()
        ))
    }

    fn record(&self, mut span: opentelemetry_sdk::trace::Span) -> opentelemetry_sdk::trace::Span {
        let mut kvs = Vec::with_capacity(115);
        kvs.push(KeyValue::new(
            "flow.community_id",
            self.attributes.flow_community_id.to_string(),
        ));
        kvs.push(KeyValue::new("flow.connection_state", ""));
        kvs.push(KeyValue::new(
            "network.source.address",
            self.attributes.source_address.to_string(),
        ));
        kvs.push(KeyValue::new(
            "network.source.port",
            self.attributes.source_port as i64,
        ));
        kvs.push(KeyValue::new(
            "network.destination.address",
            self.attributes.destination_address.to_string(),
        ));
        kvs.push(KeyValue::new(
            "network.destination.port",
            self.attributes.destination_port as i64,
        ));
        kvs.push(KeyValue::new(
            "network.transport",
            self.attributes.network_transport.to_owned().as_str(),
        ));
        kvs.push(KeyValue::new(
            "network.type",
            self.attributes.network_type.to_owned().as_str(),
        ));
        kvs.push(KeyValue::new("network.interface.index", ""));
        kvs.push(KeyValue::new("network.interface.name", ""));
        kvs.push(KeyValue::new("network.interface.mac", ""));
        kvs.push(KeyValue::new("flow.ip.dscp.id", ""));
        kvs.push(KeyValue::new("flow.ip.dscp.name", ""));
        kvs.push(KeyValue::new("flow.ip.ecn.id", ""));
        kvs.push(KeyValue::new("flow.ip.ecn.name", ""));
        kvs.push(KeyValue::new("flow.ip.ttl", ""));
        kvs.push(KeyValue::new("flow.ip.flow_label", ""));
        kvs.push(KeyValue::new("flow.icmp.type.id", ""));
        kvs.push(KeyValue::new("flow.icmp.type.name", ""));
        kvs.push(KeyValue::new("flow.icmp.code.id", ""));
        kvs.push(KeyValue::new("flow.icmp.code.name", ""));
        kvs.push(KeyValue::new("flow.tcp.flags.bits", ""));
        kvs.push(KeyValue::new("flow.tcp.flags.tags", ""));
        kvs.push(KeyValue::new(
            "flow.bytes.delta",
            self.attributes.flow_bytes_delta,
        ));
        kvs.push(KeyValue::new(
            "flow.bytes.total",
            self.attributes.flow_bytes_total,
        ));
        kvs.push(KeyValue::new(
            "flow.packets.delta",
            self.attributes.flow_packets_delta,
        ));
        kvs.push(KeyValue::new(
            "flow.packets.total",
            self.attributes.flow_packets_total,
        ));
        kvs.push(KeyValue::new(
            "flow.reverse.bytes.delta",
            self.attributes.flow_reverse_bytes_delta,
        ));
        kvs.push(KeyValue::new(
            "flow.reverse.bytes.total",
            self.attributes.flow_reverse_bytes_total,
        ));
        kvs.push(KeyValue::new(
            "flow.reverse.packets.delta",
            self.attributes.flow_reverse_packets_delta,
        ));
        kvs.push(KeyValue::new(
            "flow.reverse.packets.total",
            self.attributes.flow_reverse_packets_total,
        ));
        kvs.push(KeyValue::new("flow.tcp.handshake.snd.latency", ""));
        kvs.push(KeyValue::new("flow.tcp.handshake.snd.jitter", ""));
        kvs.push(KeyValue::new("flow.tcp.handshake.cnd.latency", ""));
        kvs.push(KeyValue::new("flow.tcp.handshake.cnd.jitter", ""));
        kvs.push(KeyValue::new("flow.tcp.svc.latency", ""));
        kvs.push(KeyValue::new("flow.tcp.svc.jitter", ""));
        kvs.push(KeyValue::new("flow.tcp.rndtrip.latency", ""));
        kvs.push(KeyValue::new("flow.tcp.rndtrip.jitter", ""));
        kvs.push(KeyValue::new("tunnel.type", ""));
        kvs.push(KeyValue::new("tunnel.source.address", ""));
        kvs.push(KeyValue::new("tunnel.source.port", ""));
        kvs.push(KeyValue::new("tunnel.destination.address", ""));
        kvs.push(KeyValue::new("tunnel.destination.port", ""));
        kvs.push(KeyValue::new("tunnel.network.transport", ""));
        kvs.push(KeyValue::new("tunnel.network.type", ""));
        kvs.push(KeyValue::new("tunnel.id", ""));
        kvs.push(KeyValue::new("tunnel.key", ""));
        kvs.push(KeyValue::new("tunnel.sender_index", ""));
        kvs.push(KeyValue::new("tunnel.receiver_index", ""));
        kvs.push(KeyValue::new("tunnel.spi", ""));
        kvs.push(KeyValue::new("source.k8s.cluster.name", ""));
        kvs.push(KeyValue::new("source.k8s.cluster.uid", ""));
        kvs.push(KeyValue::new("source.k8s.node.name", ""));
        kvs.push(KeyValue::new("source.k8s.node.uid", ""));
        kvs.push(KeyValue::new("source.k8s.namespace.name", ""));
        kvs.push(KeyValue::new("source.k8s.pod.name", ""));
        kvs.push(KeyValue::new("source.k8s.pod.uid", ""));
        kvs.push(KeyValue::new("source.k8s.container.name", ""));
        kvs.push(KeyValue::new("source.k8s.deployment.name", ""));
        kvs.push(KeyValue::new("source.k8s.deployment.uid", ""));
        kvs.push(KeyValue::new("source.k8s.replicaset.name", ""));
        kvs.push(KeyValue::new("source.k8s.replicaset.uid", ""));
        kvs.push(KeyValue::new("source.k8s.statefulset.name", ""));
        kvs.push(KeyValue::new("source.k8s.statefulset.uid", ""));
        kvs.push(KeyValue::new("source.k8s.daemonset.name", ""));
        kvs.push(KeyValue::new("source.k8s.daemonset.uid", ""));
        kvs.push(KeyValue::new("source.k8s.job.name", ""));
        kvs.push(KeyValue::new("source.k8s.job.uid", ""));
        kvs.push(KeyValue::new("source.k8s.cronjob.name", ""));
        kvs.push(KeyValue::new("source.k8s.cronjob.uid", ""));
        kvs.push(KeyValue::new("source.k8s.service.name", ""));
        kvs.push(KeyValue::new("source.k8s.service.uid", ""));
        kvs.push(KeyValue::new("destination.k8s.cluster.name", ""));
        kvs.push(KeyValue::new("destination.k8s.cluster.uid", ""));
        kvs.push(KeyValue::new("destination.k8s.node.name", ""));
        kvs.push(KeyValue::new("destination.k8s.node.uid", ""));
        kvs.push(KeyValue::new("destination.k8s.namespace.name", ""));
        kvs.push(KeyValue::new("destination.k8s.pod.name", ""));
        kvs.push(KeyValue::new("destination.k8s.pod.uid", ""));
        kvs.push(KeyValue::new("destination.k8s.container.name", ""));
        kvs.push(KeyValue::new("destination.k8s.deployment.name", ""));
        kvs.push(KeyValue::new("destination.k8s.deployment.uid", ""));
        kvs.push(KeyValue::new("destination.k8s.replicaset.name", ""));
        kvs.push(KeyValue::new("destination.k8s.replicaset.uid", ""));
        kvs.push(KeyValue::new("destination.k8s.statefulset.name", ""));
        kvs.push(KeyValue::new("destination.k8s.statefulset.uid", ""));
        kvs.push(KeyValue::new("destination.k8s.daemonset.name", ""));
        kvs.push(KeyValue::new("destination.k8s.daemonset.uid", ""));
        kvs.push(KeyValue::new("destination.k8s.job.name", ""));
        kvs.push(KeyValue::new("destination.k8s.job.uid", ""));
        kvs.push(KeyValue::new("destination.k8s.cronjob.name", ""));
        kvs.push(KeyValue::new("destination.k8s.cronjob.uid", ""));
        kvs.push(KeyValue::new("destination.k8s.service.name", ""));
        kvs.push(KeyValue::new("destination.k8s.service.uid", ""));
        kvs.push(KeyValue::new("network.policies.ingress", ""));
        kvs.push(KeyValue::new("network.policies.egress", ""));
        kvs.push(KeyValue::new("process.executable.name", ""));
        kvs.push(KeyValue::new("container.image.name", ""));
        kvs.push(KeyValue::new("container.name", ""));

        // Record optional fields only if they have values
        if let Some(ref value) = self.attributes.flow_connection_state {
            kvs.push(KeyValue::new("flow.connection_state", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.flow_end_reason {
            kvs.push(KeyValue::new("flow.end_reason", value.as_str()));
        }
        if let Some(value) = self.attributes.network_interface_index {
            kvs.push(KeyValue::new("network.interface.index", value as i64));
        }
        if let Some(ref value) = self.attributes.network_interface_name {
            kvs.push(KeyValue::new("network.interface.name", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.network_interface_mac {
            kvs.push(KeyValue::new("network.interface.mac", value.to_owned()));
        }
        if let Some(value) = self.attributes.flow_ip_dscp_id {
            kvs.push(KeyValue::new("flow.ip.dscp.id", value as i64));
        }
        if let Some(ref value) = self.attributes.flow_ip_dscp_name {
            kvs.push(KeyValue::new("flow.ip.dscp.name", value.to_owned()));
        }
        if let Some(value) = self.attributes.flow_ip_ecn_id {
            kvs.push(KeyValue::new("flow.ip.ecn.id", value as i64));
        }
        if let Some(ref value) = self.attributes.flow_ip_ecn_name {
            kvs.push(KeyValue::new("flow.ip.ecn.name", value.to_owned()));
        }
        if let Some(value) = self.attributes.flow_ip_ttl {
            kvs.push(KeyValue::new("flow.ip.ttl", value as i64));
        }
        if let Some(value) = self.attributes.flow_ip_flow_label {
            kvs.push(KeyValue::new("flow.ip.flow_label", value as i64));
        }
        if let Some(value) = self.attributes.flow_icmp_type_id {
            kvs.push(KeyValue::new("flow.icmp.type.id", value as i64));
        }
        if let Some(ref value) = self.attributes.flow_icmp_type_name {
            kvs.push(KeyValue::new("flow.icmp.type.name", value.to_owned()));
        }
        if let Some(value) = self.attributes.flow_icmp_code_id {
            kvs.push(KeyValue::new("flow.icmp.code.id", value as i64));
        }
        if let Some(ref value) = self.attributes.flow_icmp_code_name {
            kvs.push(KeyValue::new("flow.icmp.code.name", value.to_owned()));
        }
        if let Some(value) = self.attributes.flow_tcp_flags_bits {
            kvs.push(KeyValue::new("flow.tcp.flags.bits", value as i64));
        }
        if let Some(ref value) = self.attributes.flow_tcp_flags_tags {
            kvs.push(KeyValue::new("flow.tcp.flags.tags", format!("{value:?}")));
        }
        if let Some(value) = self.attributes.flow_tcp_handshake_snd_latency {
            kvs.push(KeyValue::new("flow.tcp.handshake.snd.latency", value));
        }
        if let Some(value) = self.attributes.flow_tcp_handshake_snd_jitter {
            kvs.push(KeyValue::new("flow.tcp.handshake.snd.jitter", value));
        }
        if let Some(value) = self.attributes.flow_tcp_handshake_cnd_latency {
            kvs.push(KeyValue::new("flow.tcp.handshake.cnd.latency", value));
        }
        if let Some(value) = self.attributes.flow_tcp_handshake_cnd_jitter {
            kvs.push(KeyValue::new("flow.tcp.handshake.cnd.jitter", value));
        }
        if let Some(value) = self.attributes.flow_tcp_svc_latency {
            kvs.push(KeyValue::new("flow.tcp.svc.latency", value));
        }
        if let Some(value) = self.attributes.flow_tcp_svc_jitter {
            kvs.push(KeyValue::new("flow.tcp.svc.jitter", value));
        }
        if let Some(value) = self.attributes.flow_tcp_rndtrip_latency {
            kvs.push(KeyValue::new("flow.tcp.rndtrip.latency", value));
        }
        if let Some(value) = self.attributes.flow_tcp_rndtrip_jitter {
            kvs.push(KeyValue::new("flow.tcp.rndtrip.jitter", value));
        }
        if let Some(ref value) = self.attributes.tunnel_type {
            kvs.push(KeyValue::new("tunnel.type", value.to_owned()));
        }
        if let Some(value) = self.attributes.tunnel_source_address {
            kvs.push(KeyValue::new("tunnel.source.address", value.to_string()));
        }
        if let Some(value) = self.attributes.tunnel_source_port {
            kvs.push(KeyValue::new("tunnel.source.port", value as i64));
        }
        if let Some(value) = self.attributes.tunnel_destination_address {
            kvs.push(KeyValue::new(
                "tunnel.destination.address",
                value.to_string(),
            ));
        }
        if let Some(value) = self.attributes.tunnel_destination_port {
            kvs.push(KeyValue::new("tunnel.destination.port", value as i64));
        }
        if let Some(value) = self.attributes.tunnel_network_transport {
            kvs.push(KeyValue::new("tunnel.network.transport", value.to_string()));
        }
        if let Some(value) = self.attributes.tunnel_network_type {
            kvs.push(KeyValue::new(
                "tunnel.network.type",
                value.as_str().to_string(),
            ));
        }
        if let Some(ref value) = self.attributes.tunnel_id {
            kvs.push(KeyValue::new("tunnel.id", value.to_owned()));
        }
        if let Some(value) = self.attributes.tunnel_key {
            kvs.push(KeyValue::new("tunnel.key", value as i64));
        }
        if let Some(value) = self.attributes.tunnel_sender_index {
            kvs.push(KeyValue::new("tunnel.sender_index", value as i64));
        }
        if let Some(value) = self.attributes.tunnel_receiver_index {
            kvs.push(KeyValue::new("tunnel.receiver_index", value as i64));
        }
        if let Some(value) = self.attributes.tunnel_spi {
            kvs.push(KeyValue::new("tunnel.spi", value as i64));
        }
        if let Some(ref value) = self.attributes.source_k8s_cluster_name {
            kvs.push(KeyValue::new("source.k8s.cluster.name", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.source_k8s_cluster_uid {
            kvs.push(KeyValue::new("source.k8s.cluster.uid", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.source_k8s_node_name {
            kvs.push(KeyValue::new("source.k8s.node.name", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.source_k8s_node_uid {
            kvs.push(KeyValue::new("source.k8s.node.uid", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.source_k8s_namespace_name {
            kvs.push(KeyValue::new("source.k8s.namespace.name", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.source_k8s_pod_name {
            kvs.push(KeyValue::new("source.k8s.pod.name", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.source_k8s_pod_uid {
            kvs.push(KeyValue::new("source.k8s.pod.uid", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.source_k8s_container_name {
            kvs.push(KeyValue::new("source.k8s.container.name", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.source_k8s_deployment_name {
            kvs.push(KeyValue::new(
                "source.k8s.deployment.name",
                value.to_owned(),
            ));
        }
        if let Some(ref value) = self.attributes.source_k8s_deployment_uid {
            kvs.push(KeyValue::new("source.k8s.deployment.uid", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.source_k8s_replicaset_name {
            kvs.push(KeyValue::new(
                "source.k8s.replicaset.name",
                value.to_owned(),
            ));
        }
        if let Some(ref value) = self.attributes.source_k8s_replicaset_uid {
            kvs.push(KeyValue::new("source.k8s.replicaset.uid", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.source_k8s_statefulset_name {
            kvs.push(KeyValue::new(
                "source.k8s.statefulset.name",
                value.to_owned(),
            ));
        }
        if let Some(ref value) = self.attributes.source_k8s_statefulset_uid {
            kvs.push(KeyValue::new(
                "source.k8s.statefulset.uid",
                value.to_owned(),
            ));
        }
        if let Some(ref value) = self.attributes.source_k8s_daemonset_name {
            kvs.push(KeyValue::new("source.k8s.daemonset.name", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.source_k8s_daemonset_uid {
            kvs.push(KeyValue::new("source.k8s.daemonset.uid", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.source_k8s_job_name {
            kvs.push(KeyValue::new("source.k8s.job.name", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.source_k8s_job_uid {
            kvs.push(KeyValue::new("source.k8s.job.uid", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.source_k8s_cronjob_name {
            kvs.push(KeyValue::new("source.k8s.cronjob.name", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.source_k8s_cronjob_uid {
            kvs.push(KeyValue::new("source.k8s.cronjob.uid", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.source_k8s_service_name {
            kvs.push(KeyValue::new("source.k8s.service.name", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.source_k8s_service_uid {
            kvs.push(KeyValue::new("source.k8s.service.uid", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.destination_k8s_cluster_name {
            kvs.push(KeyValue::new(
                "destination.k8s.cluster.name",
                value.to_owned(),
            ));
        }
        if let Some(ref value) = self.attributes.destination_k8s_cluster_uid {
            kvs.push(KeyValue::new(
                "destination.k8s.cluster.uid",
                value.to_owned(),
            ));
        }
        if let Some(ref value) = self.attributes.destination_k8s_node_name {
            kvs.push(KeyValue::new("destination.k8s.node.name", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.destination_k8s_node_uid {
            kvs.push(KeyValue::new("destination.k8s.node.uid", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.destination_k8s_namespace_name {
            kvs.push(KeyValue::new(
                "destination.k8s.namespace.name",
                value.to_owned(),
            ));
        }
        if let Some(ref value) = self.attributes.destination_k8s_pod_name {
            kvs.push(KeyValue::new("destination.k8s.pod.name", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.destination_k8s_pod_uid {
            kvs.push(KeyValue::new("destination.k8s.pod.uid", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.destination_k8s_container_name {
            kvs.push(KeyValue::new(
                "destination.k8s.container.name",
                value.to_owned(),
            ));
        }
        if let Some(ref value) = self.attributes.destination_k8s_deployment_name {
            kvs.push(KeyValue::new(
                "destination.k8s.deployment.name",
                value.to_owned(),
            ));
        }
        if let Some(ref value) = self.attributes.destination_k8s_deployment_uid {
            kvs.push(KeyValue::new(
                "destination.k8s.deployment.uid",
                value.to_owned(),
            ));
        }
        if let Some(ref value) = self.attributes.destination_k8s_replicaset_name {
            kvs.push(KeyValue::new(
                "destination.k8s.replicaset.name",
                value.to_owned(),
            ));
        }
        if let Some(ref value) = self.attributes.destination_k8s_replicaset_uid {
            kvs.push(KeyValue::new(
                "destination.k8s.replicaset.uid",
                value.to_owned(),
            ));
        }
        if let Some(ref value) = self.attributes.destination_k8s_statefulset_name {
            kvs.push(KeyValue::new(
                "destination.k8s.statefulset.name",
                value.to_owned(),
            ));
        }
        if let Some(ref value) = self.attributes.destination_k8s_statefulset_uid {
            kvs.push(KeyValue::new(
                "destination.k8s.statefulset.uid",
                value.to_owned(),
            ));
        }
        if let Some(ref value) = self.attributes.destination_k8s_daemonset_name {
            kvs.push(KeyValue::new(
                "destination.k8s.daemonset.name",
                value.to_owned(),
            ));
        }
        if let Some(ref value) = self.attributes.destination_k8s_daemonset_uid {
            kvs.push(KeyValue::new(
                "destination.k8s.daemonset.uid",
                value.to_owned(),
            ));
        }
        if let Some(ref value) = self.attributes.destination_k8s_job_name {
            kvs.push(KeyValue::new("destination.k8s.job.name", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.destination_k8s_job_uid {
            kvs.push(KeyValue::new("destination.k8s.job.uid", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.destination_k8s_cronjob_name {
            kvs.push(KeyValue::new(
                "destination.k8s.cronjob.name",
                value.to_owned(),
            ));
        }
        if let Some(ref value) = self.attributes.destination_k8s_cronjob_uid {
            kvs.push(KeyValue::new(
                "destination.k8s.cronjob.uid",
                value.to_owned(),
            ));
        }
        if let Some(ref value) = self.attributes.destination_k8s_service_name {
            kvs.push(KeyValue::new(
                "destination.k8s.service.name",
                value.to_owned(),
            ));
        }
        if let Some(ref value) = self.attributes.destination_k8s_service_uid {
            kvs.push(KeyValue::new(
                "destination.k8s.service.uid",
                value.to_owned(),
            ));
        }
        if let Some(ref value) = self.attributes.network_policies_ingress {
            kvs.push(KeyValue::new("network.policies.ingress", value.join(",")));
        }
        if let Some(ref value) = self.attributes.network_policies_egress {
            kvs.push(KeyValue::new("network.policies.egress", value.join(",")));
        }
        if let Some(ref value) = self.attributes.process_executable_name {
            kvs.push(KeyValue::new("process.executable.name", value.to_owned()));
        }
        if let Some(ref value) = self.attributes.container_image_name {
            kvs.push(KeyValue::new("container.image.name", value.to_string()));
        }
        if let Some(ref value) = self.attributes.container_name {
            kvs.push(KeyValue::new("container.name", value.to_owned()));
        }
        span.set_attributes(kvs);
        span
    }
}

pub type FlowSpanMap = Arc<DashMap<String, FlowSpan, FxBuildHasher>>;

// Helpers to serialize the IP protocol and EtherType which do not natively implement Serialize
fn serialize_ip_proto<S>(proto: &IpProto, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&proto.to_string())
}

fn serialize_connection_state<S>(
    state: &Option<ConnectionState>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match state {
        Some(s) => serializer.serialize_str(s.as_str()),
        None => serializer.serialize_none(),
    }
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

fn serialize_option_mac_addr<S>(
    mac_addr: &Option<pnet::datalink::MacAddr>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match mac_addr {
        Some(addr) => serializer.serialize_str(&addr.to_string()),
        None => serializer.serialize_none(),
    }
}

fn serialize_flow_end_reason<S>(
    reason: &Option<FlowEndReason>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match reason {
        Some(r) => serializer.serialize_str(r.as_str()),
        None => serializer.serialize_none(),
    }
}
