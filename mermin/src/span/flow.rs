use std::{
    net::IpAddr,
    time::{Duration, SystemTime},
};

use mermin_common::{ConnectionState, TunnelType};
use network_types::{eth::EtherType, ip::IpProto};
use opentelemetry::{
    KeyValue, StringValue, Value,
    trace::{Span, SpanKind},
};
use serde::{Serialize, Serializer};

use crate::{otlp::trace::Traceable, span::tcp::TcpFlag};

/// Flow End Reason based on RFC 5102 IPFIX Information Model
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(dead_code)]
pub enum FlowEndReason {
    /// 0x00: Reserved for future use
    #[default]
    Reserved,
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
            FlowEndReason::Reserved => "reserved",
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
            FlowEndReason::Reserved => 0x00,
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
            0x00 => Some(FlowEndReason::Reserved),
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
    // Trace ID for correlating flows with the same community ID
    #[serde(serialize_with = "serialize_option_trace_id")]
    pub trace_id: Option<opentelemetry::trace::TraceId>,
    pub start_time: SystemTime,
    pub end_time: SystemTime,
    #[serde(serialize_with = "serialize_span_kind")]
    pub span_kind: SpanKind,
    pub attributes: SpanAttributes,

    // eBPF map aggregation fields
    #[serde(skip)]
    pub flow_key: Option<mermin_common::FlowKey>,
    #[serde(skip)]
    pub last_recorded_packets: u64,
    #[serde(skip)]
    pub last_recorded_bytes: u64,
    #[serde(skip)]
    pub last_recorded_reverse_packets: u64,
    #[serde(skip)]
    pub last_recorded_reverse_bytes: u64,
    #[serde(skip)]
    #[allow(dead_code)]
    pub boot_time_offset: u64,

    // Timing metadata for polling architecture
    #[serde(skip)]
    pub last_recorded_time: SystemTime,
    #[serde(skip)]
    pub last_activity_time: SystemTime,
    #[serde(skip)]
    pub timeout_duration: Duration,
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
    pub flow_reverse_ip_dscp_id: Option<u8>,
    pub flow_reverse_ip_dscp_name: Option<String>,
    pub flow_reverse_ip_ecn_id: Option<u8>,
    pub flow_reverse_ip_ecn_name: Option<String>,
    pub flow_reverse_ip_ttl: Option<u8>,
    pub flow_reverse_ip_flow_label: Option<u32>,
    pub flow_icmp_type_id: Option<u8>,
    pub flow_icmp_type_name: Option<String>,
    pub flow_icmp_code_id: Option<u8>,
    pub flow_icmp_code_name: Option<String>,
    pub flow_reverse_icmp_type_id: Option<u8>,
    pub flow_reverse_icmp_type_name: Option<String>,
    pub flow_reverse_icmp_code_id: Option<u8>,
    pub flow_reverse_icmp_code_name: Option<String>,
    pub flow_tcp_flags_bits: Option<u8>,
    #[serde(serialize_with = "serialize_option_tcp_flags")]
    pub flow_tcp_flags_tags: Option<Vec<TcpFlag>>,
    pub flow_reverse_tcp_flags_bits: Option<u8>,
    #[serde(serialize_with = "serialize_option_tcp_flags")]
    pub flow_reverse_tcp_flags_tags: Option<Vec<TcpFlag>>,
    pub flow_ipsec_ah_spi: Option<u32>,
    pub flow_ipsec_esp_spi: Option<u32>,
    pub flow_ipsec_sender_index: Option<u32>,
    pub flow_ipsec_receiver_index: Option<u32>,

    // Client/Server Attributes (populated when direction is known)
    pub client_address: Option<String>,
    pub client_port: Option<u16>,
    pub server_address: Option<String>,
    pub server_port: Option<u16>,

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

    // Ip-in-Ip Attributes
    #[serde(serialize_with = "serialize_option_ether_type")]
    pub ipip_network_type: Option<EtherType>,
    #[serde(serialize_with = "serialize_option_ip_proto")]
    pub ipip_network_transport: Option<IpProto>,
    pub ipip_source_address: Option<IpAddr>,
    pub ipip_destination_address: Option<IpAddr>,

    // Tunnel Attributes
    #[serde(serialize_with = "serialize_option_tunnel_type")]
    pub tunnel_type: Option<TunnelType>,
    #[serde(serialize_with = "serialize_option_mac_addr")]
    pub tunnel_network_interface_mac: Option<pnet::datalink::MacAddr>,
    #[serde(serialize_with = "serialize_option_ether_type")]
    pub tunnel_network_type: Option<EtherType>,
    #[serde(serialize_with = "serialize_option_ip_proto")]
    pub tunnel_network_transport: Option<IpProto>,
    pub tunnel_source_address: Option<IpAddr>,
    pub tunnel_source_port: Option<u16>,
    pub tunnel_destination_address: Option<IpAddr>,
    pub tunnel_destination_port: Option<u16>,
    pub tunnel_id: Option<u32>,
    pub tunnel_ipsec_ah_spi: Option<u32>,

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

impl Default for SpanAttributes {
    fn default() -> Self {
        Self {
            flow_community_id: String::new(),
            flow_connection_state: None,
            flow_end_reason: None,
            source_address: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            source_port: 0,
            destination_address: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            destination_port: 0,
            network_transport: IpProto::default(),
            network_type: EtherType::default(),
            network_interface_index: None,
            network_interface_name: None,
            network_interface_mac: None,
            flow_ip_dscp_id: None,
            flow_ip_dscp_name: None,
            flow_ip_ecn_id: None,
            flow_ip_ecn_name: None,
            flow_ip_ttl: None,
            flow_ip_flow_label: None,
            flow_reverse_ip_dscp_id: None,
            flow_reverse_ip_dscp_name: None,
            flow_reverse_ip_ecn_id: None,
            flow_reverse_ip_ecn_name: None,
            flow_reverse_ip_ttl: None,
            flow_reverse_ip_flow_label: None,
            flow_icmp_type_id: None,
            flow_icmp_type_name: None,
            flow_icmp_code_id: None,
            flow_icmp_code_name: None,
            flow_reverse_icmp_type_id: None,
            flow_reverse_icmp_type_name: None,
            flow_reverse_icmp_code_id: None,
            flow_reverse_icmp_code_name: None,
            flow_tcp_flags_bits: None,
            flow_tcp_flags_tags: None,
            flow_reverse_tcp_flags_bits: None,
            flow_reverse_tcp_flags_tags: None,
            flow_ipsec_ah_spi: None,
            flow_ipsec_esp_spi: None,
            flow_ipsec_sender_index: None,
            flow_ipsec_receiver_index: None,
            client_address: None,
            client_port: None,
            server_address: None,
            server_port: None,
            flow_bytes_delta: 0,
            flow_bytes_total: 0,
            flow_packets_delta: 0,
            flow_packets_total: 0,
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
        }
    }
}

impl Traceable for FlowSpan {
    fn trace_id(&self) -> Option<opentelemetry::trace::TraceId> {
        self.trace_id
    }

    fn start_time(&self) -> SystemTime {
        self.start_time
    }

    fn end_time(&self) -> SystemTime {
        self.end_time
    }

    fn name(&self) -> Option<String> {
        Some(format!(
            "flow_{}_{}",
            self.attributes.network_type.as_str(),
            self.attributes.network_transport.to_string().as_str()
        ))
    }

    fn span_kind(&self) -> opentelemetry::trace::SpanKind {
        self.span_kind.clone()
    }

    fn record(&self, mut span: opentelemetry_sdk::trace::Span) -> opentelemetry_sdk::trace::Span {
        let mut kvs = Vec::with_capacity(115);
        kvs.push(KeyValue::new(
            "flow.community_id",
            self.attributes.flow_community_id.to_string(),
        ));
        kvs.push(KeyValue::new(
            "network.type",
            self.attributes.network_type.to_owned().as_str(),
        ));
        kvs.push(KeyValue::new(
            "network.transport",
            self.attributes.network_transport.to_owned().as_str(),
        ));
        kvs.push(KeyValue::new(
            "source.address",
            self.attributes.source_address.to_string(),
        ));
        kvs.push(KeyValue::new(
            "source.port",
            self.attributes.source_port as i64,
        ));
        kvs.push(KeyValue::new(
            "destination.address",
            self.attributes.destination_address.to_string(),
        ));
        kvs.push(KeyValue::new(
            "destination.port",
            self.attributes.destination_port as i64,
        ));
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
        // Record optional fields only if they have values
        if let Some(ref value) = self.attributes.flow_connection_state {
            kvs.push(KeyValue::new("flow.connection.state", value.as_str()));
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
            kvs.push(KeyValue::new("network.interface.mac", value.to_string()));
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
        if let Some(value) = self.attributes.flow_reverse_icmp_type_id {
            kvs.push(KeyValue::new("flow.reverse.icmp.type.id", value as i64));
        }
        if let Some(ref value) = self.attributes.flow_reverse_icmp_type_name {
            kvs.push(KeyValue::new(
                "flow.reverse.icmp.type.name",
                value.to_owned(),
            ));
        }
        if let Some(value) = self.attributes.flow_reverse_icmp_code_id {
            kvs.push(KeyValue::new("flow.reverse.icmp.code.id", value as i64));
        }
        if let Some(ref value) = self.attributes.flow_reverse_icmp_code_name {
            kvs.push(KeyValue::new(
                "flow.reverse.icmp.code.name",
                value.to_owned(),
            ));
        }
        if let Some(value) = self.attributes.flow_tcp_flags_bits {
            kvs.push(KeyValue::new("flow.tcp.flags.bits", value as i64));
        }
        if let Some(ref value) = self.attributes.flow_tcp_flags_tags {
            let flag_values: Vec<StringValue> = value
                .iter()
                .map(|f| StringValue::from(f.to_string()))
                .collect();
            kvs.push(KeyValue::new(
                "flow.tcp.flags.tags",
                Value::Array(flag_values.into()),
            ));
        }
        if let Some(value) = self.attributes.flow_reverse_tcp_flags_bits {
            kvs.push(KeyValue::new("flow.reverse.tcp.flags.bits", value as i64));
        }
        if let Some(ref value) = self.attributes.flow_reverse_tcp_flags_tags {
            let flag_values: Vec<StringValue> = value
                .iter()
                .map(|f| StringValue::from(f.to_string()))
                .collect();
            kvs.push(KeyValue::new(
                "flow.reverse.tcp.flags.tags",
                Value::Array(flag_values.into()),
            ));
        }
        if let Some(ref value) = self.attributes.client_address {
            kvs.push(KeyValue::new("client.address", value.to_owned()));
        }
        if let Some(value) = self.attributes.client_port {
            kvs.push(KeyValue::new("client.port", value as i64));
        }
        if let Some(ref value) = self.attributes.server_address {
            kvs.push(KeyValue::new("server.address", value.to_owned()));
        }
        if let Some(value) = self.attributes.server_port {
            kvs.push(KeyValue::new("server.port", value as i64));
        }
        if let Some(value) = self.attributes.flow_ipsec_ah_spi {
            kvs.push(KeyValue::new("flow.ipsec.ah.spi", value as i64));
        }
        if let Some(value) = self.attributes.flow_ipsec_esp_spi {
            kvs.push(KeyValue::new("flow.ipsec.esp.spi", value as i64));
        }
        if let Some(value) = self.attributes.flow_ipsec_sender_index {
            kvs.push(KeyValue::new("flow.ipsec.sender.index", value as i64));
        }
        if let Some(value) = self.attributes.flow_ipsec_receiver_index {
            kvs.push(KeyValue::new("flow.ipsec.receiver.index", value as i64));
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
        if let Some(ref value) = self.attributes.ipip_network_type {
            kvs.push(KeyValue::new("ipip.network.type", value.as_str()));
        }
        if let Some(ref value) = self.attributes.ipip_network_transport {
            kvs.push(KeyValue::new("ipip.network.transport", value.to_string()));
        }
        if let Some(ref value) = self.attributes.ipip_source_address {
            kvs.push(KeyValue::new("ipip.source.address", value.to_string()));
        }
        if let Some(ref value) = self.attributes.ipip_destination_address {
            kvs.push(KeyValue::new("ipip.destination.address", value.to_string()));
        }
        if let Some(ref value) = self.attributes.tunnel_type {
            kvs.push(KeyValue::new("tunnel.type", value.as_str()));
        }
        if let Some(ref value) = self.attributes.tunnel_network_interface_mac {
            kvs.push(KeyValue::new(
                "tunnel.network.interface.mac",
                value.to_string(),
            ));
        }
        if let Some(value) = self.attributes.tunnel_network_type {
            kvs.push(KeyValue::new(
                "tunnel.network.type",
                value.as_str().to_string(),
            ));
        }
        if let Some(value) = self.attributes.tunnel_network_transport {
            kvs.push(KeyValue::new("tunnel.network.transport", value.to_string()));
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
        if let Some(value) = self.attributes.tunnel_id {
            kvs.push(KeyValue::new("tunnel.id", value as i64));
        }
        if let Some(value) = self.attributes.tunnel_ipsec_ah_spi {
            kvs.push(KeyValue::new("tunnel.ipsec.ah.spi", value as i64));
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

fn serialize_option_trace_id<S>(
    trace_id: &Option<opentelemetry::trace::TraceId>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match trace_id {
        Some(id) => serializer.serialize_str(&id.to_string()),
        None => serializer.serialize_none(),
    }
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
    S: Serializer,
{
    match reason {
        Some(r) => serializer.serialize_str(r.as_str()),
        None => serializer.serialize_none(),
    }
}

fn serialize_option_tunnel_type<S>(
    tunnel_type: &Option<TunnelType>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match tunnel_type {
        Some(t) => serializer.serialize_str(t.as_str()),
        None => serializer.serialize_none(),
    }
}

fn serialize_option_tcp_flags<S>(
    flags: &Option<Vec<TcpFlag>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match flags {
        Some(flag_vec) => {
            let flag_strings: Vec<&str> = flag_vec.iter().map(|f| f.as_str()).collect();
            serializer.collect_seq(flag_strings)
        }
        None => serializer.serialize_none(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn test_flow_end_reason_as_str() {
        assert_eq!(FlowEndReason::IdleTimeout.as_str(), "idle timeout");
        assert_eq!(FlowEndReason::ActiveTimeout.as_str(), "active timeout");
        assert_eq!(
            FlowEndReason::EndOfFlowDetected.as_str(),
            "end of Flow detected"
        );
        assert_eq!(FlowEndReason::ForcedEnd.as_str(), "forced end");
        assert_eq!(FlowEndReason::LackOfResources.as_str(), "lack of resources");
    }

    #[test]
    fn test_flow_end_reason_to_u8() {
        assert_eq!(FlowEndReason::IdleTimeout.to_u8(), 0x01);
        assert_eq!(FlowEndReason::ActiveTimeout.to_u8(), 0x02);
        assert_eq!(FlowEndReason::EndOfFlowDetected.to_u8(), 0x03);
        assert_eq!(FlowEndReason::ForcedEnd.to_u8(), 0x04);
        assert_eq!(FlowEndReason::LackOfResources.to_u8(), 0x05);
    }

    #[test]
    fn test_flow_end_reason_from_u8_valid() {
        assert_eq!(
            FlowEndReason::from_u8(0x01),
            Some(FlowEndReason::IdleTimeout)
        );
        assert_eq!(
            FlowEndReason::from_u8(0x02),
            Some(FlowEndReason::ActiveTimeout)
        );
        assert_eq!(
            FlowEndReason::from_u8(0x03),
            Some(FlowEndReason::EndOfFlowDetected)
        );
        assert_eq!(FlowEndReason::from_u8(0x04), Some(FlowEndReason::ForcedEnd));
        assert_eq!(
            FlowEndReason::from_u8(0x05),
            Some(FlowEndReason::LackOfResources)
        );
    }

    #[test]
    fn test_flow_end_reason_from_u8_invalid() {
        assert_eq!(FlowEndReason::from_u8(0x06), None);
        assert_eq!(FlowEndReason::from_u8(0xFF), None);
    }

    #[test]
    fn test_flow_end_reason_roundtrip() {
        let reasons = vec![
            FlowEndReason::IdleTimeout,
            FlowEndReason::ActiveTimeout,
            FlowEndReason::EndOfFlowDetected,
            FlowEndReason::ForcedEnd,
            FlowEndReason::LackOfResources,
        ];

        for reason in reasons {
            let byte = reason.to_u8();
            let recovered = FlowEndReason::from_u8(byte);
            assert_eq!(recovered, Some(reason));
        }
    }

    #[test]
    fn test_traceable_start_time() {
        let flow_span = FlowSpan {
            start_time: std::time::UNIX_EPOCH + Duration::from_secs(100),
            end_time: std::time::UNIX_EPOCH + Duration::from_secs(200),
            span_kind: SpanKind::Internal,
            attributes: SpanAttributes::default(),
            flow_key: None,
            last_recorded_packets: 0,
            last_recorded_bytes: 0,
            last_recorded_reverse_packets: 0,
            last_recorded_reverse_bytes: 0,
            boot_time_offset: 0,
            trace_id: None,
            last_recorded_time: std::time::UNIX_EPOCH,
            last_activity_time: std::time::UNIX_EPOCH,
            timeout_duration: Duration::from_secs(0),
        };

        assert_eq!(
            flow_span.start_time(),
            std::time::UNIX_EPOCH + Duration::from_secs(100)
        );
    }

    #[test]
    fn test_traceable_end_time() {
        let flow_span = FlowSpan {
            start_time: std::time::UNIX_EPOCH + Duration::from_secs(100),
            end_time: std::time::UNIX_EPOCH + Duration::from_secs(200),
            span_kind: SpanKind::Internal,
            attributes: SpanAttributes::default(),
            flow_key: None,
            last_recorded_packets: 0,
            last_recorded_bytes: 0,
            last_recorded_reverse_packets: 0,
            last_recorded_reverse_bytes: 0,
            boot_time_offset: 0,
            trace_id: None,
            last_recorded_time: std::time::UNIX_EPOCH,
            last_activity_time: std::time::UNIX_EPOCH,
            timeout_duration: Duration::from_secs(0),
        };

        assert_eq!(
            flow_span.end_time(),
            std::time::UNIX_EPOCH + Duration::from_secs(200)
        );
    }

    #[test]
    fn test_traceable_name_ipv4_tcp() {
        let mut flow_span = FlowSpan {
            start_time: std::time::UNIX_EPOCH,
            end_time: std::time::UNIX_EPOCH,
            span_kind: SpanKind::Internal,
            attributes: SpanAttributes::default(),
            flow_key: None,
            last_recorded_packets: 0,
            last_recorded_bytes: 0,
            last_recorded_reverse_packets: 0,
            last_recorded_reverse_bytes: 0,
            boot_time_offset: 0,
            trace_id: None,
            last_recorded_time: std::time::UNIX_EPOCH,
            last_activity_time: std::time::UNIX_EPOCH,
            timeout_duration: Duration::from_secs(0),
        };
        flow_span.attributes.network_type = EtherType::Ipv4;
        flow_span.attributes.network_transport = IpProto::Tcp;

        let name = flow_span.name();
        assert_eq!(name, Some("flow_ipv4_tcp".to_string()));
    }

    #[test]
    fn test_traceable_name_ipv6_udp() {
        let mut flow_span = FlowSpan {
            start_time: std::time::UNIX_EPOCH,
            end_time: std::time::UNIX_EPOCH,
            span_kind: SpanKind::Internal,
            attributes: SpanAttributes::default(),
            flow_key: None,
            last_recorded_packets: 0,
            last_recorded_bytes: 0,
            last_recorded_reverse_packets: 0,
            last_recorded_reverse_bytes: 0,
            boot_time_offset: 0,
            trace_id: None,
            last_recorded_time: std::time::UNIX_EPOCH,
            last_activity_time: std::time::UNIX_EPOCH,
            timeout_duration: Duration::from_secs(0),
        };
        flow_span.attributes.network_type = EtherType::Ipv6;
        flow_span.attributes.network_transport = IpProto::Udp;

        let name = flow_span.name();
        assert_eq!(name, Some("flow_ipv6_udp".to_string()));
    }

    #[test]
    fn test_span_attributes_default() {
        let attrs = SpanAttributes::default();

        assert_eq!(attrs.flow_community_id, String::new());
        assert_eq!(attrs.flow_connection_state, None);
        assert_eq!(attrs.flow_end_reason, None);
        assert_eq!(attrs.source_port, 0);
        assert_eq!(attrs.destination_port, 0);
        assert_eq!(attrs.flow_bytes_delta, 0);
        assert_eq!(attrs.flow_bytes_total, 0);
        assert_eq!(attrs.flow_packets_delta, 0);
        assert_eq!(attrs.flow_packets_total, 0);
        assert_eq!(attrs.tunnel_type, None);
        assert_eq!(attrs.network_interface_index, None);
        assert_eq!(attrs.network_interface_name, None);
    }

    #[test]
    fn test_serialize_flow_end_reason_some() {
        use serde_json;

        #[derive(Serialize)]
        struct TestStruct {
            #[serde(serialize_with = "serialize_flow_end_reason")]
            reason: Option<FlowEndReason>,
        }

        let test = TestStruct {
            reason: Some(FlowEndReason::IdleTimeout),
        };

        let json = serde_json::to_string(&test).unwrap();
        assert!(json.contains("idle timeout"));
    }

    #[test]
    fn test_serialize_flow_end_reason_none() {
        use serde_json;

        #[derive(Serialize)]
        struct TestStruct {
            #[serde(serialize_with = "serialize_flow_end_reason")]
            reason: Option<FlowEndReason>,
        }

        let test = TestStruct { reason: None };

        let json = serde_json::to_string(&test).unwrap();
        assert!(json.contains("null"));
    }

    #[test]
    fn test_serialize_span_kind_internal() {
        use serde_json;

        #[derive(Serialize)]
        struct TestStruct {
            #[serde(serialize_with = "serialize_span_kind")]
            kind: SpanKind,
        }

        let test = TestStruct {
            kind: SpanKind::Internal,
        };

        let json = serde_json::to_string(&test).unwrap();
        assert!(json.contains("INTERNAL"));
    }

    #[test]
    fn test_serialize_span_kind_all_variants() {
        use serde_json;

        #[derive(Serialize)]
        struct TestStruct {
            #[serde(serialize_with = "serialize_span_kind")]
            kind: SpanKind,
        }

        let test_client = TestStruct {
            kind: SpanKind::Client,
        };
        assert!(
            serde_json::to_string(&test_client)
                .unwrap()
                .contains("CLIENT")
        );

        let test_server = TestStruct {
            kind: SpanKind::Server,
        };
        assert!(
            serde_json::to_string(&test_server)
                .unwrap()
                .contains("SERVER")
        );

        let test_producer = TestStruct {
            kind: SpanKind::Producer,
        };
        assert!(
            serde_json::to_string(&test_producer)
                .unwrap()
                .contains("PRODUCER")
        );

        let test_consumer = TestStruct {
            kind: SpanKind::Consumer,
        };
        assert!(
            serde_json::to_string(&test_consumer)
                .unwrap()
                .contains("CONSUMER")
        );
    }

    #[test]
    fn test_serialize_ip_proto() {
        use serde_json;

        #[derive(Serialize)]
        struct TestStruct {
            #[serde(serialize_with = "serialize_ip_proto")]
            proto: IpProto,
        }

        let test = TestStruct {
            proto: IpProto::Tcp,
        };

        let json = serde_json::to_string(&test).unwrap();
        assert!(json.contains("tcp"));
    }

    #[test]
    fn test_serialize_ether_type() {
        use serde_json;

        #[derive(Serialize)]
        struct TestStruct {
            #[serde(serialize_with = "serialize_ether_type")]
            ether_type: EtherType,
        }

        let test = TestStruct {
            ether_type: EtherType::Ipv4,
        };

        let json = serde_json::to_string(&test).unwrap();
        assert!(json.contains("ipv4"));
    }

    #[test]
    fn test_serialize_option_tunnel_type_some() {
        use serde_json;

        #[derive(Serialize)]
        struct TestStruct {
            #[serde(serialize_with = "serialize_option_tunnel_type")]
            tunnel_type: Option<TunnelType>,
        }

        let test = TestStruct {
            tunnel_type: Some(TunnelType::Vxlan),
        };

        let json = serde_json::to_string(&test).unwrap();
        assert!(json.contains("vxlan"));
    }

    #[test]
    fn test_serialize_option_tunnel_type_none() {
        use serde_json;

        #[derive(Serialize)]
        struct TestStruct {
            #[serde(serialize_with = "serialize_option_tunnel_type")]
            tunnel_type: Option<TunnelType>,
        }

        let test = TestStruct { tunnel_type: None };

        let json = serde_json::to_string(&test).unwrap();
        assert!(json.contains("null"));
    }

    #[test]
    fn test_flow_span_clone() {
        let flow_span = FlowSpan {
            start_time: std::time::UNIX_EPOCH,
            end_time: std::time::UNIX_EPOCH + Duration::from_secs(10),
            span_kind: SpanKind::Internal,
            attributes: SpanAttributes::default(),
            flow_key: None,
            last_recorded_packets: 0,
            last_recorded_bytes: 0,
            last_recorded_reverse_packets: 0,
            last_recorded_reverse_bytes: 0,
            boot_time_offset: 0,
            trace_id: None,
            last_recorded_time: std::time::UNIX_EPOCH,
            last_activity_time: std::time::UNIX_EPOCH,
            timeout_duration: Duration::from_secs(0),
        };

        let cloned = flow_span.clone();
        assert_eq!(flow_span.start_time, cloned.start_time);
        assert_eq!(flow_span.end_time, cloned.end_time);
    }

    #[test]
    fn test_span_attributes_with_k8s_metadata() {
        let mut attrs = SpanAttributes::default();
        attrs.source_k8s_pod_name = Some("test-pod".to_string());
        attrs.source_k8s_namespace_name = Some("test-namespace".to_string());
        attrs.destination_k8s_service_name = Some("test-service".to_string());

        assert_eq!(attrs.source_k8s_pod_name, Some("test-pod".to_string()));
        assert_eq!(
            attrs.source_k8s_namespace_name,
            Some("test-namespace".to_string())
        );
        assert_eq!(
            attrs.destination_k8s_service_name,
            Some("test-service".to_string())
        );
    }

    #[test]
    fn test_flow_span_serialization() {
        use serde_json;

        let flow_span = FlowSpan {
            start_time: std::time::UNIX_EPOCH,
            end_time: std::time::UNIX_EPOCH + Duration::from_secs(10),
            span_kind: SpanKind::Internal,
            attributes: SpanAttributes::default(),
            flow_key: None,
            last_recorded_packets: 0,
            last_recorded_bytes: 0,
            last_recorded_reverse_packets: 0,
            last_recorded_reverse_bytes: 0,
            boot_time_offset: 0,
            trace_id: None,
            last_recorded_time: std::time::UNIX_EPOCH,
            last_activity_time: std::time::UNIX_EPOCH,
            timeout_duration: Duration::from_secs(0),
        };

        let json = serde_json::to_string(&flow_span);
        assert!(json.is_ok());
    }

    #[test]
    fn test_connection_state_serialization() {
        use serde_json;

        #[derive(Serialize)]
        struct TestStruct {
            #[serde(serialize_with = "serialize_connection_state")]
            state: Option<ConnectionState>,
        }

        let test = TestStruct {
            state: Some(ConnectionState::Established),
        };

        let json = serde_json::to_string(&test).unwrap();
        assert!(json.contains("established"));
    }

    #[test]
    fn test_serialize_option_mac_addr() {
        use pnet::datalink::MacAddr;
        use serde_json;

        #[derive(Serialize)]
        struct TestStruct {
            #[serde(serialize_with = "serialize_option_mac_addr")]
            mac: Option<MacAddr>,
        }

        let test = TestStruct {
            mac: Some(MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff)),
        };

        let json = serde_json::to_string(&test).unwrap();
        assert!(json.contains("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn test_flow_end_reason_all_values() {
        // Ensure all enum variants are covered
        let all_reasons = vec![
            FlowEndReason::IdleTimeout,
            FlowEndReason::ActiveTimeout,
            FlowEndReason::EndOfFlowDetected,
            FlowEndReason::ForcedEnd,
            FlowEndReason::LackOfResources,
        ];

        for reason in all_reasons {
            let str_repr = reason.as_str();
            let byte_repr = reason.to_u8();
            let recovered = FlowEndReason::from_u8(byte_repr);

            assert!(str_repr.len() > 0);
            assert_eq!(recovered, Some(reason));
        }
    }

    #[tokio::test]
    async fn test_traceable_export_trace_id_none() {
        use std::sync::{Arc, Mutex};

        use futures::future::BoxFuture;
        use opentelemetry::trace::TraceId;
        use opentelemetry_sdk::trace::{
            SdkTracerProvider, SimpleSpanProcessor, SpanData, SpanExporter,
        };

        use crate::otlp::trace::{TraceExporterAdapter, TraceableExporter};

        #[derive(Debug, Clone)]
        struct MockExporter {
            spans: Arc<Mutex<Vec<SpanData>>>,
        }

        impl SpanExporter for MockExporter {
            #[allow(refining_impl_trait)]
            fn export(
                &self,
                batch: Vec<SpanData>,
            ) -> BoxFuture<'static, opentelemetry_sdk::error::OTelSdkResult> {
                let spans = self.spans.clone();
                Box::pin(async move {
                    spans.lock().unwrap().extend(batch);
                    Ok(())
                })
            }
        }

        let captured_spans = Arc::new(Mutex::new(Vec::new()));
        let exporter = MockExporter {
            spans: captured_spans.clone(),
        };
        let processor = SimpleSpanProcessor::new(exporter);
        let provider = SdkTracerProvider::builder()
            .with_span_processor(processor)
            .build();
        let adapter = TraceExporterAdapter::new(provider);

        let flow_span = FlowSpan {
            start_time: std::time::UNIX_EPOCH,
            end_time: std::time::UNIX_EPOCH + Duration::from_secs(10),
            span_kind: SpanKind::Internal,
            attributes: SpanAttributes::default(),
            flow_key: None,
            last_recorded_packets: 0,
            last_recorded_bytes: 0,
            last_recorded_reverse_packets: 0,
            last_recorded_reverse_bytes: 0,
            boot_time_offset: 0,
            trace_id: None,
            last_recorded_time: std::time::UNIX_EPOCH,
            last_activity_time: std::time::UNIX_EPOCH,
            timeout_duration: Duration::from_secs(0),
        };

        adapter.export(Arc::new(flow_span)).await;

        // Force flush/shutdown to ensure spans are processed (though SimpleSpanProcessor handles it synchronously usually, but adapter is async)
        // The adapter just calls start/end on span.
        // SimpleSpanProcessor processes on end.

        let spans = captured_spans.lock().unwrap();
        assert_eq!(spans.len(), 1);
        assert_ne!(spans[0].span_context.trace_id(), TraceId::INVALID);
    }

    #[tokio::test]
    async fn test_traceable_export_trace_id_some() {
        use std::sync::{Arc, Mutex};

        use futures::future::BoxFuture;
        use opentelemetry::trace::TraceId;
        use opentelemetry_sdk::trace::{
            SdkTracerProvider, SimpleSpanProcessor, SpanData, SpanExporter,
        };

        use crate::otlp::trace::{TraceExporterAdapter, TraceableExporter};

        #[derive(Debug, Clone)]
        struct MockExporter {
            spans: Arc<Mutex<Vec<SpanData>>>,
        }

        impl SpanExporter for MockExporter {
            #[allow(refining_impl_trait)]
            fn export(
                &self,
                batch: Vec<SpanData>,
            ) -> BoxFuture<'static, opentelemetry_sdk::error::OTelSdkResult> {
                let spans = self.spans.clone();
                Box::pin(async move {
                    spans.lock().unwrap().extend(batch);
                    Ok(())
                })
            }
        }

        let captured_spans = Arc::new(Mutex::new(Vec::new()));
        let exporter = MockExporter {
            spans: captured_spans.clone(),
        };
        let processor = SimpleSpanProcessor::new(exporter);
        let provider = SdkTracerProvider::builder()
            .with_span_processor(processor)
            .build();
        let adapter = TraceExporterAdapter::new(provider);

        let test_trace_id = TraceId::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]);

        let flow_span = FlowSpan {
            start_time: std::time::UNIX_EPOCH,
            end_time: std::time::UNIX_EPOCH + Duration::from_secs(10),
            span_kind: SpanKind::Internal,
            attributes: SpanAttributes::default(),
            flow_key: None,
            last_recorded_packets: 0,
            last_recorded_bytes: 0,
            last_recorded_reverse_packets: 0,
            last_recorded_reverse_bytes: 0,
            boot_time_offset: 0,
            trace_id: Some(test_trace_id),
            last_recorded_time: std::time::UNIX_EPOCH,
            last_activity_time: std::time::UNIX_EPOCH,
            timeout_duration: Duration::from_secs(0),
        };

        adapter.export(Arc::new(flow_span)).await;

        let spans = captured_spans.lock().unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].span_context.trace_id(), test_trace_id);
    }
}
