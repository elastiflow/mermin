use std::{net::IpAddr, sync::Arc};

use async_trait::async_trait;
use dashmap::DashMap;
use fxhash::FxBuildHasher;
use network_types::{eth::EtherType, ip::IpProto};
use serde::Serialize;
use tracing::{Span, info_span};

use crate::otlp::trace::lib::Traceable;

#[derive(Debug, Clone, Serialize)]
pub struct FlowSpan {
    pub community_id: String,

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
}

impl Traceable for FlowSpan {
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
