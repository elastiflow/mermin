use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use anyhow::Result;
use k8s_openapi::api::{core::v1::Pod, networking::v1::NetworkPolicySpec};
use mermin_common::{IpAddrType, PacketMeta};
use network_types::ip::IpProto;

use crate::k8s::{Attributor, EnrichedInfo, FlowContext, FlowDirection, K8sObjectMeta};

#[derive(Debug)]
#[allow(dead_code)]
pub struct NetworkPolicy {
    pub policy: K8sObjectMeta,
    pub spec: NetworkPolicySpec,
}

#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct EnrichedFlowData {
    pub id: String,
    pub source: Option<EnrichedInfo>,
    pub destination: Option<EnrichedInfo>,
    pub network_policies: Option<Vec<NetworkPolicy>>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct FlowSide {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: IpProto,
}

impl FlowSide {
    /// Creates a FlowSide from packet metadata for the source.
    fn from_packet_source(packet: &PacketMeta) -> Self {
        Self {
            ip: Self::extract_ip_addr(packet, true),
            port: u16::from_be_bytes(packet.src_port),
            protocol: packet.proto,
        }
    }

    /// Creates a FlowSide from packet metadata for the destination.
    fn from_packet_destination(packet: &PacketMeta) -> Self {
        Self {
            ip: Self::extract_ip_addr(packet, false),
            port: u16::from_be_bytes(packet.dst_port),
            protocol: packet.proto,
        }
    }

    /// Extracts IP address from packet metadata.
    fn extract_ip_addr(packet: &PacketMeta, is_source: bool) -> IpAddr {
        match packet.ip_addr_type {
            IpAddrType::Ipv4 => {
                let addr = if is_source {
                    packet.src_ipv4_addr
                } else {
                    packet.dst_ipv4_addr
                };
                IpAddr::V4(Ipv4Addr::from(addr))
            }
            IpAddrType::Ipv6 => {
                let addr = if is_source {
                    packet.src_ipv6_addr
                } else {
                    packet.dst_ipv6_addr
                };
                IpAddr::V6(Ipv6Addr::from(addr))
            }
        }
    }
}

/// Packet enrichment processor that handles the conversion of raw packet data
/// into enriched flow information with Kubernetes metadata.
pub struct PacketEnricher<'a> {
    attributor: &'a Attributor,
}

impl<'a> PacketEnricher<'a> {
    pub fn new(attributor: &'a Attributor) -> Self {
        Self { attributor }
    }

    /// Main function to parse a packet and enrich it with Kubernetes metadata.
    pub async fn parse_packet(
        &self,
        packet: &PacketMeta,
        community_id: String,
    ) -> Result<EnrichedFlowData> {
        let flow_sides = self.extract_flow_sides(packet);
        let pod_objects = self.resolve_pods(&flow_sides).await;
        let (source, destination, applicable_policies) = self
            .build_enrichment_data(&flow_sides, &pod_objects)
            .await?;

        Ok(EnrichedFlowData {
            id: community_id,
            source,
            destination,
            network_policies: applicable_policies,
        })
    }

    /// Extracts source and destination flow sides from packet metadata.
    fn extract_flow_sides(&self, packet: &PacketMeta) -> FlowSides {
        FlowSides {
            source: FlowSide::from_packet_source(packet),
            destination: FlowSide::from_packet_destination(packet),
        }
    }

    /// Resolves both source and destination IPs to Pod objects if possible.
    async fn resolve_pods(&self, flow_sides: &FlowSides) -> PodResolution {
        let source_pod = self.attributor.get_pod_by_ip(flow_sides.source.ip).await;
        let dest_pod = self
            .attributor
            .get_pod_by_ip(flow_sides.destination.ip)
            .await;

        PodResolution {
            source_pod,
            dest_pod,
        }
    }

    /// Builds the complete enrichment data including policies and fallback enrichment.
    async fn build_enrichment_data(
        &self,
        flow_sides: &FlowSides,
        pod_objects: &PodResolution,
    ) -> Result<(
        Option<EnrichedInfo>,
        Option<EnrichedInfo>,
        Option<Vec<NetworkPolicy>>,
    )> {
        let applicable_policies = self.evaluate_network_policies(flow_sides, pod_objects)?;
        let source_info = self
            .enrich_single_side(&flow_sides.source, &pod_objects.source_pod)
            .await;
        let destination_info = self
            .enrich_single_side(&flow_sides.destination, &pod_objects.dest_pod)
            .await;

        Ok((source_info, destination_info, applicable_policies))
    }

    /// Evaluates network policies for both ingress and egress directions of a flow.
    fn evaluate_network_policies(
        &self,
        flow_sides: &FlowSides,
        pod_objects: &PodResolution,
    ) -> Result<Option<Vec<NetworkPolicy>>> {
        let mut all_matching_policies = Vec::new();

        // Evaluate ingress rules if a destination pod exists.
        if let Some(dest_pod) = &pod_objects.dest_pod {
            let ingress_policies = self.get_policies_for_direction(
                dest_pod,
                FlowDirection::Ingress,
                flow_sides,
                pod_objects,
            )?;
            all_matching_policies.extend(ingress_policies);
        }

        // Evaluate egress rules if a source pod exists.
        if let Some(source_pod) = &pod_objects.source_pod {
            let egress_policies = self.get_policies_for_direction(
                source_pod,
                FlowDirection::Egress,
                flow_sides,
                pod_objects,
            )?;
            all_matching_policies.extend(egress_policies);
        }

        if all_matching_policies.is_empty() {
            Ok(None)
        } else {
            let mut seen = std::collections::HashSet::new();
            all_matching_policies.retain(|policy| {
                seen.insert((policy.policy.name.clone(), policy.policy.namespace.clone()))
            });
            Ok(Some(all_matching_policies))
        }
    }

    /// Helper to evaluate policies for a single direction (Ingress or Egress).
    fn get_policies_for_direction(
        &self,
        policy_pod: &Pod, // The pod to which the policies apply (source for egress, dest for ingress)
        direction: FlowDirection,
        flow_sides: &FlowSides,
        pod_objects: &PodResolution,
    ) -> Result<Vec<NetworkPolicy>> {
        let namespace = policy_pod
            .metadata
            .namespace
            .as_deref()
            .unwrap_or("default");

        let context = FlowContext::new(pod_objects, flow_sides, namespace, direction);

        let matching_policies = self
            .attributor
            .get_matching_network_policies(policy_pod, &context)?;

        Ok(matching_policies
            .iter()
            .map(|p| NetworkPolicy {
                policy: K8sObjectMeta::from(p.as_ref()),
                spec: p.spec.clone().unwrap_or_default(),
            })
            .collect())
    }

    /// Enriches a single side of the flow, prioritizing Pod information over fallback enrichment.
    async fn enrich_single_side(
        &self,
        side: &FlowSide,
        pod: &Option<Arc<Pod>>,
    ) -> Option<EnrichedInfo> {
        if let Some(pod) = pod.as_ref() {
            Some(self.enrich_pod_info(pod))
        } else {
            self.enrich_side_fallback(side).await
        }
    }

    /// Creates EnrichedInfo for a Pod.
    fn enrich_pod_info(&self, pod: &Pod) -> EnrichedInfo {
        let pod_meta = K8sObjectMeta::from(pod);
        let owner = self.attributor.get_top_level_controller(pod);
        EnrichedInfo::Pod {
            pod: pod_meta,
            owner,
        }
    }

    /// Enriches a single side of a flow based on its IP address.
    /// This is used as a fallback if the IP does not resolve to a Pod.
    async fn enrich_side_fallback(&self, side: &FlowSide) -> Option<EnrichedInfo> {
        // Try to match against a Node
        if let Some(node) = self.attributor.get_node_by_ip(side.ip).await {
            return Some(EnrichedInfo::Node {
                node: K8sObjectMeta::from(node.as_ref()),
            });
        }

        // Try to match against a Service
        if let Some(service) = self
            .attributor
            .get_service_by_flow_details(side.ip, side.port, side.protocol)
            .await
        {
            let service_meta = K8sObjectMeta::from(service.as_ref());
            let backend_ips = self
                .attributor
                .resolve_service_ip_to_backend_ips(side.ip)
                .await
                .unwrap_or_default();

            return Some(EnrichedInfo::Service {
                service: service_meta,
                backend_ips,
            });
        }

        // Try to match against an EndpointSlice
        if let Some(slice) = self.attributor.get_endpointslice_by_ip(side.ip).await {
            return Some(EnrichedInfo::EndpointSlice {
                slice: K8sObjectMeta::from(slice.as_ref()),
            });
        }

        None
    }
}

#[derive(Debug)]
pub struct FlowSides {
    pub src: FlowSide,
    pub dst: FlowSide,
}

#[derive(Debug)]
pub struct PodResolution {
    pub src_pod: Option<Arc<Pod>>,
    pub dst_pod: Option<Arc<Pod>>,
}

pub async fn parse_packet(
    packet: &PacketMeta,
    attributor: &Attributor,
    community_id: String,
) -> Result<EnrichedFlowData> {
    let enricher = PacketEnricher::new(attributor);
    enricher.parse_packet(packet, community_id).await
}
