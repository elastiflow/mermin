use std::net::IpAddr;

use anyhow::Result;
use k8s_openapi::api::{core::v1::Pod, networking::v1::NetworkPolicySpec};
use mermin_common::PacketMeta;

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
        // Create FlowContext directly for both directions
        let namespace = "default"; // TODO: This should be configurable or derived from context
        let ingress_context =
            FlowContext::from_packet(packet, self.attributor, namespace, FlowDirection::Ingress)
                .await;
        let egress_context =
            FlowContext::from_packet(packet, self.attributor, namespace, FlowDirection::Egress)
                .await;

        // Use contexts directly for enrichment and policy evaluation
        let source = self
            .enrich_from_context(&ingress_context.src_pod, ingress_context.src_ip)
            .await;
        let destination = self
            .enrich_from_context(&egress_context.dst_pod, egress_context.dst_ip)
            .await;
        let policies = self
            .evaluate_policies_from_context(&ingress_context, &egress_context)
            .await?;

        Ok(EnrichedFlowData {
            id: community_id,
            source,
            destination,
            network_policies: policies,
        })
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

    /// Enriches flow information from FlowContext, eliminating intermediary structures
    async fn enrich_from_context(&self, pod: &Option<&Pod>, ip: IpAddr) -> Option<EnrichedInfo> {
        if let Some(pod) = pod {
            Some(self.enrich_pod_info(pod))
        } else {
            self.enrich_ip_fallback(ip).await
        }
    }

    /// Evaluates network policies from FlowContext directly
    async fn evaluate_policies_from_context(
        &self,
        ingress_context: &FlowContext<'_>,
        egress_context: &FlowContext<'_>,
    ) -> Result<Option<Vec<NetworkPolicy>>> {
        let mut all_matching_policies = Vec::new();

        // Evaluate ingress rules if a destination pod exists
        if let Some(dst_pod) = ingress_context.dst_pod {
            let ingress_policies = self.get_policies_for_context(dst_pod, ingress_context)?;
            all_matching_policies.extend(ingress_policies);
        }

        // Evaluate egress rules if a source pod exists
        if let Some(src_pod) = egress_context.src_pod {
            let egress_policies = self.get_policies_for_context(src_pod, egress_context)?;
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

    fn get_policies_for_context(
        &self,
        policy_pod: &Pod,
        flow_context: &FlowContext<'_>,
    ) -> Result<Vec<NetworkPolicy>> {
        let matching_policies = self
            .attributor
            .get_matching_network_policies(policy_pod, flow_context)?;

        Ok(matching_policies
            .iter()
            .map(|p| NetworkPolicy {
                policy: K8sObjectMeta::from(p.as_ref()),
                spec: p.spec.clone().unwrap_or_default(),
            })
            .collect())
    }

    /// Enriches IP address with fallback information (Node, Service, EndpointSlice)
    async fn enrich_ip_fallback(&self, ip: IpAddr) -> Option<EnrichedInfo> {
        // Try to match against a Node
        if let Some(node) = self.attributor.get_node_by_ip(ip).await {
            return Some(EnrichedInfo::Node {
                node: K8sObjectMeta::from(node.as_ref()),
            });
        }

        // Try to match against a Service
        if let Some(service) = self.attributor.get_service_by_ip(ip).await {
            let service_meta = K8sObjectMeta::from(service.as_ref());
            let backend_ips = self
                .attributor
                .resolve_service_ip_to_backend_ips(ip)
                .await
                .unwrap_or_default();

            return Some(EnrichedInfo::Service {
                service: service_meta,
                backend_ips,
            });
        }

        // Try to match against an EndpointSlice
        if let Some(slice) = self.attributor.get_endpointslice_by_ip(ip).await {
            return Some(EnrichedInfo::EndpointSlice {
                slice: K8sObjectMeta::from(slice.as_ref()),
            });
        }

        None
    }
}

pub async fn parse_packet(
    packet: &PacketMeta,
    attributor: &Attributor,
    community_id: String,
) -> Result<EnrichedFlowData> {
    let enricher = PacketEnricher::new(attributor);
    enricher.parse_packet(packet, community_id).await
}
