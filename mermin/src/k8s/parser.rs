use std::net::IpAddr;

use k8s_openapi::api::{core::v1::Pod, networking::v1::NetworkPolicySpec};
use tracing::debug;

use super::K8sError;
use crate::{
    k8s::decorator::{
        DecorationInfo, Decorator, FlowContext, FlowDirection, K8sObjectMeta, WorkloadOwner,
    },
    span::flow::FlowSpan,
};

#[derive(Debug)]
pub struct NetworkPolicy {
    pub policy: K8sObjectMeta,
    #[allow(dead_code)] // TODO: Use for network policy enforcement
    pub spec: NetworkPolicySpec,
}

/// Kubernetes decoration processor that correlates a FlowSpan with Kubernetes metadata
/// to produce enriched flow attributes containing resource information.
struct SpanDecorator<'a> {
    decorator: &'a Decorator,
}

impl<'a> SpanDecorator<'a> {
    fn new(decorator: &'a Decorator) -> Self {
        Self { decorator }
    }

    /// Correlates flow attributes with Kubernetes resources and populates K8s metadata fields.
    /// Returns a cloned FlowSpan with source and destination Kubernetes attributes populated.
    async fn decorate(&self, flow_span: &FlowSpan) -> Result<FlowSpan, K8sError> {
        // Create FlowContext directly for both directions
        let ctx = FlowContext::from_flow_span(flow_span, self.decorator).await;

        // Resolve source and destination IPs to Kubernetes resources and evaluate policies
        let src_decoration: Option<DecorationInfo> = self.enrich(&ctx.src_pod, ctx.src_ip).await;
        let dst_decoration = self.enrich(&ctx.dst_pod, ctx.dst_ip).await;
        let (ingress_policies, egress_policies) = self.evaluate_flow_policies(&ctx).await?;

        // Clone the original flow attributes and populate with Kubernetes metadata
        let mut decorated_flow = flow_span.clone();

        // Populate source Kubernetes attributes
        if let Some(src_info) = &src_decoration {
            self.populate_k8s_attributes(&mut decorated_flow, src_info, true);
        }

        // Populate destination Kubernetes attributes
        if let Some(dst_info) = &dst_decoration {
            self.populate_k8s_attributes(&mut decorated_flow, dst_info, false);
        }

        // Populate network policy information
        self.populate_network_policies(&mut decorated_flow, &ingress_policies, &egress_policies);

        Ok(decorated_flow)
    }

    /// Resolves a pod and IP address to Kubernetes resource decoration information.
    /// Returns Pod decoration if available, otherwise attempts IP-based fallback resolution.
    async fn enrich(&self, pod: &Option<Pod>, ip: IpAddr) -> Option<DecorationInfo> {
        if let Some(pod) = pod {
            let pod_meta = K8sObjectMeta::from(pod);
            let owner = self.decorator.get_top_level_controller(pod);
            Some(DecorationInfo::Pod {
                pod: pod_meta,
                owner,
            })
        } else {
            self.enrich_ip_fallback(ip).await
        }
    }

    /// Populates Kubernetes attributes in a FlowSpan based on DecorationInfo.
    /// Maps resource metadata to the appropriate source or destination K8s fields.
    fn populate_k8s_attributes(
        &self,
        flow_span: &mut FlowSpan,
        decoration_info: &DecorationInfo,
        is_source: bool,
    ) {
        match decoration_info {
            DecorationInfo::Pod { pod, owner } => {
                self.set_k8s_attr(flow_span, "pod.name", &pod.name, is_source);
                self.set_k8s_attr_opt(flow_span, "namespace.name", &pod.namespace, is_source);

                // Populate workload controller information if available
                if let Some(workload_owner) = owner {
                    self.populate_workload_attributes(flow_span, workload_owner, is_source);
                }
            }
            DecorationInfo::Node { node } => {
                self.set_k8s_attr(flow_span, "node.name", &node.name, is_source);
            }
            DecorationInfo::Service { service, .. } => {
                self.set_k8s_attr(flow_span, "service.name", &service.name, is_source);
                self.set_k8s_attr_opt(flow_span, "namespace.name", &service.namespace, is_source);
            }
            DecorationInfo::EndpointSlice { slice } => {
                // EndpointSlice provides namespace context for service discovery
                self.set_k8s_attr_opt(flow_span, "namespace.name", &slice.namespace, is_source);
            }
        }
    }

    /// Maps workload controller metadata to the appropriate K8s attributes.
    /// Handles Deployment, ReplicaSet, StatefulSet, DaemonSet, and Job controllers.
    fn populate_workload_attributes(
        &self,
        flow_span: &mut FlowSpan,
        owner: &WorkloadOwner,
        is_source: bool,
    ) {
        match owner {
            WorkloadOwner::Deployment(meta) => {
                self.set_k8s_attr(flow_span, "deployment.name", &meta.name, is_source);
            }
            WorkloadOwner::ReplicaSet(meta) => {
                self.set_k8s_attr(flow_span, "replicaset.name", &meta.name, is_source);
            }
            WorkloadOwner::StatefulSet(meta) => {
                self.set_k8s_attr(flow_span, "statefulset.name", &meta.name, is_source);
            }
            WorkloadOwner::DaemonSet(meta) => {
                self.set_k8s_attr(flow_span, "daemonset.name", &meta.name, is_source);
            }
            WorkloadOwner::Job(meta) => {
                self.set_k8s_attr(flow_span, "job.name", &meta.name, is_source);
            }
        }
    }

    /// Sets a required Kubernetes attribute by wrapping the value in Some().
    fn set_k8s_attr(
        &self,
        flow_span: &mut FlowSpan,
        attr_name: &str,
        value: &str,
        is_source: bool,
    ) {
        self.set_k8s_attr_opt(flow_span, attr_name, &Some(value.to_string()), is_source);
    }

    /// Sets an optional Kubernetes attribute using a compact mapping approach.
    fn set_k8s_attr_opt(
        &self,
        flow_span: &mut FlowSpan,
        attr_name: &str,
        value: &Option<String>,
        is_source: bool,
    ) {
        macro_rules! k8s_attr_mapping {
            ($(($attr:literal, $source_field:ident, $dest_field:ident)),* $(,)?) => {
                match (is_source, attr_name) {
                    $(
                        (true, $attr) => &mut flow_span.attributes.$source_field,
                        (false, $attr) => &mut flow_span.attributes.$dest_field,
                    )*
                    _ => return, // Unknown attribute - silently ignored for forward compatibility
                }
            };
        }

        // Get mutable reference to the appropriate k8s attribute based on direction and type
        let field = k8s_attr_mapping! {
            ("cluster.name", source_k8s_cluster_name, destination_k8s_cluster_name),
            ("namespace.name", source_k8s_namespace_name, destination_k8s_namespace_name),
            ("node.name", source_k8s_node_name, destination_k8s_node_name),
            ("pod.name", source_k8s_pod_name, destination_k8s_pod_name),
            ("container.name", source_k8s_container_name, destination_k8s_container_name),
            ("deployment.name", source_k8s_deployment_name, destination_k8s_deployment_name),
            ("replicaset.name", source_k8s_replicaset_name, destination_k8s_replicaset_name),
            ("statefulset.name", source_k8s_statefulset_name, destination_k8s_statefulset_name),
            ("daemonset.name", source_k8s_daemonset_name, destination_k8s_daemonset_name),
            ("job.name", source_k8s_job_name, destination_k8s_job_name),
            ("cronjob.name", source_k8s_cronjob_name, destination_k8s_cronjob_name),
            ("service.name", source_k8s_service_name, destination_k8s_service_name),
        };

        *field = value.clone();
    }

    /// Populates network policy decoration in a FlowSpan.
    /// Converts policy lists to comma-separated strings for telemetry.
    fn populate_network_policies(
        &self,
        flow_span: &mut FlowSpan,
        ingress_policies: &[NetworkPolicy],
        egress_policies: &[NetworkPolicy],
    ) {
        // Format ingress policies (affecting destination pod)
        if !ingress_policies.is_empty() {
            let policy_names: Vec<String> = ingress_policies
                .iter()
                .map(|p| {
                    if let Some(ns) = &p.policy.namespace {
                        format!("{}/{}", ns, p.policy.name)
                    } else {
                        p.policy.name.clone()
                    }
                })
                .collect();
            flow_span.attributes.network_policies_ingress = Some(policy_names);
        }

        // Format egress policies (affecting source pod)
        if !egress_policies.is_empty() {
            let policy_names: Vec<String> = egress_policies
                .iter()
                .map(|p| {
                    if let Some(ns) = &p.policy.namespace {
                        format!("{}/{}", ns, p.policy.name)
                    } else {
                        p.policy.name.clone()
                    }
                })
                .collect();
            flow_span.attributes.network_policies_egress = Some(policy_names);
        }
    }

    /// Evaluates NetworkPolicies for a flow and separates them by direction.
    /// Returns (ingress_policies, egress_policies) for telemetry decoration.
    async fn evaluate_flow_policies(
        &self,
        ctx: &FlowContext,
    ) -> Result<(Vec<NetworkPolicy>, Vec<NetworkPolicy>), K8sError> {
        let mut ingress_policies = Vec::new();
        let mut egress_policies = Vec::new();

        // Get ingress policies that apply to the destination pod
        if let Some(dst_pod) = &ctx.dst_pod {
            ingress_policies = self.get_policies_for_pod(ctx, dst_pod, FlowDirection::Ingress)?;
        }

        // Get egress policies that apply to the source pod
        if let Some(src_pod) = &ctx.src_pod {
            egress_policies = self.get_policies_for_pod(ctx, src_pod, FlowDirection::Egress)?;
        }

        Ok((ingress_policies, egress_policies))
    }

    /// Retrieves NetworkPolicies that match a specific pod in the given direction.
    /// Converts from the internal policy representation to our NetworkPolicy struct.
    fn get_policies_for_pod(
        &self,
        ctx: &FlowContext,
        policy_pod: &Pod,
        direction: FlowDirection,
    ) -> Result<Vec<NetworkPolicy>, K8sError> {
        let matching_policies = self
            .decorator
            .get_matching_network_policies(ctx, policy_pod, direction)?;

        Ok(matching_policies
            .iter()
            .map(|p| NetworkPolicy {
                policy: K8sObjectMeta::from(p.as_ref()),
                spec: p.spec.clone().unwrap_or_default(),
            })
            .collect())
    }

    /// Attempts to resolve an IP address to Kubernetes resources when no pod is found.
    /// Tries Node, Service, and EndpointSlice lookups in priority order.
    async fn enrich_ip_fallback(&self, ip: IpAddr) -> Option<DecorationInfo> {
        // Try to match against a Node
        if let Some(node) = self.decorator.get_node_by_ip(ip).await {
            return Some(DecorationInfo::Node {
                node: K8sObjectMeta::from(node.as_ref()),
            });
        }

        // Try to match against a Service
        if let Some(service) = self.decorator.get_service_by_ip(ip).await {
            let service_meta = K8sObjectMeta::from(service.as_ref());
            let backend_ips = match self.decorator.resolve_service_ip_to_backend_ips(ip).await {
                Some(ips) => ips,
                None => {
                    debug!(
                        "failed to resolve backend IPs for service {} with IP {}",
                        service_meta.name, ip
                    );
                    Vec::new()
                }
            };

            return Some(DecorationInfo::Service {
                service: service_meta,
                backend_ips,
            });
        }

        // Try to match against an EndpointSlice
        if let Some(slice) = self.decorator.get_endpointslice_by_ip(ip).await {
            return Some(DecorationInfo::EndpointSlice {
                slice: K8sObjectMeta::from(slice.as_ref()),
            });
        }

        // No Kubernetes resource found for this IP
        debug!(
            "IP {} could not be attributed to any Kubernetes resource (pod, node, service, or endpoint)",
            ip
        );
        None
    }
}

/// Public interface for attributing a FlowSpan with Kubernetes metadata.
/// Creates a SpanAttributor and performs the correlation process.
pub async fn decorate_flow_span(
    flow_span: &FlowSpan,
    attributor: &Attributor,
) -> Result<FlowSpan, K8sError> {
    let span_attributor = SpanAttributor::new(attributor);
    span_attributor.attribute(flow_span).await
}
