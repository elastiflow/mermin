use k8s_openapi::api::{core::v1::Pod, networking::v1::NetworkPolicySpec};
use kube_runtime::reflector::ObjectRef;
use tracing::debug;

use crate::{
    k8s::{
        K8sError,
        decorator::{
            DecorationInfo, Decorator, FlowContext, FlowDirection, K8sObjectMeta, WorkloadOwner,
        },
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
        // Clone the original flow attributes and populate with Kubernetes metadata
        let mut decorated_flow = flow_span.clone();

        let associations = self.decorator.associate_flow(&decorated_flow).await;

        let src_pod = self.find_and_get_pod(&associations, "source").await;
        let dst_pod = self.find_and_get_pod(&associations, "destination").await;

        let ctx = FlowContext {
            src_pod: src_pod.as_deref().cloned(),
            src_ip: flow_span.attributes.source_address,
            dst_pod: dst_pod.as_deref().cloned(),
            dst_ip: flow_span.attributes.destination_address,
            port: flow_span.attributes.destination_port,
            protocol: flow_span.attributes.network_transport,
        };

        let (ingress_policies, egress_policies) = self.evaluate_flow_policies(&ctx).await?;

        // Populate source Kubernetes attributes
        if let Some(source_objects) = associations.get("source") {
            for meta in source_objects {
                let decoration_info = self.build_decoration_info_from_meta(meta, &src_pod).await;
                self.populate_k8s_attributes(&mut decorated_flow, &decoration_info, true);
            }
        }

        if let Some(destination_objects) = associations.get("destination") {
            for meta in destination_objects {
                let decoration_info = self.build_decoration_info_from_meta(meta, &dst_pod).await;
                self.populate_k8s_attributes(&mut decorated_flow, &decoration_info, false);
            }
        }

        // Populate network policy information
        self.populate_network_policies(&mut decorated_flow, &ingress_policies, &egress_policies);

        Ok(decorated_flow)
    }

    async fn find_and_get_pod(
        &self,
        associations: &std::collections::HashMap<String, Vec<K8sObjectMeta>>,
        direction: &str,
    ) -> Option<std::sync::Arc<Pod>> {
        if let Some(metas) = associations.get(direction) {
            if let Some(pod_meta) = metas.iter().find(|m| m.kind == "Pod") {
                return self.get_pod_from_meta(pod_meta).await;
            }
        }
        None
    }

    async fn get_pod_from_meta(&self, meta: &K8sObjectMeta) -> Option<std::sync::Arc<Pod>> {
        if meta.kind != "Pod" {
            return None;
        }
        let key = ObjectRef::new(&meta.name).within(meta.namespace.as_deref().unwrap_or_default());
        self.decorator.resource_store.pods.get(&key)
    }

    async fn build_decoration_info_from_meta(
        &self,
        meta: &K8sObjectMeta,
        pod_obj: &Option<std::sync::Arc<Pod>>,
    ) -> DecorationInfo {
        match meta.kind.as_str() {
            "Pod" => {
                let owners = pod_obj
                    .as_ref()
                    .and_then(|pod| self.decorator.get_owners(pod));
                DecorationInfo::Pod {
                    pod: meta.clone(),
                    owners,
                    selector_relations,
                }
            }
            "Service" => DecorationInfo::Service {
                service: meta.clone(),
                backend_ips: Vec::new(),
            },
            "Node" => DecorationInfo::Node { node: meta.clone() },
            "EndpointSlice" => DecorationInfo::EndpointSlice {
                slice: meta.clone(),
            },
            _ => DecorationInfo::Resource {
                resource: meta.clone(),
            },
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
            DecorationInfo::Pod {
                pod,
                owners,
                selector_relations,
            } => {
                self.set_k8s_attr(flow_span, "pod.name", &pod.name, is_source);
                self.set_k8s_attr_opt(flow_span, "namespace.name", &pod.namespace, is_source);

                // Populate workload controller information for all owners in the chain
                if let Some(workload_owners) = owners {
                    for workload_owner in workload_owners {
                        self.populate_workload_attributes(flow_span, workload_owner, is_source);
                    }
                }

                // Populate selector-based relations (NetworkPolicies, Services that select this pod)
                if let Some(relations) = selector_relations {
                    for relation in relations {
                        self.populate_selector_relation_attributes(flow_span, relation, is_source);
                    }
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
            DecorationInfo::Resource { resource } => {
                debug!(
                    event.name = "k8s.decorator.unhandled_resource",
                    k8s.resource.kind = %resource.kind,
                    k8s.resource.name = %resource.name,
                    k8s.resource.namespace = resource.namespace.as_deref().unwrap_or(""),
                    "skipping attribute population for unhandled kubernetes resource type"
                );
            }
        }
    }

    /// Maps workload controller metadata to the appropriate K8s attributes.
    /// Handles Deployment, ReplicaSet, StatefulSet, DaemonSet, Job, and CronJob controllers.
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
            WorkloadOwner::CronJob(meta) => {
                self.set_k8s_attr(flow_span, "cronjob.name", &meta.name, is_source);
            }
        }
    }

    /// Maps selector-based relation metadata to the appropriate K8s attributes.
    /// Handles resources that have selectors matching the pod (e.g., NetworkPolicy, Service, workload controllers).
    fn populate_selector_relation_attributes(
        &self,
        flow_span: &mut FlowSpan,
        relation: &K8sObjectMeta,
        is_source: bool,
    ) {
        // Match based on the kind field (case-insensitive comparison)
        match relation.kind.to_lowercase().as_str() {
            "networkpolicy" => {
                self.set_k8s_attr(flow_span, "networkpolicy.name", &relation.name, is_source);
            }
            "service" => {
                self.set_k8s_attr(flow_span, "service.name", &relation.name, is_source);
            }
            "replicaset" => {
                self.set_k8s_attr(flow_span, "replicaset.name", &relation.name, is_source);
            }
            "deployment" => {
                self.set_k8s_attr(flow_span, "deployment.name", &relation.name, is_source);
            }
            "statefulset" => {
                self.set_k8s_attr(flow_span, "statefulset.name", &relation.name, is_source);
            }
            "daemonset" => {
                self.set_k8s_attr(flow_span, "daemonset.name", &relation.name, is_source);
            }
            "job" => {
                self.set_k8s_attr(flow_span, "job.name", &relation.name, is_source);
            }
            "cronjob" => {
                self.set_k8s_attr(flow_span, "cronjob.name", &relation.name, is_source);
            }
            _ => {
                // For other kinds, we could add a generic attribute or log
                debug!(
                    event.name = "k8s.selector_relation.unknown_kind",
                    k8s.resource.kind = %relation.kind,
                    k8s.resource.name = %relation.name,
                    "selector relation for unsupported resource kind"
                );
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
}

/// Public interface for attributing a FlowSpan with Kubernetes metadata.
/// Creates a SpanDecorator and performs the correlation process.
pub async fn decorate_flow_span(
    flow_span: &FlowSpan,
    decorator: &Decorator,
) -> Result<FlowSpan, K8sError> {
    let span_decorator = SpanDecorator::new(decorator);
    span_decorator.decorate(flow_span).await
}
