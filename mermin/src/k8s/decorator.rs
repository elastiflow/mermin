//! decorator.rs - Kubernetes decoration processor
//!
//! This module provides a high-level, concurrent, and ergonomic interface for
//! decorating flow spans with Kubernetes metadata. It features:
//! - A high-level Decorator client for querying and correlating resources.
//! - Support for Pods, Nodes, key workload types (Deployments, StatefulSets, etc.).
//! - Network-related resources like Services, Ingresses and NetworkPolicies.

use std::{collections::HashMap, net::IpAddr};

use k8s_openapi::api::{core::v1::Pod, networking::v1::NetworkPolicySpec};
use tracing::{debug, trace};

use crate::{
    k8s::{
        K8sError,
        attributor::{
            Attributor, DecorationInfo, FlowContext, FlowDirection, K8sObjectMeta, WorkloadOwner,
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
pub struct Decorator<'a> {
    attributor: &'a Attributor,
    source_extract_rules: Vec<String>,
    dest_extract_rules: Vec<String>,
}

impl<'a> Decorator<'a> {
    pub fn new(
        attributor: &'a Attributor,
        source_extract_rules: Vec<String>,
        dest_extract_rules: Vec<String>,
    ) -> Self {
        Self {
            attributor,
            source_extract_rules,
            dest_extract_rules,
        }
    }

    /// Decorate a flow span with K8s metadata, with automatic fallback to undecorated span on error.
    ///
    /// This is the primary method for the K8s decorator pipeline. It ensures that spans are
    /// NEVER dropped - if decoration fails for any reason, the original undecorated span is returned.
    ///
    /// # Returns
    /// A tuple of (FlowSpan, Option<K8sError>) where:
    /// - FlowSpan is either decorated (on success) or the original undecorated span (on error)
    /// - Option<K8sError> is Some(error) if decoration failed, None if successful
    pub async fn decorate_or_fallback(&self, flow_span: FlowSpan) -> (FlowSpan, Option<K8sError>) {
        match self.decorate(&flow_span).await {
            Ok(decorated_span) => (decorated_span, None),
            Err(e) => (flow_span, Some(e)),
        }
    }

    /// Correlates flow attributes with Kubernetes resources and populates K8s metadata fields.
    /// Returns a cloned FlowSpan with source and destination Kubernetes attributes populated.
    async fn decorate(&self, flow_span: &FlowSpan) -> Result<FlowSpan, K8sError> {
        let ctx = FlowContext::from_flow_span(flow_span, self.attributor).await;
        let mut decorated_flow = flow_span.clone();

        let src_info = self.enrich(ctx.src_pod.as_ref(), ctx.src_ip).await;
        if let Some(info) = &src_info {
            trace!(
                event.name = "k8s.decorator.associated",
                flow.community_id = %flow_span.attributes.flow_community_id,
                k8s.direction = "source",
                "successfully associated source of flow"
            );
            self.populate_k8s_attributes(
                &mut decorated_flow,
                info,
                true,
                ctx.src_pod.as_ref(),
                flow_span.attributes.source_port,
            );
        }

        let dst_info = self.enrich(ctx.dst_pod.as_ref(), ctx.dst_ip).await;
        if let Some(info) = &dst_info {
            trace!(
                event.name = "k8s.decorator.associated",
                flow.community_id = %flow_span.attributes.flow_community_id,
                k8s.direction = "destination",
                "successfully associated destination of flow"
            );
            self.populate_k8s_attributes(
                &mut decorated_flow,
                info,
                false,
                ctx.dst_pod.as_ref(),
                flow_span.attributes.destination_port,
            );
        }

        let (ingress_policies, egress_policies) = self.evaluate_flow_policies(&ctx).await?;
        self.populate_network_policies(&mut decorated_flow, &ingress_policies, &egress_policies);

        Ok(decorated_flow)
    }

    /// Resolves a pod and IP address to Kubernetes resource decoration information.
    /// Returns Pod decoration if available, otherwise attempts IP-based fallback resolution.
    async fn enrich(&self, pod: Option<&Pod>, ip: IpAddr) -> Option<DecorationInfo> {
        if let Some(pod) = pod {
            let pod_meta = K8sObjectMeta::from(pod);
            let node_name = pod.spec.as_ref()?.node_name.clone();
            let owners = self.attributor.get_owners(pod);
            let selector_relations = self.attributor.get_selector_based_metadata(pod);
            return Some(DecorationInfo::Pod {
                pod: pod_meta,
                node_name,
                owners,
                selector_relations,
            });
        }

        if let Some(service) = self.attributor.get_service_by_ip(ip).await {
            let service_meta = K8sObjectMeta::from(service.as_ref());
            let backend_ips = self
                .attributor
                .resolve_service_ip_to_backend_ips(ip)
                .await
                .unwrap_or_default();
            return Some(DecorationInfo::Service {
                service: service_meta,
                backend_ips,
            });
        }

        if let Some(node) = self.attributor.get_node_by_ip(ip).await {
            return Some(DecorationInfo::Node {
                node: K8sObjectMeta::from(node.as_ref()),
            });
        }

        if let Some(slice) = self.attributor.get_endpointslice_by_ip(ip).await {
            return Some(DecorationInfo::EndpointSlice {
                slice: K8sObjectMeta::from(slice.as_ref()),
            });
        }

        trace!(
            event.name = "k8s.ip_unattributable",
            net.ip.address = %ip,
            "ip could not be attributed to any known kubernetes resource"
        );
        None
    }

    /// Checks if a specific metadata field should be extracted based on config.
    ///
    /// generic_kind: "pod", "node", "service", etc.
    /// field_type: "name", "namespace", "uid", "annotations", "labels"
    fn should_extract(&self, resource: &str, field: &str, is_source: bool) -> bool {
        let rules = if is_source {
            &self.source_extract_rules
        } else {
            &self.dest_extract_rules
        };

        let specific = format!("{resource}.metadata.{field}");
        if rules.contains(&specific) {
            return true;
        }

        let wildcard = format!("[*].metadata.{field}");
        if rules.contains(&wildcard) {
            return true;
        }

        false
    }

    /// Shared helper to populate standard Kubernetes metadata (Name, UID, Annotations, Namespace).
    fn populate_common_meta(
        &self,
        flow_span: &mut FlowSpan,
        kind: &str,
        meta: &K8sObjectMeta,
        is_source: bool,
        extract_namespace: bool,
    ) {
        if self.should_extract(kind, "name", is_source) {
            let attr_key = format!("{kind}.name");
            self.set_k8s_attr(flow_span, &attr_key, &meta.name, is_source);
        }

        if extract_namespace && self.should_extract(kind, "namespace", is_source) {
            self.set_k8s_attr_opt(flow_span, "namespace.name", &meta.namespace, is_source);
        }

        if self.should_extract(kind, "uid", is_source) {
            let attr_key = format!("{kind}.uid");
            self.set_k8s_attr_opt(flow_span, &attr_key, &meta.uid, is_source);
        }

        if self.should_extract(kind, "annotations", is_source) {
            let attr_key = format!("{kind}.annotations");
            self.set_k8s_map_attr(flow_span, &attr_key, &meta.annotations, is_source);
        }
    }

    /// Populates Kubernetes attributes in a FlowSpan based on DecorationInfo.
    /// Maps resource metadata to the appropriate source or destination K8s fields.
    fn populate_k8s_attributes(
        &self,
        flow_span: &mut FlowSpan,
        decoration_info: &DecorationInfo,
        is_source: bool,
        pod: Option<&Pod>,
        port: u16,
    ) {
        match decoration_info {
            DecorationInfo::Pod {
                pod: pod_meta,
                node_name,
                owners,
                selector_relations,
            } => {
                self.populate_common_meta(flow_span, "pod", pod_meta, is_source, true);

                if self.should_extract("pod", "node_name", is_source) {
                    self.set_k8s_attr_opt(flow_span, "node.name", node_name, is_source);
                }

                // Resolve and populate container information
                if let Some((container_name, container_image)) =
                    pod.and_then(|p| resolve_pod_container_by_port(p, port))
                {
                    self.set_k8s_attr(flow_span, "container.name", &container_name, is_source);
                    self.set_k8s_attr(
                        flow_span,
                        "container.image.name",
                        &container_image,
                        is_source,
                    );
                }

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
                self.populate_common_meta(flow_span, "node", node, is_source, false);
            }
            DecorationInfo::Service { service, .. } => {
                self.populate_common_meta(flow_span, "service", service, is_source, true);
            }
            DecorationInfo::EndpointSlice { slice } => {
                if self.should_extract("endpointslice", "namespace", is_source) {
                    self.set_k8s_attr_opt(flow_span, "namespace.name", &slice.namespace, is_source);
                }

                if self.should_extract("endpointslice", "annotations", is_source) {
                    self.set_k8s_map_attr(
                        flow_span,
                        "endpointslice.annotations",
                        &slice.annotations,
                        is_source,
                    );
                }
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
        let (kind, meta) = match owner {
            WorkloadOwner::Deployment(m) => ("deployment", m),
            WorkloadOwner::ReplicaSet(m) => ("replicaset", m),
            WorkloadOwner::StatefulSet(m) => ("statefulset", m),
            WorkloadOwner::DaemonSet(m) => ("daemonset", m),
            WorkloadOwner::Job(m) => ("job", m),
            WorkloadOwner::CronJob(m) => ("cronjob", m),
        };

        self.populate_common_meta(flow_span, kind, meta, is_source, false);
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
            ("container.image.name", source_container_image_name, destination_container_image_name),
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

    /// Sets an optional HashMap attribute.
    fn set_k8s_map_attr(
        &self,
        flow_span: &mut FlowSpan,
        attr_name: &str, // e.g. "pod.annotations"
        value: &Option<HashMap<String, String>>,
        is_source: bool,
    ) {
        match (is_source, attr_name) {
            (true, "pod.annotations") => {
                flow_span.attributes.source_k8s_pod_annotations = value.clone()
            }
            (false, "pod.annotations") => {
                flow_span.attributes.destination_k8s_pod_annotations = value.clone()
            }

            (true, "node.annotations") => {
                flow_span.attributes.source_k8s_node_annotations = value.clone()
            }
            (false, "node.annotations") => {
                flow_span.attributes.destination_k8s_node_annotations = value.clone()
            }

            (true, "service.annotations") => {
                flow_span.attributes.source_k8s_service_annotations = value.clone()
            }
            (false, "service.annotations") => {
                flow_span.attributes.destination_k8s_service_annotations = value.clone()
            }

            (true, "deployment.annotations") => {
                flow_span.attributes.source_k8s_deployment_annotations = value.clone()
            }
            (false, "deployment.annotations") => {
                flow_span.attributes.destination_k8s_deployment_annotations = value.clone()
            }

            (true, "daemonset.annotations") => {
                flow_span.attributes.source_k8s_daemonset_annotations = value.clone()
            }
            (false, "daemonset.annotations") => {
                flow_span.attributes.destination_k8s_daemonset_annotations = value.clone()
            }

            (true, "replicaset.annotations") => {
                flow_span.attributes.source_k8s_replicaset_annotations = value.clone()
            }
            (false, "replicaset.annotations") => {
                flow_span.attributes.destination_k8s_replicaset_annotations = value.clone()
            }

            (true, "statefulset.annotations") => {
                flow_span.attributes.source_k8s_statefulset_annotations = value.clone()
            }
            (false, "statefulset.annotations") => {
                flow_span.attributes.destination_k8s_statefulset_annotations = value.clone()
            }

            (true, "job.annotations") => {
                flow_span.attributes.source_k8s_job_annotations = value.clone()
            }
            (false, "job.annotations") => {
                flow_span.attributes.destination_k8s_job_annotations = value.clone()
            }

            (true, "cronjob.annotations") => {
                flow_span.attributes.source_k8s_cronjob_annotations = value.clone()
            }
            (false, "cronjob.annotations") => {
                flow_span.attributes.destination_k8s_cronjob_annotations = value.clone()
            }
            _ => {}
        }
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
            .attributor
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

/// Resolves container information from a Pod by matching the specified port.
///
/// Logic:
/// - Searches for a container with a matching containerPort
/// - Returns None if no container matches the port
/// - Validates that Kubernetes containerPort is in valid range (1-65535)
/// - Skips containers without images defined
pub fn resolve_pod_container_by_port(pod: &Pod, port: u16) -> Option<(String, String)> {
    let spec = pod.spec.as_ref()?;

    // Iterate through all containers in the pod
    for container in &spec.containers {
        // Skip containers without ports defined
        let Some(ports) = container.ports.as_ref() else {
            continue;
        };

        // Check if any of the container's ports match the requested port
        for container_port in ports {
            // Kubernetes containerPort is i32 but must be in valid port range (1-65535)
            // Invalid values are rejected by the API server, so we can safely cast
            let port_num = container_port.container_port;
            if port_num > 0 && port_num <= 65535 && port_num as u16 == port {
                // Found a match! Extract container name and image
                // Clone is necessary since we're borrowing from the Pod and need owned data
                let name = container.name.clone();
                let Some(image_name) = container.image.clone() else {
                    continue; // Skip containers without image
                };

                return Some((name, image_name));
            }
        }
    }

    // No matching container found
    None
}

#[cfg(test)]
mod tests {
    use k8s_openapi::api::core::v1::{Container, ContainerPort, Pod, PodSpec};

    use super::resolve_pod_container_by_port;

    /// Helper to create a container with optional ports and image
    fn create_container(name: &str, image: Option<&str>, ports: Option<Vec<i32>>) -> Container {
        Container {
            name: name.to_string(),
            image: image.map(String::from),
            ports: ports.map(|ps| {
                ps.into_iter()
                    .map(|p| ContainerPort {
                        container_port: p,
                        ..Default::default()
                    })
                    .collect()
            }),
            ..Default::default()
        }
    }

    /// Helper to create a Pod with specified containers
    fn create_pod_with_containers(containers: Vec<Container>) -> Pod {
        Pod {
            metadata: Default::default(),
            spec: Some(PodSpec {
                containers,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn test_resolve_container_single_container_returns_it() {
        let pod = create_pod_with_containers(vec![create_container(
            "nginx",
            Some("nginx:1.21"),
            Some(vec![80]),
        )]);

        let result = resolve_pod_container_by_port(&pod, 80);
        assert_eq!(
            result,
            Some(("nginx".to_string(), "nginx:1.21".to_string()))
        );
    }

    #[test]
    fn test_resolve_container_multi_container_matches_by_port() {
        let pod = create_pod_with_containers(vec![
            create_container("sidecar", Some("envoy:v1"), Some(vec![15001])),
            create_container("app", Some("myapp:v2"), Some(vec![8080])),
            create_container("metrics", Some("prom-exporter:latest"), Some(vec![9090])),
        ]);

        // Should match the app container on port 8080
        let result = resolve_pod_container_by_port(&pod, 8080);
        assert_eq!(result, Some(("app".to_string(), "myapp:v2".to_string())));

        // Should match the metrics container on port 9090
        let result = resolve_pod_container_by_port(&pod, 9090);
        assert_eq!(
            result,
            Some(("metrics".to_string(), "prom-exporter:latest".to_string()))
        );
    }

    #[test]
    fn test_resolve_container_no_port_match_returns_none() {
        let pod = create_pod_with_containers(vec![
            create_container("first", Some("first:v1"), Some(vec![80])),
            create_container("second", Some("second:v2"), Some(vec![443])),
        ]);

        // Port 9999 doesn't match any container, should return None (more accurate)
        let result = resolve_pod_container_by_port(&pod, 9999);
        assert_eq!(result, None);
    }

    #[test]
    fn test_resolve_container_with_matching_port() {
        let pod = create_pod_with_containers(vec![
            create_container("alpha", Some("alpha:1.0"), Some(vec![80])),
            create_container("beta", Some("beta:2.0"), Some(vec![443])),
        ]);

        // Match beta container on port 443
        let result = resolve_pod_container_by_port(&pod, 443);
        assert_eq!(result, Some(("beta".to_string(), "beta:2.0".to_string())));
    }

    #[test]
    fn test_resolve_container_empty_containers_returns_none() {
        let pod = create_pod_with_containers(vec![]);

        let result = resolve_pod_container_by_port(&pod, 80);
        assert_eq!(result, None);
    }

    #[test]
    fn test_resolve_container_no_spec_returns_none() {
        let pod = Pod {
            metadata: Default::default(),
            spec: None,
            ..Default::default()
        };

        let result = resolve_pod_container_by_port(&pod, 80);
        assert_eq!(result, None);
    }

    #[test]
    fn test_resolve_container_no_image_returns_none() {
        let pod =
            create_pod_with_containers(vec![create_container("noimage", None, Some(vec![80]))]);

        let result = resolve_pod_container_by_port(&pod, 80);
        assert_eq!(result, None);
    }

    #[test]
    fn test_resolve_container_skips_containers_without_ports() {
        let pod = create_pod_with_containers(vec![
            create_container("no-ports", Some("app:v1"), None),
            create_container("with-ports", Some("app:v2"), Some(vec![8080])),
        ]);

        // Looking for port 8080, should find the second container
        let result = resolve_pod_container_by_port(&pod, 8080);
        assert_eq!(
            result,
            Some(("with-ports".to_string(), "app:v2".to_string()))
        );

        // Looking for port 9999, no match, returns None (more accurate)
        let result = resolve_pod_container_by_port(&pod, 9999);
        assert_eq!(result, None);
    }

    #[test]
    fn test_resolve_container_multiple_ports_on_single_container() {
        let pod = create_pod_with_containers(vec![create_container(
            "multi-port",
            Some("server:v1"),
            Some(vec![80, 443, 8080]),
        )]);

        let expected = Some(("multi-port".to_string(), "server:v1".to_string()));

        // Should match on any of the ports
        assert_eq!(resolve_pod_container_by_port(&pod, 80), expected);
        assert_eq!(resolve_pod_container_by_port(&pod, 443), expected);
        assert_eq!(resolve_pod_container_by_port(&pod, 8080), expected);
    }
}
