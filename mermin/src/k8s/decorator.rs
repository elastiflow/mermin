//! decorator.rs - Kubernetes decoration processor
//!
//! This module provides a high-level, concurrent, and ergonomic interface for
//! decorating flow spans with Kubernetes metadata. It features:
//! - A high-level Decorator client for querying and correlating resources.
//! - Support for Pods, Nodes, key workload types (Deployments, StatefulSets, etc.).
//! - Network-related resources like Services, Ingresses and NetworkPolicies.

use std::{collections::HashMap, net::IpAddr};

use k8s_openapi::api::core::v1::Pod;
use tracing::debug;

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

    /// Decorate a flow span with K8s metadata, with automatic fallback on error.
    ///
    /// This is the primary method for the K8s decorator pipeline. It ensures that spans are
    /// NEVER dropped - if decoration fails for any reason, the span is returned as-is. The
    /// returned span may be partially decorated: if src/dst K8s attribute lookups succeeded
    /// before the failure, those fields will be populated on the fallback span.
    pub async fn decorate_or_fallback(&self, flow_span: FlowSpan) -> (FlowSpan, Option<K8sError>) {
        match self.decorate(flow_span).await {
            Ok(decorated_span) => (decorated_span, None),
            Err((e, original)) => (original, Some(e)),
        }
    }

    /// Correlates flow attributes with Kubernetes resources and populates K8s metadata fields.
    ///
    /// Takes ownership of `flow_span` so that K8s fields can be written via `attrs_mut()` without
    /// cloning the inner `Arc<SpanAttributes>` (refcount is 1 on entry). On error the span is
    /// returned inside the `Err` variant so the caller can fall back to the undecorated version.
    async fn decorate(&self, mut flow_span: FlowSpan) -> Result<FlowSpan, (K8sError, FlowSpan)> {
        let ctx = FlowContext::from_flow_span(&flow_span, self.attributor).await;

        // Copy the port scalars (u16, Copy) before any mutable borrow of flow_span.
        let src_port = flow_span.attributes.source_port;
        let dst_port = flow_span.attributes.destination_port;

        let src_info = self.enrich(ctx.src_pod.as_ref(), ctx.src_ip).await;
        if let Some(info) = &src_info {
            self.populate_k8s_attributes(
                &mut flow_span,
                info,
                true,
                ctx.src_pod.as_ref(),
                src_port,
            );
        }

        let dst_info = self.enrich(ctx.dst_pod.as_ref(), ctx.dst_ip).await;
        if let Some(info) = &dst_info {
            self.populate_k8s_attributes(
                &mut flow_span,
                info,
                false,
                ctx.dst_pod.as_ref(),
                dst_port,
            );
        }

        let (ingress_policies, egress_policies) = match self.evaluate_flow_policies(&ctx).await {
            Ok(policies) => policies,
            Err(e) => return Err((e, flow_span)),
        };
        self.populate_network_policies(&mut flow_span, &ingress_policies, &egress_policies);

        Ok(flow_span)
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
            return Some(DecorationInfo::Service {
                service: K8sObjectMeta::from(service.as_ref()),
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

                if let Some((container_name, container_image)) =
                    pod.and_then(|p| resolve_pod_container_by_port(p, port))
                    && self.should_extract("container", "name", is_source)
                {
                    self.set_k8s_attr(flow_span, "container.name", &container_name, is_source);
                    self.set_k8s_attr(
                        flow_span,
                        "container.image.name",
                        &container_image,
                        is_source,
                    );
                }

                if let Some(workload_owners) = owners {
                    for workload_owner in workload_owners {
                        self.populate_workload_attributes(flow_span, workload_owner, is_source);
                    }
                }

                if let Some(relations) = selector_relations {
                    for relation in relations {
                        self.populate_selector_relation_attributes(flow_span, relation, is_source);
                    }
                }
            }
            DecorationInfo::Node { node } => {
                self.populate_common_meta(flow_span, "node", node, is_source, false);
            }
            DecorationInfo::Service { service } => {
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

    fn populate_selector_relation_attributes(
        &self,
        flow_span: &mut FlowSpan,
        relation: &K8sObjectMeta,
        is_source: bool,
    ) {
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

    fn set_k8s_attr(
        &self,
        flow_span: &mut FlowSpan,
        attr_name: &str,
        value: &str,
        is_source: bool,
    ) {
        self.set_k8s_attr_opt(flow_span, attr_name, &Some(value.to_string()), is_source);
    }

    fn set_k8s_attr_opt(
        &self,
        flow_span: &mut FlowSpan,
        attr_name: &str,
        value: &Option<String>,
        is_source: bool,
    ) {
        let attrs = flow_span.attrs_mut();

        macro_rules! k8s_attr_mapping {
            ($(($attr:literal, $source_field:ident, $dest_field:ident)),* $(,)?) => {
                match (is_source, attr_name) {
                    $(
                        (true, $attr) => &mut attrs.$source_field,
                        (false, $attr) => &mut attrs.$dest_field,
                    )*
                    _ => return, // Unknown attribute - silently ignored for forward compatibility
                }
            };
        }

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

    fn set_k8s_map_attr(
        &self,
        flow_span: &mut FlowSpan,
        attr_name: &str,
        value: &Option<HashMap<String, String>>,
        is_source: bool,
    ) {
        let attrs = flow_span.attrs_mut();
        match (is_source, attr_name) {
            (true, "pod.annotations") => attrs.source_k8s_pod_annotations = value.clone(),
            (false, "pod.annotations") => attrs.destination_k8s_pod_annotations = value.clone(),

            (true, "node.annotations") => attrs.source_k8s_node_annotations = value.clone(),
            (false, "node.annotations") => attrs.destination_k8s_node_annotations = value.clone(),

            (true, "service.annotations") => attrs.source_k8s_service_annotations = value.clone(),
            (false, "service.annotations") => {
                attrs.destination_k8s_service_annotations = value.clone()
            }

            (true, "deployment.annotations") => {
                attrs.source_k8s_deployment_annotations = value.clone()
            }
            (false, "deployment.annotations") => {
                attrs.destination_k8s_deployment_annotations = value.clone()
            }

            (true, "daemonset.annotations") => {
                attrs.source_k8s_daemonset_annotations = value.clone()
            }
            (false, "daemonset.annotations") => {
                attrs.destination_k8s_daemonset_annotations = value.clone()
            }

            (true, "replicaset.annotations") => {
                attrs.source_k8s_replicaset_annotations = value.clone()
            }
            (false, "replicaset.annotations") => {
                attrs.destination_k8s_replicaset_annotations = value.clone()
            }

            (true, "statefulset.annotations") => {
                attrs.source_k8s_statefulset_annotations = value.clone()
            }
            (false, "statefulset.annotations") => {
                attrs.destination_k8s_statefulset_annotations = value.clone()
            }

            (true, "job.annotations") => attrs.source_k8s_job_annotations = value.clone(),
            (false, "job.annotations") => attrs.destination_k8s_job_annotations = value.clone(),

            (true, "cronjob.annotations") => attrs.source_k8s_cronjob_annotations = value.clone(),
            (false, "cronjob.annotations") => {
                attrs.destination_k8s_cronjob_annotations = value.clone()
            }
            _ => {}
        }
    }

    fn populate_network_policies(
        &self,
        flow_span: &mut FlowSpan,
        ingress_policies: &[NetworkPolicy],
        egress_policies: &[NetworkPolicy],
    ) {
        if ingress_policies.is_empty() && egress_policies.is_empty() {
            return;
        }

        let format_names = |policies: &[NetworkPolicy]| -> Option<Vec<String>> {
            if policies.is_empty() {
                return None;
            }
            Some(
                policies
                    .iter()
                    .map(|p| match &p.policy.namespace {
                        Some(ns) => format!("{}/{}", ns, p.policy.name),
                        None => p.policy.name.clone(),
                    })
                    .collect(),
            )
        };

        let attrs = flow_span.attrs_mut();
        attrs.network_policies_ingress = format_names(ingress_policies);
        attrs.network_policies_egress = format_names(egress_policies);
    }

    async fn evaluate_flow_policies(
        &self,
        ctx: &FlowContext,
    ) -> Result<(Vec<NetworkPolicy>, Vec<NetworkPolicy>), K8sError> {
        let mut ingress_policies = Vec::new();
        let mut egress_policies = Vec::new();

        if let Some(dst_pod) = &ctx.dst_pod {
            ingress_policies = self.get_policies_for_pod(ctx, dst_pod, FlowDirection::Ingress)?;
        }

        if let Some(src_pod) = &ctx.src_pod {
            egress_policies = self.get_policies_for_pod(ctx, src_pod, FlowDirection::Egress)?;
        }

        Ok((ingress_policies, egress_policies))
    }

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
            })
            .collect())
    }
}

/// Resolves container name and image from a Pod by matching the specified port number.
pub fn resolve_pod_container_by_port(pod: &Pod, port: u16) -> Option<(String, String)> {
    let spec = pod.spec.as_ref()?;

    for container in &spec.containers {
        let Some(ports) = container.ports.as_ref() else {
            continue;
        };

        for container_port in ports {
            let port_num = container_port.container_port;
            if port_num > 0 && port_num <= 65535 && port_num as u16 == port {
                let name = container.name.clone();
                let Some(image_name) = container.image.clone() else {
                    continue;
                };
                return Some((name, image_name));
            }
        }
    }

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
