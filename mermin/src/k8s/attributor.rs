// k8s.rs - Kubernetes client and resource management
//
// This module provides a high-level, concurrent, and ergonomic interface for
// interacting with Kubernetes resources. It features:
// - A ResourceStore for concurrent initialization and caching of resource reflectors.
// - A high-level Attributor client for querying and correlating resources.
// - Support for Pods, Nodes, key workload types (Deployments, StatefulSets, etc.).
// - Network-related resources like Services, Ingresses and NetworkPolicies.

use std::{
    collections::{BTreeMap, HashMap},
    fmt::Debug,
    net::IpAddr,
    sync::{Arc, atomic::Ordering},
};

use anyhow::Result;
use futures::TryStreamExt;
use ipnetwork::IpNetwork;
use k8s_openapi::{
    api::{
        apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet},
        batch::v1::Job,
        core::v1::{Namespace, Node, Pod, Service},
        discovery::v1::EndpointSlice,
        networking::v1::{Ingress, NetworkPolicy, NetworkPolicyPeer, NetworkPolicyPort},
    },
    apimachinery::pkg::{
        apis::meta::v1::{LabelSelector, LabelSelectorRequirement, OwnerReference},
        util::intstr::IntOrString,
    },
};
use kube::{
    Client,
    api::{Api, ListParams, Resource, ResourceExt},
    runtime::reflector,
};
use kube_runtime::watcher;
use log::{debug, warn};
use network_types::ip::IpProto;
use tokio::sync::oneshot;
use tracing::error;

use crate::{health::HealthState, span::flow::FlowSpan};

/// Holds metadata for a single Kubernetes object.
#[derive(Debug, Clone)]
pub struct K8sObjectMeta {
    #[allow(dead_code)]
    pub kind: String,
    pub name: String,
    #[allow(dead_code)]
    pub uid: Option<String>,
    pub namespace: Option<String>,
    #[allow(dead_code)]
    pub labels: Option<HashMap<String, String>>,
    #[allow(dead_code)]
    pub annotations: Option<HashMap<String, String>>,
}

/// Generic implementation to convert any Kubernetes Resource into our K8sObjectMeta.
impl<T> From<&T> for K8sObjectMeta
where
    T: Resource<DynamicType = ()>,
{
    fn from(resource: &T) -> Self {
        Self {
            kind: T::kind(&()).to_string(),
            name: resource.name_any(),
            uid: resource.uid(),
            namespace: resource.namespace(),
            labels: (!resource.labels().is_empty())
                .then(|| resource.labels().clone().into_iter().collect()),
            annotations: (!resource.annotations().is_empty())
                .then(|| resource.annotations().clone().into_iter().collect()),
        }
    }
}

/// Represents the workload controllers that own other resources, like Pods.
#[derive(Debug, Clone)]
pub enum WorkloadOwner {
    ReplicaSet(K8sObjectMeta),
    Deployment(K8sObjectMeta),
    StatefulSet(K8sObjectMeta),
    DaemonSet(K8sObjectMeta),
    Job(K8sObjectMeta),
}

#[derive(Debug, Clone)]
pub enum AttributionInfo {
    Pod {
        pod: K8sObjectMeta,
        owner: Option<WorkloadOwner>,
    },
    Node {
        node: K8sObjectMeta,
    },
    Service {
        service: K8sObjectMeta,
        #[allow(dead_code)]
        backend_ips: Vec<String>,
    },
    EndpointSlice {
        slice: K8sObjectMeta,
    },
}

/// A trait for types that contain a reflector store for a specific Kubernetes resource.
/// This enables generic, type-safe access to the stores.
pub trait HasStore<K>
where
    K: Resource,
    K::DynamicType: Eq + std::hash::Hash + Clone,
{
    /// Returns a reference to the store for the resource type `K`.
    fn store(&self) -> &reflector::Store<K>;
}

/// A central cache holding reflectors for all Kubernetes resources.
#[derive(Clone)]
pub struct ResourceStore {
    pub pods: reflector::Store<Pod>,
    pub nodes: reflector::Store<Node>,
    pub namespaces: reflector::Store<Namespace>,
    pub deployments: reflector::Store<Deployment>,
    pub replica_sets: reflector::Store<ReplicaSet>,
    pub stateful_sets: reflector::Store<StatefulSet>,
    pub daemon_sets: reflector::Store<DaemonSet>,
    pub jobs: reflector::Store<Job>,
    pub services: reflector::Store<Service>,
    pub ingresses: reflector::Store<Ingress>,
    pub endpoint_slices: reflector::Store<EndpointSlice>,
    pub network_policies: reflector::Store<NetworkPolicy>,
}

macro_rules! impl_has_store {
    ($resource:ty, $field:ident) => {
        impl HasStore<$resource> for ResourceStore {
            fn store(&self) -> &reflector::Store<$resource> {
                &self.$field
            }
        }
    };
}

impl_has_store!(Pod, pods);
impl_has_store!(Node, nodes);
impl_has_store!(Namespace, namespaces);
impl_has_store!(Deployment, deployments);
impl_has_store!(ReplicaSet, replica_sets);
impl_has_store!(StatefulSet, stateful_sets);
impl_has_store!(DaemonSet, daemon_sets);
impl_has_store!(Job, jobs);
impl_has_store!(Service, services);
impl_has_store!(Ingress, ingresses);
impl_has_store!(EndpointSlice, endpoint_slices);
impl_has_store!(NetworkPolicy, network_policies);

impl ResourceStore {
    /// Initializes all resource reflectors concurrently and builds the ResourceStore.
    pub async fn new(client: Client, health_state: HealthState) -> Result<Self> {
        let all_stores_and_handles = futures::try_join!(
            Self::create_resource_store::<Pod>(&client, true),
            Self::create_resource_store::<Node>(&client, false),
            Self::create_resource_store::<Namespace>(&client, true),
            Self::create_resource_store::<Deployment>(&client, false),
            Self::create_resource_store::<ReplicaSet>(&client, false),
            Self::create_resource_store::<StatefulSet>(&client, false),
            Self::create_resource_store::<DaemonSet>(&client, false),
            Self::create_resource_store::<Job>(&client, false),
            Self::create_resource_store::<Service>(&client, false),
            Self::create_resource_store::<Ingress>(&client, false),
            Self::create_resource_store::<EndpointSlice>(&client, false),
            Self::create_resource_store::<NetworkPolicy>(&client, false),
        )?;

        let (
            (pods, pods_r),
            (nodes, nodes_r),
            (namespaces, namespaces_r),
            (deployments, deployments_r),
            (replica_sets, replica_sets_r),
            (stateful_sets, stateful_sets_r),
            (daemon_sets, daemon_sets_r),
            (jobs, jobs_r),
            (services, services_r),
            (ingresses, ingresses_r),
            (endpoint_slices, endpoint_slices_r),
            (network_policies, network_policies_r),
        ) = all_stores_and_handles;

        let readiness_handles: Vec<_> = [
            pods_r,
            nodes_r,
            namespaces_r,
            deployments_r,
            replica_sets_r,
            stateful_sets_r,
            daemon_sets_r,
            jobs_r,
            services_r,
            ingresses_r,
            endpoint_slices_r,
            network_policies_r,
        ]
        .into_iter()
        .flatten()
        .collect();

        let _ = futures::future::join_all(readiness_handles).await;

        health_state
            .k8s_caches_synced
            .store(true, Ordering::Relaxed);

        Ok(Self {
            pods,
            nodes,
            namespaces,
            deployments,
            replica_sets,
            stateful_sets,
            daemon_sets,
            jobs,
            services,
            ingresses,
            endpoint_slices,
            network_policies,
        })
    }

    /// Helper to create a store for a resource, handling failures gracefully.
    async fn create_resource_store<K>(
        client: &Client,
        is_critical: bool,
    ) -> Result<(reflector::Store<K>, Option<oneshot::Receiver<()>>)>
    where
        K: Resource + Clone + Debug + Send + Sync + 'static + for<'de> serde::Deserialize<'de>,
        K::DynamicType: Default + std::hash::Hash + std::cmp::Eq + Clone,
    {
        let resource_name = K::kind(&K::DynamicType::default()).to_string();
        match create_store::<K>(client.clone()).await {
            Ok((store, readiness_rx)) => Ok((store, Some(readiness_rx))),
            Err(e) => {
                if is_critical {
                    warn!("failed to create critical reflector for {resource_name}: {e}");
                    Err(anyhow::anyhow!(
                        "failed to create critical reflector for {resource_name}: {e}"
                    ))
                } else {
                    warn!(
                        "failed to create reflector for {resource_name}: {e}. Continuing with an empty store."
                    );
                    let (reader, _) = reflector::store();
                    Ok((reader, None))
                }
            }
        }
    }

    /// Generic method to find resources of a specific type by namespace.
    pub fn get_by_namespace<K>(&self, namespace: &str) -> Vec<Arc<K>>
    where
        Self: HasStore<K>,
        K: Resource + Clone + 'static,
        K::DynamicType: Eq + std::hash::Hash + Clone,
    {
        self.store()
            .state()
            .iter()
            .filter(|resource| resource.meta().namespace.as_deref() == Some(namespace))
            .cloned()
            .collect()
    }
}

/// Creates a new reflector for a Kubernetes resource type.
async fn create_store<K>(client: Client) -> Result<(reflector::Store<K>, oneshot::Receiver<()>)>
where
    K: Resource + Clone + Debug + Send + Sync + 'static + for<'de> serde::Deserialize<'de>,
    K::DynamicType: Default + std::hash::Hash + Eq + Clone,
{
    let resource_name = K::kind(&K::DynamicType::default()).to_string();
    let api: Api<K> = Api::all(client);

    // Fail fast if the API is unreachable.
    api.list(&ListParams::default().limit(1)).await?;

    let (reader, writer) = reflector::store();
    let reflector = reflector(writer, watcher(api, watcher::Config::default()));

    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let mut pinned_reflector = Box::pin(reflector);
        let mut sender = Some(tx);

        loop {
            match pinned_reflector.try_next().await {
                Ok(Some(_event)) => {
                    if let Some(sender) = sender.take()
                        && sender.send(()).is_ok()
                    {
                        debug!("initial sync complete for {resource_name}");
                    }
                }
                Ok(None) => {
                    warn!("reflector stream for {resource_name} has terminated.");
                    break;
                }
                Err(e) => {
                    error!("reflector error for {resource_name}: {e}. retrying...");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
    });

    Ok((reader, rx))
}

/// Represents the context of a network flow for policy evaluation
#[derive(Debug, Clone)]
pub struct FlowContext {
    pub src_pod: Option<Pod>,
    pub src_ip: IpAddr,
    pub dst_pod: Option<Pod>,
    pub dst_ip: IpAddr,
    pub port: u16,
    pub protocol: IpProto,
}

impl FlowContext {
    pub async fn from_flow_span(flow_span: &FlowSpan, attributor: &Attributor) -> Self {
        // Extract IPs and ports
        let (src_ip, dst_ip, port, protocol) = (
            flow_span.attributes.source_address,
            flow_span.attributes.destination_address,
            flow_span.attributes.destination_port,
            flow_span.attributes.network_transport,
        );

        // Resolve pods
        let src_pod = attributor.get_pod_by_ip(src_ip).await;
        let dst_pod = attributor.get_pod_by_ip(dst_ip).await;

        Self {
            src_pod: src_pod.as_deref().cloned(),
            src_ip,
            dst_pod: dst_pod.as_deref().cloned(),
            dst_ip,
            port,
            protocol,
        }
    }
}

/// A high-level client for querying Kubernetes resources.
pub struct Attributor {
    #[allow(dead_code)]
    pub client: Client,
    pub resource_store: ResourceStore,
}

impl Attributor {
    /// Creates a new Attributor, initializing all resource reflectors concurrently.
    pub async fn new(health_state: HealthState) -> Result<Self> {
        let client = Client::try_default().await?;
        let resource_store = ResourceStore::new(client.clone(), health_state).await?;
        Ok(Self {
            client,
            resource_store,
        })
    }

    /// Given a Pod object, traverses its ownerReferences to find its top-level managing controller.
    pub fn get_top_level_controller(&self, pod: &Pod) -> Option<WorkloadOwner> {
        let mut current_owners = pod.owner_references().to_vec();
        let mut namespace = pod.namespace().unwrap_or_default();
        let mut top_level_owner = None;

        while let Some(owner_ref) = current_owners.pop() {
            if let Some((owner, next_owners_opt)) = self.get_owner(&owner_ref, &namespace) {
                top_level_owner = Some(owner);

                if let Some(next_owners) = next_owners_opt {
                    current_owners = next_owners;
                    if let Some(Some(ns)) = top_level_owner.as_ref().map(|o| match o {
                        WorkloadOwner::Deployment(m) => m.namespace.as_ref(),
                        WorkloadOwner::ReplicaSet(m) => m.namespace.as_ref(),
                        WorkloadOwner::StatefulSet(m) => m.namespace.as_ref(),
                        WorkloadOwner::DaemonSet(m) => m.namespace.as_ref(),
                        WorkloadOwner::Job(m) => m.namespace.as_ref(),
                    }) {
                        namespace = ns.clone();
                    }
                } else {
                    break;
                }
            } else {
                warn!(
                    "failed to find owner {} ({}) in store for namespace {}",
                    owner_ref.name, owner_ref.kind, namespace
                );
                break;
            }
        }

        top_level_owner
    }

    /// Looks up a single owner reference in the corresponding resource store.
    fn get_owner(
        &self,
        owner_ref: &OwnerReference,
        namespace: &str,
    ) -> Option<(WorkloadOwner, Option<Vec<OwnerReference>>)> {
        let name = &owner_ref.name;
        macro_rules! find_in_store {
            ($store_type:ty, $variant:ident) => {
                self.resource_store
                    .get_by_namespace::<$store_type>(namespace)
                    .iter()
                    .find(|obj| obj.name_any() == *name)
                    .map(|obj| {
                        let meta = K8sObjectMeta::from(obj.as_ref());
                        let next_owners = obj.meta().owner_references.clone();
                        (WorkloadOwner::$variant(meta), next_owners)
                    })
            };
        }

        match owner_ref.kind.as_str() {
            "ReplicaSet" => find_in_store!(ReplicaSet, ReplicaSet),
            "Deployment" => find_in_store!(Deployment, Deployment),
            "StatefulSet" => find_in_store!(StatefulSet, StatefulSet),
            "DaemonSet" => find_in_store!(DaemonSet, DaemonSet),
            "Job" => find_in_store!(Job, Job),
            _ => {
                warn!(
                    "owner lookup for kind '{}' is not implemented",
                    owner_ref.kind
                );
                None
            }
        }
    }

    /// Looks up a Pod by its IP address.
    pub async fn get_pod_by_ip(&self, ip: IpAddr) -> Option<Arc<Pod>> {
        let ip_str = ip.to_string();
        let target_ip_slice = Some(ip_str.as_str());

        self.resource_store
            .pods
            .state()
            .iter()
            .find(|pod| {
                pod.status.as_ref().is_some_and(|status| {
                    status.pod_ip.as_deref() == target_ip_slice
                        || status.host_ip.as_deref() == target_ip_slice
                        || status.pod_ips.as_ref().is_some_and(|ips| {
                            ips.iter()
                                .any(|pod_ip_info| pod_ip_info.ip.as_str() == ip_str)
                        })
                        || status.host_ips.as_ref().is_some_and(|ips| {
                            ips.iter()
                                .any(|host_ip_info| host_ip_info.ip.as_str() == ip_str)
                        })
                })
            })
            .cloned()
    }

    pub async fn get_node_by_ip(&self, ip: IpAddr) -> Option<Arc<Node>> {
        let ip_str = ip.to_string();
        self.resource_store
            .nodes
            .state()
            .iter()
            .find(|node| {
                node.status
                    .as_ref()
                    .and_then(|status| status.addresses.as_ref())
                    .is_some_and(|addresses| addresses.iter().any(|addr| addr.address == ip_str))
            })
            .cloned()
    }

    /// Looks up a Service by an IP address.
    ///
    /// This method checks against the following fields:
    /// - `spec.cluster_ip` and `spec.cluster_ips`
    /// - `spec.external_ips`
    /// - `spec.load_balancer_ip` (a user-requested IP)
    /// - `status.load_balancer.ingress` (the actual provisioned IPs)
    pub async fn get_service_by_ip(&self, ip: IpAddr) -> Option<Arc<Service>> {
        let ip_str = ip.to_string();
        self.resource_store
            .services
            .state()
            .iter()
            .find(|service| {
                let spec_match = service.spec.as_ref().is_some_and(|spec| {
                    spec.cluster_ip.as_deref() == Some(&ip_str)
                        || spec
                            .cluster_ips
                            .as_ref()
                            .is_some_and(|ips| ips.contains(&ip_str))
                        || spec
                            .external_ips
                            .as_ref()
                            .is_some_and(|ips| ips.contains(&ip_str))
                        || spec.load_balancer_ip.as_deref() == Some(&ip_str)
                });
                if spec_match {
                    return true;
                }

                // Check the status for provisioned LoadBalancer IPs
                service
                    .status
                    .as_ref()
                    .and_then(|status| status.load_balancer.as_ref())
                    .and_then(|lb| lb.ingress.as_ref())
                    .is_some_and(|ingress| ingress.iter().any(|i| i.ip.as_deref() == Some(&ip_str)))
            })
            .cloned()
    }

    /// Takes a virtual IP (like a ClusterIP) and resolves it to the list of
    /// real, ready backend IP addresses from the associated EndpointSlices.
    ///
    /// Returns `None` if the input IP does not belong to any Service.
    /// Returns `Some(Vec<String>)` containing the backend IPs if resolution is successful.
    pub async fn resolve_service_ip_to_backend_ips(
        &self,
        service_ip: IpAddr,
    ) -> Option<Vec<String>> {
        let service = self.get_service_by_ip(service_ip).await?;
        let slices = self.get_endpointslices_for_service(&service);

        let backend_ips = slices
            .iter()
            .flat_map(|slice| &slice.endpoints)
            .filter(|endpoint| {
                endpoint
                    .conditions
                    .as_ref()
                    .and_then(|c| c.ready)
                    .unwrap_or(false)
            })
            .flat_map(|endpoint| &endpoint.addresses)
            .cloned()
            .collect::<Vec<String>>();

        Some(backend_ips)
    }

    /// Looks up an EndpointSlice directly by one of its endpoint IP addresses.
    pub async fn get_endpointslice_by_ip(&self, ip: IpAddr) -> Option<Arc<EndpointSlice>> {
        let ip_str = ip.to_string();
        self.resource_store
            .endpoint_slices
            .state()
            .iter()
            .find(|slice| {
                // An EndpointSlice contains a list of endpoints.
                slice.endpoints.iter().any(|endpoint| {
                    // Each endpoint has a list of IP addresses.
                    endpoint.addresses.contains(&ip_str)
                })
            })
            .cloned()
    }

    /// Finds all EndpointSlices associated with a given Service.
    pub fn get_endpointslices_for_service(&self, service: &Service) -> Vec<Arc<EndpointSlice>> {
        let service_name = service.metadata.name.as_deref().unwrap_or_default();
        if service_name.is_empty() {
            return Vec::new();
        }

        self.resource_store
            .endpoint_slices
            .state()
            .iter()
            .filter(|slice| {
                // Ensure the slice is in the same namespace as the service
                slice.metadata.namespace == service.metadata.namespace &&
                    // Check for the controlling label
                    slice
                        .metadata
                        .labels
                        .as_ref()
                        .and_then(|labels| labels.get("kubernetes.io/service-name"))
                        .is_some_and(|name| name == service_name)
            })
            .cloned()
            .collect()
    }

    /// Main entry point: finds all NetworkPolicies that permit the specified traffic flow
    pub fn get_matching_network_policies(
        &self,
        ctx: &FlowContext,
        pod: &Pod,
        direction: FlowDirection,
    ) -> Result<Vec<Arc<NetworkPolicy>>> {
        let applicable_policies = self.get_network_policies_for_pod(pod)?;

        Ok(applicable_policies
            .into_iter()
            .filter(|policy| self.policy_permits_flow(ctx, policy, direction))
            .collect())
    }

    /// Gets NetworkPolicies that apply to the given pod based on podSelector
    fn get_network_policies_for_pod(&self, pod: &Pod) -> Result<Vec<Arc<NetworkPolicy>>> {
        let pod_namespace = pod.clone().metadata.namespace.unwrap_or_default();
        let pod_labels = pod.labels();

        let policies = self
            .resource_store
            .get_by_namespace::<NetworkPolicy>(&pod_namespace)
            .into_iter()
            .filter(|policy| {
                // Check if the policy's podSelector matches the destination pod
                policy
                    .spec
                    .as_ref()
                    .map(|spec| spec.clone().pod_selector)
                    .is_some_and(|selector| self.selector_matches(&selector, pod_labels))
            })
            .collect();

        Ok(policies)
    }

    /// Checks if a label selector matches the given labels
    fn selector_matches(
        &self,
        selector: &LabelSelector,
        labels: &BTreeMap<String, String>,
    ) -> bool {
        // Check match_labels
        if let Some(match_labels) = &selector.match_labels {
            for (key, value) in match_labels {
                if labels.get(key) != Some(value) {
                    return false;
                }
            }
        }

        // Check match_expressions
        if let Some(match_expressions) = &selector.match_expressions {
            for expr in match_expressions {
                if !self.expression_matches(expr, labels) {
                    return false;
                }
            }
        }

        true
    }

    /// Checks if a label selector requirement matches the given labels
    fn expression_matches(
        &self,
        expr: &LabelSelectorRequirement,
        labels: &BTreeMap<String, String>,
    ) -> bool {
        let label_value = labels.get(&expr.key);
        let binding = vec![];
        let values = expr.values.as_ref().unwrap_or(&binding);

        match expr.operator.as_str() {
            "In" => {
                if let Some(value) = label_value {
                    values.contains(value)
                } else {
                    false
                }
            }
            "NotIn" => {
                if let Some(value) = label_value {
                    !values.contains(value)
                } else {
                    true
                }
            }
            "Exists" => label_value.is_some(),
            "DoesNotExist" => label_value.is_none(),
            _ => false,
        }
    }

    /// Consolidated policy evaluation - supports both ingress and egress rules
    fn policy_permits_flow(
        &self,
        ctx: &FlowContext,
        policy: &NetworkPolicy,
        direction: FlowDirection,
    ) -> bool {
        match direction {
            FlowDirection::Ingress => self.evaluate_ingress_rules(ctx, policy, direction),
            FlowDirection::Egress => self.evaluate_egress_rules(ctx, policy, direction),
        }
    }

    /// Evaluates ingress rules for a policy.
    fn evaluate_ingress_rules(
        &self,
        ctx: &FlowContext,
        policy: &NetworkPolicy,
        direction: FlowDirection,
    ) -> bool {
        let Some(ingress_rules) = policy.spec.as_ref().and_then(|s| s.ingress.as_ref()) else {
            return false;
        };

        ingress_rules.iter().any(|rule| {
            let from_match = rule.from.as_ref().is_none_or(|from_peers| {
                from_peers.is_empty()
                    || from_peers.iter().any(|peer| {
                        self.peer_matches(ctx, peer, true, policy.clone().metadata.namespace)
                    })
            });

            from_match && self.check_ports_match(ctx, &rule.ports, direction)
        })
    }

    /// Evaluates egress rules for a policy.
    fn evaluate_egress_rules(
        &self,
        ctx: &FlowContext,
        policy: &NetworkPolicy,
        direction: FlowDirection,
    ) -> bool {
        let Some(egress_rules) = policy.spec.as_ref().and_then(|s| s.egress.as_ref()) else {
            return false;
        };

        egress_rules.iter().any(|rule| {
            let to_match = rule.to.as_ref().is_none_or(|to_peers| {
                to_peers.is_empty()
                    || to_peers.iter().any(|peer| {
                        self.peer_matches(ctx, peer, false, policy.clone().metadata.namespace)
                    })
            });

            to_match && self.check_ports_match(ctx, &rule.ports, direction)
        })
    }

    /// Checks if a flow's port and protocol match any of the specified NetworkPolicyPorts.
    /// Returns true if there are no ports specified (allowing all ports).
    fn check_ports_match(
        &self,
        ctx: &FlowContext,
        ports: &Option<Vec<NetworkPolicyPort>>,
        direction: FlowDirection,
    ) -> bool {
        ports.as_ref().is_none_or(|ports| {
            ports.is_empty() || ports.iter().any(|p| self.port_matches(ctx, p, direction))
        })
    }

    /// Enhanced port matching with support for ranges and named ports for a single port spec.
    fn port_matches(
        &self,
        ctx: &FlowContext,
        port_spec: &NetworkPolicyPort,
        direction: FlowDirection,
    ) -> bool {
        // First, ensure the protocol matches. This is a good guard clause.
        let proto_match = port_spec
            .protocol
            .as_deref()
            .unwrap_or("TCP")
            .eq_ignore_ascii_case(ctx.protocol.as_str());

        if !proto_match {
            return false;
        }

        // Then, check the port number based on its type (Int, String, or None)
        match &port_spec.port {
            Some(IntOrString::Int(p_num)) => {
                let start_port = *p_num as u16;
                let end_port = port_spec.end_port.map(|ep| ep as u16).unwrap_or(start_port);
                (start_port..=end_port).contains(&ctx.port)
            }
            Some(IntOrString::String(port_name)) => {
                self.resolve_named_port(ctx, port_name, direction)
            }
            None => true, // If `port` is not specified, it allows all ports for the given protocol.
        }
    }

    /// Resolves named ports by searching through the containers of the relevant pod.
    fn resolve_named_port(
        &self,
        ctx: &FlowContext,
        port_name: &str,
        direction: FlowDirection,
    ) -> bool {
        // Determine which pod to inspect based on traffic direction.
        let target_pod = match direction {
            FlowDirection::Ingress => &ctx.dst_pod,
            FlowDirection::Egress => &ctx.src_pod,
        };

        let Some(pod) = target_pod else {
            return false;
        };
        let Some(spec) = pod.spec.as_ref() else {
            return false;
        };

        spec.containers
            .iter()
            .flat_map(|container| container.ports.as_ref().into_iter().flatten())
            .any(|port| {
                port.name.as_deref() == Some(port_name) && port.container_port as u16 == ctx.port
            })
    }

    fn peer_matches(
        &self,
        ctx: &FlowContext,
        peer: &NetworkPolicyPeer,
        is_source: bool,
        policy_namespace: Option<String>,
    ) -> bool {
        let (target_ip, target_pod) = if is_source {
            (ctx.src_ip, &ctx.src_pod)
        } else {
            (ctx.dst_ip, &ctx.dst_pod)
        };

        // If the peer has an ipBlock, a match on CIDR is sufficient.
        if let Some(ip_block) = &peer.ip_block
            && self.ip_matches_cidr(target_ip, &ip_block.cidr)
        {
            return true;
        }

        // If we didn't match an ipBlock and there's no pod, we can't match further.
        let Some(pod) = target_pod else {
            return false;
        };

        // Check for namespace selector match.
        let namespace_matches =
            self.namespace_matches_selector_internal(pod, peer, policy_namespace);

        if !namespace_matches {
            return false;
        }

        // If namespace matches, check for pod selector match.
        // No pod selector means it matches all pods in the selected namespace(s).
        peer.pod_selector
            .as_ref()
            .is_none_or(|ps| self.selector_matches(ps, pod.labels()))
    }

    /// Checks if an IP address matches a CIDR block using the `ipnetwork` crate.
    fn ip_matches_cidr(&self, ip: IpAddr, cidr: &str) -> bool {
        // The `ipnetwork` crate handles parsing both single IPs and CIDR notations correctly.
        match cidr.parse::<IpNetwork>() {
            Ok(network) => network.contains(ip),
            Err(_) => {
                debug!("failed to parse CIDR string: {cidr}");
                false
            }
        }
    }

    /// Consolidated namespace matching for both ingress and egress rules
    fn namespace_matches_selector_internal(
        &self,
        pod: &Pod,
        peer: &NetworkPolicyPeer,
        policy_namespace: Option<String>,
    ) -> bool {
        match &peer.namespace_selector {
            Some(ns_selector) => {
                // If namespace selector is present, evaluate it against the pod's namespace
                let pod_namespace = pod.namespace().unwrap_or_default();
                if let Some(ns) = self
                    .resource_store
                    .get_by_namespace::<Namespace>(&pod_namespace)
                    .first()
                {
                    self.selector_matches(ns_selector, ns.labels())
                } else {
                    false
                }
            }
            None => match (pod.namespace(), policy_namespace) {
                (Some(pod_ns), Some(pol_ns)) => pod_ns == pol_ns,
                _ => false,
            },
        }
    }
}

/// Flow direction for policy evaluation
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FlowDirection {
    Ingress,
    Egress,
}
