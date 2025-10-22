// k8s.rs - Kubernetes client and resource management
//
// This module provides a high-level, concurrent, and ergonomic interface for
// interacting with Kubernetes resources. It features:
// - A ResourceStore for concurrent initialization and caching of resource reflectors.
// - A high-level Decorator client for querying and correlating resources.
// - Support for Pods, Nodes, key workload types (Deployments, StatefulSets, etc.).
// - Network-related resources like Services, Ingresses and NetworkPolicies.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Debug,
    net::IpAddr,
    sync::{Arc, atomic::Ordering},
};

use futures::TryStreamExt;
use ip_network::IpNetwork;
use k8s_openapi::{
    api::{
        apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet},
        batch::v1::{CronJob, Job},
        core::v1::{Namespace, Node, Pod, Service},
        discovery::v1::EndpointSlice,
        networking::v1::{Ingress, NetworkPolicy, NetworkPolicyPeer, NetworkPolicyPort},
    },
    apimachinery::pkg::{
        apis::meta::v1::{LabelSelector, LabelSelectorRequirement},
        util::intstr::IntOrString,
    },
};
use kube::{
    Client,
    api::{Api, ListParams, Resource, ResourceExt},
    runtime::{reflector, reflector::ObjectRef},
};
use kube_runtime::watcher;
use network_types::ip::IpProto;
use serde_json::{Value, to_value};
use tokio::{
    net::lookup_host,
    sync::{RwLock, oneshot},
};
use tracing::{debug, error, warn};

use crate::{
    health::HealthState,
    k8s::{
        K8sError,
        owner_relations::{OwnerRelationsManager, OwnerRelationsOptions},
        selector_relations::SelectorRelationsManager,
    },
    runtime::conf::{AttributesConf, Conf, ObjectAssociationRule, SelectorRelationRule},
    span::flow::FlowSpan,
};

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
    CronJob(K8sObjectMeta),
}

#[derive(Debug, Clone)]
pub enum DecorationInfo {
    Pod {
        pod: K8sObjectMeta,
        owners: Option<Vec<WorkloadOwner>>,
        /// Resources that have selectors matching this pod's labels
        /// (e.g., NetworkPolicies, Services that select this pod)
        selector_relations: Option<Vec<K8sObjectMeta>>,
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
    // generic fallback for any other resource type
    Resource {
        resource: K8sObjectMeta,
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
    pub cron_jobs: reflector::Store<CronJob>,
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
impl_has_store!(CronJob, cron_jobs);
impl_has_store!(Service, services);
impl_has_store!(Ingress, ingresses);
impl_has_store!(EndpointSlice, endpoint_slices);
impl_has_store!(NetworkPolicy, network_policies);

impl ResourceStore {
    /// Initializes all resource reflectors concurrently and builds the ResourceStore.
    pub async fn new(
        client: Client,
        health_state: HealthState,
        required_kinds: &HashSet<String>,
    ) -> Result<Self, K8sError> {
        let mut readiness_handles = Vec::new();

        macro_rules! create {
            ($kind:literal, $type:ty, $is_critical:expr) => {{
                let (store, rx) = Self::create_resource_store::<$type>(
                    &client,
                    required_kinds.contains($kind),
                    $is_critical,
                )
                .await?;
                readiness_handles.extend(rx);
                store
            }};
        }

        // Critical stores
        let (pods, pods_r) = Self::create_resource_store::<Pod>(&client, true, true).await?;
        readiness_handles.extend(pods_r);
        let (namespaces, ns_r) =
            Self::create_resource_store::<Namespace>(&client, true, true).await?;
        readiness_handles.extend(ns_r);

        // Dynamic Stores
        let nodes = create!("node", Node, false);
        let deployments = create!("deployment", Deployment, false);
        let replica_sets = create!("replicaset", ReplicaSet, false);
        let stateful_sets = create!("statefulset", StatefulSet, false);
        let daemon_sets = create!("daemonset", DaemonSet, false);
        let jobs = create!("job", Job, false);
        let cron_jobs = create!("cronjob", CronJob, false);
        let services = create!("service", Service, false);
        let ingresses = create!("ingress", Ingress, false);
        let endpoint_slices = create!("endpointslice", EndpointSlice, false);
        let network_policies = create!("networkpolicy", NetworkPolicy, false);

        // Wait for all *started* reflectors to sync
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
            cron_jobs,
            services,
            ingresses,
            endpoint_slices,
            network_policies,
        })
    }

    /// Helper to create a store for a resource, handling failures gracefully.
    async fn create_resource_store<K>(
        client: &Client,
        is_required: bool,
        is_critical: bool,
    ) -> Result<(reflector::Store<K>, Option<oneshot::Receiver<()>>), K8sError>
    where
        K: Resource + Clone + Debug + Send + Sync + 'static + for<'de> serde::Deserialize<'de>,
        K::DynamicType: Default + std::hash::Hash + std::cmp::Eq + Clone,
    {
        if !is_required {
            let (reader, _) = reflector::store();
            return Ok((reader, None));
        }

        let resource_name = K::kind(&K::DynamicType::default()).to_string();
        match create_store::<K>(client.clone()).await {
            Ok((store, readiness_rx)) => Ok((store, Some(readiness_rx))),
            Err(e) => {
                if is_critical {
                    error!(
                        event.name = "k8s.reflector_create_failed",
                        k8s.resource.name = %resource_name,
                        error.message = %e,
                        "failed to create critical kubernetes resource reflector"
                    );
                    Err(K8sError::critical_reflector(resource_name, e))
                } else {
                    warn!(
                        event.name = "k8s.reflector_create_failed",
                        k8s.resource.name = %resource_name,
                        error.message = %e,
                        "failed to create non-critical reflector; continuing with empty store"
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
async fn create_store<K>(
    client: Client,
) -> Result<(reflector::Store<K>, oneshot::Receiver<()>), K8sError>
where
    K: Resource + Clone + Debug + Send + Sync + 'static + for<'de> serde::Deserialize<'de>,
    K::DynamicType: Default + std::hash::Hash + Eq + Clone,
{
    let resource_name = K::kind(&K::DynamicType::default()).to_string();
    let api: Api<K> = Api::all(client);

    // Fail fast if the API is unreachable.
    api.list(&ListParams::default().limit(1))
        .await
        .map_err(|e| K8sError::ResourceList {
            resource: resource_name.clone(),
            source: Box::new(e),
        })?;

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
                        debug!(
                            event.name = "k8s.reflector_synced",
                            k8s.resource.name = %resource_name,
                            "initial sync complete for kubernetes resource reflector"
                        );
                    }
                }
                Ok(None) => {
                    warn!(
                        event.name = "k8s.reflector_terminated",
                        k8s.resource.name = %resource_name,
                        "reflector stream has terminated unexpectedly"
                    );
                    break;
                }
                Err(e) => {
                    error!(
                        event.name = "k8s.reflector_error",
                        k8s.resource.name = %resource_name,
                        error.message = %e,
                        "reflector encountered an error; will retry"
                    );
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
    pub async fn from_flow_span(flow_span: &FlowSpan, decorator: &Decorator) -> Self {
        // Extract IPs and ports
        let (src_ip, dst_ip, port, protocol) = (
            flow_span.attributes.source_address,
            flow_span.attributes.destination_address,
            flow_span.attributes.destination_port,
            flow_span.attributes.network_transport,
        );

        // Resolve pods
        let src_pod = decorator.get_pod_by_ip(src_ip).await;
        let dst_pod = decorator.get_pod_by_ip(dst_ip).await;

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
pub struct Decorator {
    #[allow(dead_code)]
    pub client: Client,
    pub resource_store: ResourceStore,
    pub owner_relations_manager: OwnerRelationsManager,
    pub selector_relations_manager: Option<SelectorRelationsManager>,
    pub association_rules: HashMap<String, HashMap<String, AttributesConf>>,
    ip_index: Arc<RwLock<HashMap<String, Vec<K8sObjectMeta>>>>,
}

impl Decorator {
    /// Creates a new Decorator, initializing all resource reflectors concurrently.
    pub async fn new(
        health_state: HealthState,
        owner_relations_opts: Option<OwnerRelationsOptions>,
        selector_relations_opts: Option<Vec<SelectorRelationRule>>,
        conf: &Conf,
    ) -> Result<Self, K8sError> {
        let client = Client::try_default()
            .await
            .map_err(|e| K8sError::ClientInitialization(Box::new(e)))?;

        let mut required_kinds = HashSet::new();
        for provider_map in conf.attributes.values() {
            if let Some(k8s_conf) = provider_map.get("k8s") {
                let assoc = &k8s_conf.association;
                if assoc.pod.is_some() {
                    required_kinds.insert("pod".to_string());
                }
                if assoc.node.is_some() {
                    required_kinds.insert("node".to_string());
                }
                if assoc.service.is_some() {
                    required_kinds.insert("service".to_string());
                }
                if assoc.ingress.is_some() {
                    required_kinds.insert("ingress".to_string());
                }
                if assoc.endpointslice.is_some() {
                    required_kinds.insert("endpointslice".to_string());
                }
                if assoc.networkpolicy.is_some() {
                    required_kinds.insert("networkpolicy".to_string());
                }
            }
        }
        required_kinds.insert("deployment".to_string());
        required_kinds.insert("replicaset".to_string());
        required_kinds.insert("statefulset".to_string());
        required_kinds.insert("daemonset".to_string());
        required_kinds.insert("job".to_string());

        let resource_store =
            ResourceStore::new(client.clone(), health_state, &required_kinds).await?;

        // Use provided config or defaults
        let owner_relations_manager =
            OwnerRelationsManager::new(owner_relations_opts.unwrap_or_default());

        // Create selector relations manager if rules are provided
        // Note: If selector_relations is None or an empty list, no manager is created.
        // This is intentional - without rules, selector matching cannot function.
        // Both states effectively mean "selector relations disabled".
        let selector_relations_manager = selector_relations_opts
            .filter(|rules| !rules.is_empty())
            .map(SelectorRelationsManager::new);

        let ip_index = Arc::new(RwLock::new(HashMap::new()));
        update_ip_index(resource_store.clone(), ip_index.clone()).await;

        let resource_store_clone = resource_store.clone();
        let ip_index_clone = ip_index.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                update_ip_index(resource_store_clone.clone(), ip_index_clone.clone()).await;
            }
        });

        Ok(Self {
            client,
            resource_store,
            owner_relations_manager,
            selector_relations_manager,
            association_rules: conf.attributes.clone(),
            ip_index,
        })
    }

    /// Given a Pod object, returns all owners in the ownership chain, filtered according to
    /// the owner_relations configuration.
    ///
    /// Walks the chain up to max_depth and filters based on include/exclude rules.
    pub fn get_owners(&self, pod: &Pod) -> Option<Vec<WorkloadOwner>> {
        self.owner_relations_manager
            .get_owners(pod, &self.resource_store)
    }

    /// Given a Pod object, returns metadata for all resources that have selectors matching
    /// the pod's labels (e.g., NetworkPolicies, Services).
    ///
    /// Returns None if selector_relations is not configured or no matches are found.
    pub fn get_selector_based_metadata(&self, pod: &Pod) -> Option<Vec<K8sObjectMeta>> {
        let manager = self.selector_relations_manager.as_ref()?;
        let pod_labels = pod.labels();
        let pod_namespace = pod.namespace().unwrap_or_default();

        manager.get_related_resources(pod_labels, &pod_namespace, &self.resource_store)
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
    ) -> Result<Vec<Arc<NetworkPolicy>>, K8sError> {
        let applicable_policies = self.get_network_policies_for_pod(pod)?;

        Ok(applicable_policies
            .into_iter()
            .filter(|policy| self.policy_permits_flow(ctx, policy, direction))
            .collect())
    }

    /// Gets NetworkPolicies that apply to the given pod based on podSelector
    fn get_network_policies_for_pod(&self, pod: &Pod) -> Result<Vec<Arc<NetworkPolicy>>, K8sError> {
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
                debug!(
                    event.name = "k8s.cidr_parse_failed",
                    net.cidr = %cidr,
                    "failed to parse cidr string from networkpolicy"
                );
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

    /// Associates a flow span with Kubernetes objects based on the loaded configuration.
    /// Returns a map where keys are "source" and "destination" and values are lists of matched objects.
    pub async fn associate_flow(
        &self,
        flow_span: &FlowSpan,
    ) -> HashMap<String, Vec<K8sObjectMeta>> {
        let mut results = HashMap::new();
        let index = self.ip_index.read().await;

        let source_ip = flow_span.attributes.source_address.to_string();
        if let Some(source_candidates) = index.get(&source_ip) {
            let mut source_matches = Vec::new();
            for candidate_meta in source_candidates {
                if let Some(full_object_json) = self.get_full_object_as_json(candidate_meta) {
                    if self
                        .check_secondary_rules(
                            flow_span,
                            &full_object_json,
                            candidate_meta,
                            "source",
                        )
                        .await
                    {
                        source_matches.push(candidate_meta.clone());
                    }
                }
            }
            if !source_matches.is_empty() {
                results.insert("source".to_string(), source_matches);
            }
        }

        let dest_ip = flow_span.attributes.destination_address.to_string();
        if let Some(dest_candidates) = index.get(&dest_ip) {
            let mut dest_matches = Vec::new();
            for candidate_meta in dest_candidates {
                if let Some(full_object_json) = self.get_full_object_as_json(candidate_meta) {
                    if self
                        .check_secondary_rules(
                            flow_span,
                            &full_object_json,
                            candidate_meta,
                            "destination",
                        )
                        .await
                    {
                        dest_matches.push(candidate_meta.clone());
                    }
                }
            }
            if !dest_matches.is_empty() {
                results.insert("destination".to_string(), dest_matches);
            }
        }

        results
    }

    async fn check_secondary_rules(
        &self,
        flow_span: &FlowSpan,
        full_object_json: &Value,
        candidate: &K8sObjectMeta,
        direction: &str,
    ) -> bool {
        if let Some(providers) = self.association_rules.get(direction) {
            if let Some(k8s_conf) = providers.get("k8s") {
                let rule = match candidate.kind.as_str() {
                    "Pod" => k8s_conf.association.pod.as_ref(),
                    "Service" => k8s_conf.association.service.as_ref(),
                    "Node" => k8s_conf.association.node.as_ref(),
                    "Ingress" => k8s_conf.association.ingress.as_ref(),
                    "EndpointSlice" => k8s_conf.association.endpointslice.as_ref(),
                    "NetworkPolicy" => k8s_conf.association.networkpolicy.as_ref(),
                    "Gateway" => k8s_conf.association.gateway.as_ref(),
                    "Endpoint" => k8s_conf.association.endpoint.as_ref(),
                    _ => None,
                };

                if let Some(rule) = rule {
                    for source in &rule.sources {
                        if source.name.ends_with(".ip") {
                            continue;
                        }

                        let Some(flow_value) = get_flow_attribute(flow_span, &source.name) else {
                            return false;
                        };

                        let mut rule_matched = false;
                        for to_path in &source.to {
                            let k8s_values = extract_k8s_values(full_object_json, to_path);
                            if k8s_values.is_empty() {
                                continue;
                            }

                            if self.values_match(&flow_value, k8s_values, to_path).await {
                                rule_matched = true;
                                break;
                            }
                        }

                        if !rule_matched {
                            return false;
                        }
                    }
                }
            }
        }
        true
    }

    /// Given metadata, fetches the full Kubernetes object from the appropriate cache.
    /// Returns it as a generic serde_json::Value for easy inspection.
    fn get_full_object_as_json(&self, meta: &K8sObjectMeta) -> Option<Value> {
        macro_rules! get_from_store {
            ($store:expr) => {
                $store
                    .get(
                        &ObjectRef::new(&meta.name)
                            .within(meta.namespace.as_deref().unwrap_or_default()),
                    )
                    .and_then(|obj| to_value(obj.as_ref()).ok())
            };
        }

        match meta.kind.as_str() {
            "Pod" => get_from_store!(self.resource_store.pods),
            "Service" => get_from_store!(self.resource_store.services),
            "Node" => get_from_store!(self.resource_store.nodes),
            "Ingress" => get_from_store!(self.resource_store.ingresses),
            "EndpointSlice" => get_from_store!(self.resource_store.endpoint_slices),
            "NetworkPolicy" => get_from_store!(self.resource_store.network_policies),
            _ => None,
        }
    }

    /// The comparison engine. Checks if a flow value matches any of the K8s values,
    /// handling special logic based on the attribute path.
    async fn values_match(&self, flow_value: &str, k8s_values: Vec<&Value>, to_path: &str) -> bool {
        if to_path.ends_with("ipBlock.cidr") {
            let Ok(flow_ip) = flow_value.parse::<IpAddr>() else {
                return false;
            };
            for k8s_val in k8s_values {
                if let Some(cidr_str) = k8s_val.as_str() {
                    if let Ok(network) = cidr_str.parse::<IpNetwork>() {
                        if network.contains(flow_ip) {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        // Check for fields that might contain hostnames and require DNS resolution
        let resolve_dns = [
            "status.addresses",            // Used by Node, Gateway
            "spec.externalName",           // Used by Service
            "status.loadBalancer.ingress", // Used by Ingress
        ]
        .iter()
        .any(|p| to_path.contains(p));

        for k8s_val in k8s_values {
            if let Some(k8s_str) = k8s_val.as_str() {
                if k8s_str == flow_value {
                    return true;
                }

                if resolve_dns {
                    if let Ok(resolved_addrs) = lookup_host(format!("{k8s_str}:0")).await {
                        for addr in resolved_addrs {
                            if addr.ip().to_string() == flow_value {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }
}

/// Helper to retrieve an attribute value from a FlowSpan by its name.
fn get_flow_attribute(flow: &FlowSpan, attribute_name: &str) -> Option<String> {
    match attribute_name {
        "source.ip" => Some(flow.attributes.source_address.to_string()),
        "destination.ip" => Some(flow.attributes.destination_address.to_string()),
        "source.port" => Some(flow.attributes.source_port.to_string()),
        "destination.port" => Some(flow.attributes.destination_port.to_string()),
        "network.transport" => Some(flow.attributes.network_transport.to_string()),
        "network.type" => Some(
            if flow.attributes.source_address.is_ipv4() {
                "ipv4"
            } else {
                "ipv6"
            }
            .to_string(),
        ),
        _ => None,
    }
}

/// Extracts values from a serde_json::Value using a dot-notation path with wildcard support.
fn extract_k8s_values<'a>(object: &'a Value, path: &str) -> Vec<&'a Value> {
    let mut current_values = vec![object];
    let parts: Vec<&str> = path.split('.').collect();

    for part in parts {
        let mut next_values = Vec::new();
        if part == "[*]" {
            for val in current_values {
                if let Some(arr) = val.as_array() {
                    next_values.extend(arr.iter());
                }
            }
        } else {
            for val in current_values {
                if let Some(obj) = val.as_object() {
                    if let Some(v) = obj.get(part) {
                        next_values.push(v);
                    }
                }
            }
        }
        current_values = next_values;
    }
    current_values
}

/// Scans all relevant Kubernetes objects and builds a lookup map from IP to object metadata.
async fn update_ip_index(
    store: ResourceStore,
    index: Arc<RwLock<HashMap<String, Vec<K8sObjectMeta>>>>,
) {
    let mut new_index: HashMap<String, Vec<K8sObjectMeta>> = HashMap::new();

    // Index Pods
    for pod in store.pods.state().iter() {
        if let Some(status) = &pod.status {
            if let Some(ip) = &status.pod_ip {
                new_index
                    .entry(ip.clone())
                    .or_default()
                    .push(K8sObjectMeta::from(pod.as_ref()));
            }
            if let Some(ips) = &status.pod_ips {
                for pod_ip in ips {
                    new_index
                        .entry(pod_ip.ip.clone())
                        .or_default()
                        .push(K8sObjectMeta::from(pod.as_ref()));
                }
            }
        }
    }

    // Index Nodes
    for node in store.nodes.state().iter() {
        if let Some(status) = &node.status {
            if let Some(addresses) = &status.addresses {
                for addr in addresses {
                    new_index
                        .entry(addr.address.clone())
                        .or_default()
                        .push(K8sObjectMeta::from(node.as_ref()));
                }
            }
        }
    }

    // Index Services
    for service in store.services.state().iter() {
        if let Some(spec) = &service.spec {
            if let Some(ip) = &spec.cluster_ip {
                if *ip != "None" {
                    new_index
                        .entry(ip.clone())
                        .or_default()
                        .push(K8sObjectMeta::from(service.as_ref()));
                }
            }
            if let Some(ips) = &spec.cluster_ips {
                for ip in ips {
                    new_index
                        .entry(ip.clone())
                        .or_default()
                        .push(K8sObjectMeta::from(service.as_ref()));
                }
            }
        }
    }

    // Index Ingresses
    for ingress in store.ingresses.state().iter() {
        if let Some(status) = &ingress.status {
            if let Some(lb) = &status.load_balancer {
                if let Some(ingress_points) = &lb.ingress {
                    for point in ingress_points {
                        if let Some(ip) = &point.ip {
                            new_index
                                .entry(ip.clone())
                                .or_default()
                                .push(K8sObjectMeta::from(ingress.as_ref()));
                        }
                    }
                }
            }
        }
    }

    // Index EndpointSlices
    for slice in store.endpoint_slices.state().iter() {
        for endpoint in &slice.endpoints {
            for ip_addr_str in &endpoint.addresses {
                new_index
                    .entry(ip_addr_str.clone())
                    .or_default()
                    .push(K8sObjectMeta::from(slice.as_ref()));
            }
        }
    }

    let mut writer = index.write().await;
    *writer = new_index;

    debug!(
        event.name = "k8s.ip_index.updated",
        index.size = writer.len(),
        "ip to object index was updated"
    );
}

/// Flow direction for policy evaluation
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FlowDirection {
    Ingress,
    Egress,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;

    use super::*;
    use crate::{
        k8s::{
            owner_relations::OwnerRelationsOptions, selector_relations::SelectorRelationsManager,
        },
        runtime::conf::SelectorRelationRule,
    };

    /// Creates a test pod with the given name, labels, and owner references
    fn create_test_pod(
        name: &str,
        namespace: &str,
        labels: BTreeMap<String, String>,
        owner_refs: Option<Vec<OwnerReference>>,
    ) -> Pod {
        Pod {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                labels: Some(labels),
                owner_references: owner_refs,
                uid: Some(format!("{}-uid", name)),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Creates a test ReplicaSet that owns pods
    fn create_test_replicaset(
        name: &str,
        namespace: &str,
        selector_labels: BTreeMap<String, String>,
        owner_refs: Option<Vec<OwnerReference>>,
    ) -> ReplicaSet {
        ReplicaSet {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                owner_references: owner_refs,
                uid: Some(format!("{}-uid", name)),
                ..Default::default()
            },
            spec: Some(k8s_openapi::api::apps::v1::ReplicaSetSpec {
                selector: LabelSelector {
                    match_labels: Some(selector_labels),
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Creates a test Deployment that owns ReplicaSets
    fn create_test_deployment(
        name: &str,
        namespace: &str,
        selector_labels: BTreeMap<String, String>,
    ) -> Deployment {
        Deployment {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                uid: Some(format!("{}-uid", name)),
                ..Default::default()
            },
            spec: Some(k8s_openapi::api::apps::v1::DeploymentSpec {
                selector: LabelSelector {
                    match_labels: Some(selector_labels),
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Creates a test Service with a pod selector
    fn create_test_service(
        name: &str,
        namespace: &str,
        selector_labels: BTreeMap<String, String>,
    ) -> Service {
        Service {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                uid: Some(format!("{}-uid", name)),
                ..Default::default()
            },
            spec: Some(k8s_openapi::api::core::v1::ServiceSpec {
                selector: Some(selector_labels),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Creates a test NetworkPolicy with a pod selector
    fn create_test_network_policy(
        name: &str,
        namespace: &str,
        pod_selector_labels: BTreeMap<String, String>,
    ) -> NetworkPolicy {
        NetworkPolicy {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                uid: Some(format!("{}-uid", name)),
                ..Default::default()
            },
            spec: Some(k8s_openapi::api::networking::v1::NetworkPolicySpec {
                pod_selector: LabelSelector {
                    match_labels: Some(pod_selector_labels),
                    ..Default::default()
                },
                ..Default::default()
            }),
        }
    }

    /// High-level integration test that proves both owner relations and selector relations
    /// work together in the decoration pipeline.
    ///
    /// Test scenario:
    /// - Pod "web-pod" with labels {app: web, tier: frontend}
    /// - Owned by ReplicaSet "web-rs" which is owned by Deployment "web-deployment"
    /// - Selected by Service "web-service"
    /// - Selected by NetworkPolicy "web-policy"
    ///
    /// Expected results:
    /// - get_owners() should return [ReplicaSet, Deployment] (owner chain)
    /// - get_selector_based_metadata() should return [Service, NetworkPolicy] (selector matches)
    #[test]
    fn test_decoration_with_both_owner_and_selector_relations() {
        // Setup: Create test data
        let namespace = "default";
        let pod_labels = BTreeMap::from([
            ("app".to_string(), "web".to_string()),
            ("tier".to_string(), "frontend".to_string()),
        ]);

        // Create the ownership chain: Deployment -> ReplicaSet -> Pod
        let deployment = create_test_deployment("web-deployment", namespace, pod_labels.clone());

        let replicaset = create_test_replicaset(
            "web-rs",
            namespace,
            pod_labels.clone(),
            Some(vec![OwnerReference {
                api_version: "apps/v1".to_string(),
                kind: "Deployment".to_string(),
                name: "web-deployment".to_string(),
                uid: "web-deployment-uid".to_string(),
                ..Default::default()
            }]),
        );

        let pod = create_test_pod(
            "web-pod",
            namespace,
            pod_labels.clone(),
            Some(vec![OwnerReference {
                api_version: "apps/v1".to_string(),
                kind: "ReplicaSet".to_string(),
                name: "web-rs".to_string(),
                uid: "web-rs-uid".to_string(),
                ..Default::default()
            }]),
        );

        // Create resources that select the pod via labels
        let service = create_test_service("web-service", namespace, pod_labels.clone());
        let network_policy =
            create_test_network_policy("web-policy", namespace, pod_labels.clone());

        // Setup: Create ResourceStore with test data
        // Note: In a real implementation, we would populate actual reflector stores
        // For this test, we'll create a minimal ResourceStore and manually inject data
        let (deployments_store, mut deployments_writer) = reflector::store();
        deployments_writer.apply_watcher_event(&watcher::Event::Apply(deployment));

        let (replicasets_store, mut replicasets_writer) = reflector::store();
        replicasets_writer.apply_watcher_event(&watcher::Event::Apply(replicaset));

        let (pods_store, mut pods_writer) = reflector::store();
        pods_writer.apply_watcher_event(&watcher::Event::Apply(pod.clone()));

        let (services_store, mut services_writer) = reflector::store();
        services_writer.apply_watcher_event(&watcher::Event::Apply(service));

        let (network_policies_store, mut network_policies_writer) = reflector::store();
        network_policies_writer.apply_watcher_event(&watcher::Event::Apply(network_policy));

        // Create empty stores for other resource types
        let (nodes_store, _) = reflector::store::<Node>();
        let (namespaces_store, _) = reflector::store::<Namespace>();
        let (stateful_sets_store, _) = reflector::store::<StatefulSet>();
        let (daemon_sets_store, _) = reflector::store::<DaemonSet>();
        let (jobs_store, _) = reflector::store::<Job>();
        let (cron_jobs_store, _) = reflector::store::<CronJob>();
        let (ingresses_store, _) = reflector::store::<Ingress>();
        let (endpoint_slices_store, _) = reflector::store::<EndpointSlice>();

        let resource_store = ResourceStore {
            pods: pods_store,
            nodes: nodes_store,
            namespaces: namespaces_store,
            deployments: deployments_store,
            replica_sets: replicasets_store,
            stateful_sets: stateful_sets_store,
            daemon_sets: daemon_sets_store,
            jobs: jobs_store,
            cron_jobs: cron_jobs_store,
            services: services_store,
            ingresses: ingresses_store,
            endpoint_slices: endpoint_slices_store,
            network_policies: network_policies_store,
        };

        // Setup: Create OwnerRelationsManager with default config (include all)
        let owner_options = OwnerRelationsOptions {
            max_depth: 5,
            include_kinds: vec![], // Empty = include all
            exclude_kinds: vec![],
        };
        let owner_relations_manager = OwnerRelationsManager::new(owner_options);

        // Setup: Create SelectorRelationsManager with rules for Service and NetworkPolicy
        let selector_rules = vec![
            SelectorRelationRule {
                kind: "Service".to_string(),
                to: "Pod".to_string(),
                selector_match_labels_field: Some("spec.selector".to_string()),
                selector_match_expressions_field: None,
            },
            SelectorRelationRule {
                kind: "NetworkPolicy".to_string(),
                to: "Pod".to_string(),
                selector_match_labels_field: Some("spec.podSelector.matchLabels".to_string()),
                selector_match_expressions_field: Some(
                    "spec.podSelector.matchExpressions".to_string(),
                ),
            },
        ];
        let selector_relations_manager = Some(SelectorRelationsManager::new(selector_rules));

        // Setup: Create a mock Decorator (we can't use Decorator::new() as it's async and requires a real k8s client)
        // Instead, we'll manually construct the parts we need and test them directly

        // Test Owner Relations
        let owners = owner_relations_manager.get_owners(&pod, &resource_store);
        assert!(owners.is_some(), "Owner relations should return results");
        let owners = owners.unwrap();

        // Should have 2 owners: ReplicaSet and Deployment
        assert_eq!(
            owners.len(),
            2,
            "Expected 2 owners (ReplicaSet + Deployment), got {}",
            owners.len()
        );

        // Verify ReplicaSet owner
        let has_replicaset = owners
            .iter()
            .any(|o| matches!(o, WorkloadOwner::ReplicaSet(meta) if meta.name == "web-rs"));
        assert!(
            has_replicaset,
            "Owner chain should include ReplicaSet 'web-rs'"
        );

        // Verify Deployment owner
        let has_deployment = owners
            .iter()
            .any(|o| matches!(o, WorkloadOwner::Deployment(meta) if meta.name == "web-deployment"));
        assert!(
            has_deployment,
            "Owner chain should include Deployment 'web-deployment'"
        );

        // Test Selector Relations
        let selector_manager = selector_relations_manager.as_ref().unwrap();
        let pod_labels = pod.labels();
        let pod_namespace = pod.namespace().unwrap_or_default();

        let selector_matches =
            selector_manager.get_related_resources(pod_labels, &pod_namespace, &resource_store);

        assert!(
            selector_matches.is_some(),
            "Selector relations should return results"
        );
        let selector_matches = selector_matches.unwrap();

        // Should have 2 matches: Service and NetworkPolicy
        assert_eq!(
            selector_matches.len(),
            2,
            "Expected 2 selector matches (Service + NetworkPolicy), got {}",
            selector_matches.len()
        );

        // Verify Service match
        let has_service = selector_matches
            .iter()
            .any(|m| m.kind.to_lowercase() == "service" && m.name == "web-service");
        assert!(
            has_service,
            "Selector matches should include Service 'web-service'"
        );

        // Verify NetworkPolicy match
        let has_network_policy = selector_matches
            .iter()
            .any(|m| m.kind.to_lowercase() == "networkpolicy" && m.name == "web-policy");
        assert!(
            has_network_policy,
            "Selector matches should include NetworkPolicy 'web-policy'"
        );

        // Success! Both owner relations and selector relations worked correctly
        println!(
            "✓ Owner relations found: {:?}",
            owners
                .iter()
                .map(|o| match o {
                    WorkloadOwner::ReplicaSet(m) => format!("ReplicaSet/{}", m.name),
                    WorkloadOwner::Deployment(m) => format!("Deployment/{}", m.name),
                    WorkloadOwner::StatefulSet(m) => format!("StatefulSet/{}", m.name),
                    WorkloadOwner::DaemonSet(m) => format!("DaemonSet/{}", m.name),
                    WorkloadOwner::Job(m) => format!("Job/{}", m.name),
                    WorkloadOwner::CronJob(m) => format!("CronJob/{}", m.name),
                })
                .collect::<Vec<_>>()
        );

        println!(
            "✓ Selector relations found: {:?}",
            selector_matches
                .iter()
                .map(|m| format!("{}/{}", m.kind, m.name))
                .collect::<Vec<_>>()
        );
    }

    /// Test that proves custom field path extraction works with selector relations.
    /// This is essential for CRD support where selectors may be at non-standard locations.
    #[test]
    fn test_generic_field_path_extraction_with_custom_paths() {
        use serde_json::json;

        // Create a custom resource-like structure with a non-standard selector path
        let custom_resource = json!({
            "apiVersion": "example.com/v1",
            "kind": "CustomResource",
            "metadata": {
                "name": "custom-app",
                "namespace": "default"
            },
            "spec": {
                "application": {
                    "podSelector": {
                        "matchLabels": {
                            "app": "custom",
                            "version": "v1"
                        }
                    }
                }
            }
        });

        // Create a rule with custom field paths
        let selector_rules = vec![SelectorRelationRule {
            kind: "CustomResource".to_string(),
            to: "Pod".to_string(),
            // Note the non-standard path: spec.application.podSelector.matchLabels
            selector_match_labels_field: Some(
                "spec.application.podSelector.matchLabels".to_string(),
            ),
            selector_match_expressions_field: None,
        }];

        let manager = SelectorRelationsManager::new(selector_rules);

        // Extract selector using the generic method
        let extracted = manager.extract_selector_generic(&custom_resource, &manager.rules[0]);

        assert!(
            extracted.is_some(),
            "Generic extraction should find selector at custom path"
        );

        let selector = extracted.unwrap();
        assert!(selector.match_labels.is_some());

        let match_labels = selector.match_labels.as_ref().unwrap();
        assert_eq!(
            match_labels.get("app"),
            Some(&"custom".to_string()),
            "Should extract 'app' label from custom path"
        );
        assert_eq!(
            match_labels.get("version"),
            Some(&"v1".to_string()),
            "Should extract 'version' label from custom path"
        );

        // Verify the selector works for matching
        let pod_labels = BTreeMap::from([
            ("app".to_string(), "custom".to_string()),
            ("version".to_string(), "v1".to_string()),
        ]);

        assert!(
            manager.selector_matches(&selector, &pod_labels),
            "Extracted selector should match pod labels"
        );

        // Verify non-matching labels don't match
        let wrong_labels = BTreeMap::from([
            ("app".to_string(), "other".to_string()),
            ("version".to_string(), "v1".to_string()),
        ]);

        assert!(
            !manager.selector_matches(&selector, &wrong_labels),
            "Extracted selector should not match wrong labels"
        );

        println!("✓ Generic field path extraction works with custom paths for CRD-like resources");
    }
}
