//! attributor.rs - Kubernetes client and resource management
//!
//! This module provides a high-level, concurrent, and ergonomic interface for
//! interacting with Kubernetes resources. It features:
//! - A ResourceStore for concurrent initialization and caching of resource reflectors.
//! - A high-level Decorator client for querying and correlating resources.
//! - Support for Pods, Nodes, key workload types (Deployments, StatefulSets, etc.).
//! - Network-related resources like Services, Ingresses and NetworkPolicies.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Debug,
    net::IpAddr,
    sync::{Arc, atomic::Ordering},
};

use dashmap::DashMap;
use futures::{StreamExt, TryStreamExt};
use ip_network::IpNetwork;
use jsonpath_rust::JsonPath;
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
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    net::lookup_host,
    sync::oneshot,
    time::{Duration, timeout},
};
use tracing::{debug, error, trace, warn};

use crate::{
    health::HealthState,
    k8s::{
        K8sError,
        owner_relations::{OwnerRelationsManager, OwnerRelationsRules},
        selector::ResourceFilter,
        selector_relations::{SelectorRelationRule, SelectorRelationsManager},
    },
    metrics::{self, cleanup::MetricCleanupTracker},
    runtime::{self, conf::Conf, memory::ShrinkPolicy},
    span::flow::FlowSpan,
};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
/// Defines the configuration for associating network flows with Kubernetes objects.
pub struct AttributesOptions {
    /// Defines metadata to extract from all Kubernetes objects.
    pub extract: Extract,
    /// Defines rules for mapping flow attributes to Kubernetes object attributes.
    pub association: AssociationBlock,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
/// Configuration for metadata extraction from Kubernetes objects.
pub struct Extract {
    /// A list of metadata fields to extract.
    pub metadata: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
/// Defines association rules for different Kubernetes object kinds.
pub struct AssociationBlock {
    #[serde(default)]
    pub pod: Option<ObjectAssociationRule>,
    #[serde(default)]
    pub node: Option<ObjectAssociationRule>,
    #[serde(default)]
    pub service: Option<ObjectAssociationRule>,
    #[serde(default)]
    pub networkpolicy: Option<ObjectAssociationRule>,
    #[serde(default)]
    pub endpoint: Option<ObjectAssociationRule>,
    #[serde(default)]
    pub endpointslice: Option<ObjectAssociationRule>,
    #[serde(default)]
    pub ingress: Option<ObjectAssociationRule>,
    #[serde(default)]
    pub gateway: Option<ObjectAssociationRule>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
/// Represents the association rules for a specific Kubernetes object kind.
pub struct ObjectAssociationRule {
    /// A list of sources to match against for association.
    pub sources: Vec<AssociationSource>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
/// Defines a single association rule mapping a flow attribute to Kubernetes object fields.
pub struct AssociationSource {
    /// The origin of the attribute (e.g., "flow").
    pub from: String,
    /// The specific attribute name (e.g., "source.ip").
    pub name: String,
    /// A list of Kubernetes object fields to match against.
    pub to: Vec<String>,
}

/// Creates the default Kubernetes attribution configuration.
/// This enables pod, service, and node enrichment out-of-the-box.
pub fn default_attributes() -> HashMap<String, HashMap<String, AttributesOptions>> {
    let src_mapping = create_k8s_attributes_mapping("source");
    let dst_mapping = create_k8s_attributes_mapping("destination");

    HashMap::from([
        (
            "source".to_string(),
            HashMap::from([("k8s".to_string(), src_mapping)]),
        ),
        (
            "destination".to_string(),
            HashMap::from([("k8s".to_string(), dst_mapping)]),
        ),
    ])
}

/// Helper to create an `AttributesConf` for a given flow direction ("source" or "destination").
fn create_k8s_attributes_mapping(direction: &str) -> AttributesOptions {
    let ip_attr_name = format!("{direction}.ip");
    let port_attr_name = format!("{direction}.port");

    AttributesOptions {
        extract: Extract {
            metadata: vec![
                "[*].metadata.name".to_string(),
                "[*].metadata.namespace".to_string(),
                "[*].metadata.uid".to_string(),
            ],
        },
        association: AssociationBlock {
            pod: Some(ObjectAssociationRule {
                sources: vec![
                    AssociationSource {
                        from: "flow".to_string(),
                        name: ip_attr_name.clone(),
                        to: vec![
                            "status.podIP".to_string(),
                            "status.podIPs[*]".to_string(),
                            "status.hostIP".to_string(),
                            "status.hostIPs[*]".to_string(),
                        ],
                    },
                    AssociationSource {
                        from: "flow".to_string(),
                        name: port_attr_name.clone(),
                        to: vec![
                            "spec.containers[*].ports[*].containerPort".to_string(),
                            "spec.containers[*].ports[*].hostPort".to_string(),
                        ],
                    },
                    AssociationSource {
                        from: "flow".to_string(),
                        name: "network.transport".to_string(),
                        to: vec!["spec.containers[*].ports[*].protocol".to_string()],
                    },
                ],
            }),
            service: Some(ObjectAssociationRule {
                sources: vec![
                    AssociationSource {
                        from: "flow".to_string(),
                        name: ip_attr_name.clone(),
                        to: vec![
                            "spec.clusterIP".to_string(),
                            "spec.clusterIPs[*]".to_string(),
                            "spec.externalIPs[*]".to_string(),
                            "spec.loadBalancerIP".to_string(),
                        ],
                    },
                    AssociationSource {
                        from: "flow".to_string(),
                        name: port_attr_name.clone(),
                        to: vec!["spec.ports[*].port".to_string()],
                    },
                    AssociationSource {
                        from: "flow".to_string(),
                        name: "network.transport".to_string(),
                        to: vec!["spec.ports[*].protocol".to_string()],
                    },
                ],
            }),
            node: Some(ObjectAssociationRule {
                sources: vec![AssociationSource {
                    from: "flow".to_string(),
                    name: ip_attr_name.clone(),
                    to: vec!["status.addresses[*].address".to_string()],
                }],
            }),
            endpoint: Some(ObjectAssociationRule {
                sources: vec![AssociationSource {
                    from: "flow".to_string(),
                    name: ip_attr_name,
                    to: vec!["endpoints[*].addresses[*]".to_string()],
                }],
            }),
            ..Default::default()
        },
    }
}

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
        ip_index: Arc<DashMap<String, Vec<K8sObjectMeta>>>,
        conf: &Conf,
        cleanup_tracker: Option<MetricCleanupTracker>,
    ) -> Result<Self, K8sError> {
        let mut readiness_handles = Vec::new();

        /// Creates a REQUIRED resource store.
        /// This will always attempt creation, and failure is a fatal error.
        macro_rules! create_required_store {
            ($type:ty, $condition:expr) => {{
                let (store, rx) = Self::create_resource_store::<$type>(&client, $condition).await?;
                readiness_handles.extend(rx);
                store
            }};
        }

        /// Creates an OPTIONAL resource store.
        /// This creates the store only if its kind is listed in `required_kinds`.
        /// Failure to create the store results in a warning, not a fatal error.
        macro_rules! create_optional_store {
            ($kind:literal, $condition:expr, $type:ty) => {{
                if required_kinds.contains($kind) {
                    create_required_store!($type, $condition)
                } else {
                    let (store, _writer) = reflector::store();
                    store
                }
            }};
        }

        // Critical stores
        let pods = create_required_store!(Pod, true);
        let namespaces = create_required_store!(Namespace, true);

        // Dynamic Stores
        let nodes = create_optional_store!("node", false, Node);
        let deployments = create_optional_store!("deployment", false, Deployment);
        let replica_sets = create_optional_store!("replicaset", false, ReplicaSet);
        let stateful_sets = create_optional_store!("statefulset", false, StatefulSet);
        let daemon_sets = create_optional_store!("daemonset", false, DaemonSet);
        let jobs = create_optional_store!("job", false, Job);
        let cron_jobs = create_optional_store!("cronjob", false, CronJob);
        let services = create_optional_store!("service", false, Service);
        let ingresses = create_optional_store!("ingress", false, Ingress);
        let endpoint_slices = create_optional_store!("endpointslice", false, EndpointSlice);
        let network_policies = create_optional_store!("networkpolicy", false, NetworkPolicy);

        let store = Self {
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
        };

        // Wait for all *started* reflectors to sync with timeout
        let timeout_secs = conf
            .discovery
            .informer
            .as_ref()
            .and_then(|i| i.k8s.as_ref())
            .map(|k| k.informers_sync_timeout.as_secs())
            .unwrap_or(30u64);

        match timeout(
            Duration::from_secs(timeout_secs),
            futures::future::join_all(readiness_handles),
        )
        .await
        {
            Ok(_) => {
                debug!(
                    event.name = "k8s.reflector.all_synced",
                    timeout_secs = timeout_secs,
                    "all active kubernetes resource reflectors have synced"
                );
            }
            Err(_) => {
                return Err(K8sError::Attribution(format!(
                    "kubernetes cache sync timed out after {timeout_secs}s - increase informers_sync_timeout if needed",
                )));
            }
        }

        debug!(
            event.name = "k8s.ip_index.initial_build",
            "caches synced, performing initial ip index build"
        );
        update_ip_index(&store, &ip_index, conf).await;

        let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();

        let store_clone = store.clone();
        let ip_index_clone = ip_index.clone();
        let conf_clone = conf.clone();
        tokio::spawn(async move {
            // Debounce rapid changes (e.g., rolling updates, Node status updates) to avoid excessive rebuilds
            // Use 1 second debounce to prevent death spiral from frequent Node heartbeat events
            let mut debounce_timer = tokio::time::interval(Duration::from_secs(1));
            debounce_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut pending_update = false;

            loop {
                tokio::select! {
                    Some(_) = event_rx.recv() => {
                        pending_update = true;
                    }
                    _ = debounce_timer.tick() => {
                        if pending_update {
                            let timer = metrics::registry::K8S_IP_INDEX_UPDATE_DURATION_SECONDS.start_timer();
                            update_ip_index(&store_clone, &ip_index_clone, &conf_clone).await;
                            timer.observe_duration();
                            metrics::registry::K8S_IP_INDEX_UPDATES_TOTAL.inc();
                            pending_update = false;
                            trace!(
                                event.name = "k8s.ip_index.updated",
                                "IP index rebuilt due to K8s resource changes"
                            );
                        }
                    }
                }
            }
        });

        // Spawn watchers for resources that have IP addresses
        // These will trigger IP index rebuilds ONLY when IPs actually change (not on status-only updates)
        spawn_ip_resource_watcher::<Pod, _>(
            client.clone(),
            event_tx.clone(),
            extract_pod_ips,
            cleanup_tracker.clone(),
        );
        spawn_ip_resource_watcher::<Node, _>(
            client.clone(),
            event_tx.clone(),
            extract_node_ips,
            cleanup_tracker.clone(),
        );
        spawn_ip_resource_watcher::<Service, _>(
            client.clone(),
            event_tx.clone(),
            extract_service_ips,
            cleanup_tracker.clone(),
        );
        spawn_ip_resource_watcher::<Ingress, _>(
            client.clone(),
            event_tx.clone(),
            extract_ingress_ips,
            cleanup_tracker.clone(),
        );
        spawn_ip_resource_watcher::<EndpointSlice, _>(
            client.clone(),
            event_tx,
            extract_endpointslice_ips,
            cleanup_tracker,
        );

        health_state
            .k8s_caches_synced
            .store(true, Ordering::Relaxed);

        Ok(store)
    }

    /// Helper to create a store for a resource, handling failures gracefully.
    async fn create_resource_store<K>(
        client: &Client,
        is_critical: bool,
    ) -> Result<(reflector::Store<K>, Option<oneshot::Receiver<()>>), K8sError>
    where
        K: Resource + Clone + Debug + Send + Sync + 'static + for<'de> serde::Deserialize<'de>,
        K::DynamicType: Default + std::hash::Hash + std::cmp::Eq + Clone,
    {
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
    pub owner_relations_manager: OwnerRelationsManager,
    pub selector_relations_manager: Option<SelectorRelationsManager>,
    pub filter: ResourceFilter,
    ip_index: Arc<DashMap<String, Vec<K8sObjectMeta>>>,
}

impl Attributor {
    /// Creates a new Decorator, initializing all resource reflectors concurrently.
    pub async fn new(
        health_state: HealthState,
        owner_relations_opts: Option<OwnerRelationsRules>,
        selector_relations_opts: Option<Vec<SelectorRelationRule>>,
        conf: &Conf,
        cleanup_tracker: Option<MetricCleanupTracker>,
    ) -> Result<Self, K8sError> {
        let client = Client::try_default()
            .await
            .map_err(|e| K8sError::ClientInitialization(Box::new(e)))?;
        let selectors = conf
            .discovery
            .informer
            .as_ref()
            .and_then(|i| i.k8s.as_ref())
            .map(|k| k.selectors.clone())
            .unwrap_or_default();
        let filter = ResourceFilter::new(selectors);

        let mut required_kinds = HashSet::new();
        if let Some(attributes_map) = &conf.attributes {
            for provider_map in attributes_map.values() {
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
        }
        required_kinds.insert("deployment".to_string());
        required_kinds.insert("replicaset".to_string());
        required_kinds.insert("statefulset".to_string());
        required_kinds.insert("daemonset".to_string());
        required_kinds.insert("job".to_string());
        required_kinds.insert("cronjob".to_string());

        let ip_index = Arc::new(DashMap::with_capacity(
            runtime::memory::initial_capacity::K8S_IP_INDEX,
        ));
        let resource_store = ResourceStore::new(
            client.clone(),
            health_state,
            &required_kinds,
            ip_index.clone(),
            conf,
            cleanup_tracker,
        )
        .await?;

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

        Ok(Self {
            client,
            resource_store,
            owner_relations_manager,
            selector_relations_manager,
            filter,
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

    /// A generic helper to find the first object of a specific kind for a given IP.
    /// This is the new internal engine that uses the IP index.
    async fn get_objects_by_ip<K>(&self, ip: IpAddr) -> Vec<Arc<K>>
    where
        K: Resource<DynamicType = ()> + Clone + 'static,
        ResourceStore: HasStore<K>,
    {
        let ip_str = ip.to_string();
        let mut results = Vec::new();

        if let Some(entry) = self.ip_index.get(&ip_str) {
            let candidates = entry.value();
            let store = self.resource_store.store();

            for meta in candidates {
                if meta.kind == K::kind(&()) {
                    let key = ObjectRef::new(&meta.name)
                        .within(meta.namespace.as_deref().unwrap_or_default());
                    if let Some(obj) = store.get(&key) {
                        if self.filter.is_allowed(obj.as_ref()) {
                            results.push(obj);
                        } else {
                            debug!(
                                event.name = "k8s.attributor.filtered",
                                k8s.kind = %meta.kind,
                                k8s.name = %meta.name,
                                "resource found but excluded by selector configuration"
                            );
                        }
                    }
                }
            }
        }
        results
    }

    /// Looks up a Pod by its IP address.
    pub async fn get_pod_by_ip(&self, ip: IpAddr) -> Option<Arc<Pod>> {
        self.get_objects_by_ip(ip).await.into_iter().next()
    }

    pub async fn get_node_by_ip(&self, ip: IpAddr) -> Option<Arc<Node>> {
        self.get_objects_by_ip(ip).await.into_iter().next()
    }

    /// Looks up a Service by an IP address.
    ///
    /// This method checks against the following fields:
    /// - `spec.cluster_ip` and `spec.cluster_ips`
    /// - `spec.external_ips`
    /// - `spec.load_balancer_ip` (a user-requested IP)
    /// - `status.load_balancer.ingress` (the actual provisioned IPs)
    pub async fn get_service_by_ip(&self, ip: IpAddr) -> Option<Arc<Service>> {
        self.get_objects_by_ip(ip).await.into_iter().next()
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
        self.get_objects_by_ip(ip).await.into_iter().next()
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
}

/// Extracts string values from a Kubernetes resource using a JSONPath-like expression.
///
/// This function serializes the resource to a serde_json::Value and then applies
/// the path expression to find and return all matching string values.
fn extract_values_from_resource<K: serde::Serialize>(
    resource: &K,
    path: &str,
) -> Result<Vec<String>, K8sError> {
    let full_path = format!("$.{path}");

    let json_value = serde_json::to_value(resource)
        .map_err(|e| K8sError::Attribution(format!("failed to serialize resource to json: {e}")))?;

    let found_values: Vec<&Value> = json_value.query(&full_path).map_err(|e| {
        K8sError::Attribution(format!(
            "invalid jsonpath expression '{full_path}' during value extraction: {e}"
        ))
    })?;

    let results = found_values
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    Ok(results)
}

/// (private helper) Resolves a hostname and adds all resulting IPs to the index.
async fn index_hostname(
    new_index: &mut HashMap<String, Vec<K8sObjectMeta>>,
    hostname: &str,
    meta: &K8sObjectMeta,
) {
    if let Ok(resolved_addrs) = lookup_host(format!("{hostname}:0")).await {
        for resolved in resolved_addrs {
            new_index
                .entry(resolved.ip().to_string())
                .or_default()
                .push(meta.clone());
        }
    }
}

/// (private helper) Adds an IP address and metadata to the index.
fn add_to_index(index: &mut HashMap<String, Vec<K8sObjectMeta>>, ip: &str, meta: &K8sObjectMeta) {
    index.entry(ip.to_string()).or_default().push(meta.clone());
}

async fn index_resource_by_ip<K>(
    store: &ResourceStore,
    new_index: &mut HashMap<String, Vec<K8sObjectMeta>>,
    association_rule: &ObjectAssociationRule,
) where
    K: Resource<DynamicType = ()> + Clone + serde::Serialize + 'static,
    ResourceStore: HasStore<K>,
{
    let ip_source = association_rule
        .sources
        .iter()
        .find(|s| s.from == "flow" && (s.name == "source.ip" || s.name == "destination.ip"));

    if let Some(source) = ip_source {
        for resource in store.store().state() {
            let meta = K8sObjectMeta::from(resource.as_ref());

            for path in &source.to {
                match extract_values_from_resource(resource.as_ref(), path) {
                    Ok(values) => {
                        for value in values {
                            if path.contains("hostname") || path.contains("externalName") {
                                index_hostname(new_index, &value, &meta).await;
                            } else {
                                add_to_index(new_index, &value, &meta);
                            }
                        }
                    }
                    Err(e) => {
                        debug!(
                            event.name = "k8s.decorator.value_extraction_failed",
                            k8s.jsonpath.expression = %path,
                            error.message = %e,
                            "failed to extract values for configured jsonpath"
                        );
                    }
                }
            }
        }
    }
}

/// Extracts IP addresses from a Pod resource
fn extract_pod_ips(pod: &Pod) -> HashSet<String> {
    let mut ips = HashSet::new();
    if let Some(status) = &pod.status {
        if let Some(pod_ip) = &status.pod_ip {
            ips.insert(pod_ip.clone());
        }
        if let Some(pod_ips) = &status.pod_ips {
            for pod_ip_info in pod_ips {
                ips.insert(pod_ip_info.ip.clone());
            }
        }
    }
    ips
}

/// Extracts IP addresses from a Node resource
fn extract_node_ips(node: &Node) -> HashSet<String> {
    let mut ips = HashSet::new();
    if let Some(status) = &node.status
        && let Some(addresses) = &status.addresses
    {
        for addr in addresses {
            if addr.type_ == "InternalIP" || addr.type_ == "ExternalIP" {
                ips.insert(addr.address.clone());
            }
        }
    }
    ips
}

/// Extracts IP addresses from a Service resource
fn extract_service_ips(service: &Service) -> HashSet<String> {
    let mut ips = HashSet::new();
    if let Some(spec) = &service.spec {
        if let Some(cluster_ip) = &spec.cluster_ip
            && cluster_ip != "None"
        {
            ips.insert(cluster_ip.clone());
        }
        if let Some(cluster_ips) = &spec.cluster_ips {
            for ip in cluster_ips {
                if ip != "None" {
                    ips.insert(ip.clone());
                }
            }
        }
        if let Some(external_ips) = &spec.external_ips {
            for ip in external_ips {
                ips.insert(ip.clone());
            }
        }
    }
    if let Some(status) = &service.status
        && let Some(load_balancer) = &status.load_balancer
        && let Some(ingress_list) = &load_balancer.ingress
    {
        for ingress in ingress_list {
            if let Some(ip) = &ingress.ip {
                ips.insert(ip.clone());
            }
        }
    }
    ips
}

/// Extracts IP addresses from an Ingress resource
fn extract_ingress_ips(ingress: &Ingress) -> HashSet<String> {
    let mut ips = HashSet::new();
    if let Some(status) = &ingress.status
        && let Some(load_balancer) = &status.load_balancer
        && let Some(ingress_list) = &load_balancer.ingress
    {
        for ing in ingress_list {
            if let Some(ip) = &ing.ip {
                ips.insert(ip.clone());
            }
        }
    }
    ips
}

/// Extracts IP addresses from an EndpointSlice resource
fn extract_endpointslice_ips(endpoint_slice: &EndpointSlice) -> HashSet<String> {
    let mut ips = HashSet::new();
    for endpoint in &endpoint_slice.endpoints {
        for address in &endpoint.addresses {
            ips.insert(address.clone());
        }
    }
    ips
}

/// Spawns a watcher for a Kubernetes resource that triggers IP index updates only when IPs change.
///
/// This uses the K8s watch API to receive real-time events when resources are created,
/// updated, or deleted. The watcher automatically handles reconnection and error recovery.
///
/// **Smart IP Change Detection:**
/// - Caches IP addresses for each resource
/// - Compares current vs previous IPs on Apply events
/// - Only triggers rebuild if IPs actually changed
/// - Drastically reduces unnecessary rebuilds from status-only updates (e.g. Node heartbeats)
///
/// # Arguments
/// * `client` - Kubernetes client
/// * `event_tx` - Channel to send trigger events for IP index rebuilds
/// * `extract_ips` - Function to extract IP addresses from the resource
///
/// # Resource Types
/// This should only be used for resources that contain IP addresses:
/// - Pod (pod IPs)
/// - Node (node IPs)
/// - Service (cluster IPs, external IPs)
/// - Ingress (load balancer IPs)
/// - EndpointSlice (endpoint IPs)
fn spawn_ip_resource_watcher<K, F>(
    client: Client,
    event_tx: tokio::sync::mpsc::UnboundedSender<()>,
    extract_ips: F,
    cleanup_tracker: Option<MetricCleanupTracker>,
) where
    K: Resource + Clone + Debug + Send + 'static + for<'de> serde::Deserialize<'de>,
    K::DynamicType: Default,
    F: Fn(&K) -> HashSet<String> + Send + 'static,
{
    tokio::spawn(async move {
        let resource_name = K::kind(&K::DynamicType::default()).to_string();
        let api = Api::<K>::all(client);

        // Cache of resource UID -> IP addresses for smart change detection
        let ip_cache: DashMap<String, HashSet<String>> =
            DashMap::with_capacity(runtime::memory::initial_capacity::K8S_WATCHER_CACHE);
        let k8s_shrink_policy = ShrinkPolicy::k8s_cache();

        loop {
            debug!(
                event.name = "k8s.watcher.starting",
                k8s.resource.name = %resource_name,
                "Starting K8s resource watcher for IP index updates"
            );

            let watcher_config = watcher::Config::default();
            let mut stream = watcher(api.clone(), watcher_config).boxed();

            while let Some(event) = stream.next().await {
                match event {
                    Ok(watcher::Event::Apply(obj)) => {
                        metrics::registry::K8S_WATCHER_EVENTS_TOTAL
                            .with_label_values(&["apply"])
                            .inc();
                        if metrics::registry::debug_enabled() {
                            metrics::registry::K8S_WATCHER_EVENTS_BY_RESOURCE_TOTAL
                                .with_label_values(&[&resource_name, "apply"])
                                .inc();
                        }

                        // Extract current IPs from this resource
                        let current_ips = extract_ips(&obj);
                        let uid = obj.meta().uid.clone().unwrap_or_default();

                        // Compare with cached IPs to detect if IPs actually changed
                        let ips_changed = if let Some(cached_entry) = ip_cache.get(&uid) {
                            let cached_ips = cached_entry.value();
                            cached_ips != &current_ips
                        } else {
                            // New resource, IPs definitely changed (from none to some)
                            !current_ips.is_empty()
                        };

                        if ips_changed {
                            // Update cache with new IPs
                            ip_cache.insert(uid.clone(), current_ips.clone());

                            // Trigger IP index rebuild
                            if event_tx.send(()).is_err() {
                                warn!(
                                    event.name = "k8s.watcher.channel_closed",
                                    k8s.resource.name = %resource_name,
                                    "IP index update channel closed, stopping watcher"
                                );
                                return;
                            }
                            trace!(
                                event.name = "k8s.watcher.ip_changed",
                                k8s.resource.name = %resource_name,
                                k8s.resource.object = ?obj.meta().name,
                                k8s.resource.uid = %uid,
                                old_ip_count = current_ips.len(),
                                "Resource IPs changed, triggering IP index update"
                            );
                        } else {
                            trace!(
                                event.name = "k8s.watcher.ip_unchanged",
                                k8s.resource.name = %resource_name,
                                k8s.resource.object = ?obj.meta().name,
                                "Resource updated but IPs unchanged, skipping rebuild"
                            );
                        }
                    }
                    Ok(watcher::Event::Delete(obj)) => {
                        metrics::registry::K8S_WATCHER_EVENTS_TOTAL
                            .with_label_values(&["delete"])
                            .inc();
                        if metrics::registry::debug_enabled() {
                            metrics::registry::K8S_WATCHER_EVENTS_BY_RESOURCE_TOTAL
                                .with_label_values(&[&resource_name, "delete"])
                                .inc();
                        }

                        // Remove from cache and trigger rebuild since IPs are being removed
                        let uid = obj.meta().uid.clone().unwrap_or_default();
                        ip_cache.remove(&uid);

                        // Schedule cleanup of metrics for this resource
                        if let Some(ref tracker) = cleanup_tracker {
                            tracker.schedule_k8s_cleanup(resource_name.clone());
                        }

                        // Shrink ip_cache capacity if it's significantly oversized.
                        // This prevents capacity retention when many K8s resources are deleted
                        // (e.g., during scale-down, pod churn, or cluster drain).
                        let cache_capacity = ip_cache.capacity();
                        let cache_len = ip_cache.len();
                        if k8s_shrink_policy.should_shrink(cache_capacity, cache_len) {
                            ip_cache.shrink_to_fit();
                        }

                        if event_tx.send(()).is_err() {
                            warn!(
                                event.name = "k8s.watcher.channel_closed",
                                k8s.resource.name = %resource_name,
                                "IP index update channel closed, stopping watcher"
                            );
                            return;
                        }
                        trace!(
                            event.name = "k8s.watcher.event",
                            k8s.resource.name = %resource_name,
                            k8s.resource.object = ?obj.meta().name,
                            k8s.resource.uid = %uid,
                            event_type = "delete",
                            "Resource deleted, triggering IP index update"
                        );
                    }
                    Ok(watcher::Event::Init) => {
                        metrics::registry::K8S_WATCHER_EVENTS_TOTAL
                            .with_label_values(&["init"])
                            .inc();
                        if metrics::registry::debug_enabled() {
                            metrics::registry::K8S_WATCHER_EVENTS_BY_RESOURCE_TOTAL
                                .with_label_values(&[&resource_name, "init"])
                                .inc();
                        }

                        debug!(
                            event.name = "k8s.watcher.init",
                            k8s.resource.name = %resource_name,
                            "K8s watcher initialization started"
                        );
                    }
                    Ok(watcher::Event::InitApply(_)) => {
                        trace!(
                            event.name = "k8s.watcher.init_apply",
                            k8s.resource.name = %resource_name,
                            "K8s watcher loading initial object"
                        );
                    }
                    Ok(watcher::Event::InitDone) => {
                        metrics::registry::K8S_WATCHER_EVENTS_TOTAL
                            .with_label_values(&["init_done"])
                            .inc();
                        if metrics::registry::debug_enabled() {
                            metrics::registry::K8S_WATCHER_EVENTS_BY_RESOURCE_TOTAL
                                .with_label_values(&[&resource_name, "init_done"])
                                .inc();
                        }

                        if event_tx.send(()).is_err() {
                            return;
                        }
                        debug!(
                            event.name = "k8s.watcher.init_done",
                            k8s.resource.name = %resource_name,
                            "K8s watcher initialization complete, triggering IP index update"
                        );
                    }
                    Err(e) => {
                        metrics::registry::K8S_WATCHER_ERRORS_TOTAL.inc();
                        if metrics::registry::debug_enabled() {
                            metrics::registry::K8S_WATCHER_ERRORS_BY_RESOURCE_TOTAL
                                .with_label_values(&[&resource_name])
                                .inc();
                        }

                        error!(
                            event.name = "k8s.watcher.error",
                            error.message = %e,
                            k8s.resource.name = %resource_name,
                            "K8s watcher error, will retry"
                        );
                        break;
                    }
                }
            }

            warn!(
                event.name = "k8s.watcher.reconnecting",
                k8s.resource.name = %resource_name,
                "K8s watcher disconnected, reconnecting in 5s"
            );
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

/// Scans all relevant Kubernetes objects and builds a lookup map from IP to object metadata.
/// This is triggered by resource changes for real-time accuracy.
async fn update_ip_index(
    store: &ResourceStore,
    index: &Arc<DashMap<String, Vec<K8sObjectMeta>>>,
    conf: &Conf,
) {
    let mut new_index = HashMap::new();

    if let Some(k8s_conf) = conf
        .attributes
        .as_ref()
        .and_then(|attributes_map| attributes_map.values().find_map(|p| p.get("k8s")))
    {
        let assoc = &k8s_conf.association;

        if let Some(rule) = &assoc.pod {
            index_resource_by_ip::<Pod>(store, &mut new_index, rule).await;
        }
        if let Some(rule) = &assoc.node {
            index_resource_by_ip::<Node>(store, &mut new_index, rule).await;
        }
        if let Some(rule) = &assoc.service {
            index_resource_by_ip::<Service>(store, &mut new_index, rule).await;
        }
        if let Some(rule) = &assoc.ingress {
            index_resource_by_ip::<Ingress>(store, &mut new_index, rule).await;
        }
        if let Some(rule) = &assoc.endpointslice {
            index_resource_by_ip::<EndpointSlice>(store, &mut new_index, rule).await;
        }
    }

    index.clear();
    for (ip, metas) in new_index {
        index.insert(ip, metas);
    }

    // Shrink capacity after rebuild to release excess memory.
    // The clear() above removes entries but retains capacity, which can
    // cause memory bloat in large clusters where the IP index size fluctuates.
    index.shrink_to_fit();

    trace!(
        event.name = "k8s.ip_index.updated",
        index.size = index.len(),
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
    use crate::k8s::{
        owner_relations::OwnerRelationsRules, selector_relations::SelectorRelationRule,
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
        let owner_options = OwnerRelationsRules {
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
