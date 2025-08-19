// k8s.rs - Kubernetes client and resource management
//
// This module provides a high-level, concurrent, and ergonomic interface for
// interacting with Kubernetes resources. It features:
// - A concurrent AppStoreBuilder for fast, parallel initialization of reflectors.
// - A generic `HasStore` trait for type-safe access to resource caches.
// - A high-level KubeClient for performing queries against the cached data.

use std::{collections::HashMap, fmt::Debug, net::Ipv4Addr, sync::Arc};

use anyhow::Result;
use k8s_openapi::api::{
    apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet},
    batch::v1::Job,
    core::v1::{Node, Pod, Service},
    discovery::v1::EndpointSlice,
    networking::v1::{Ingress, NetworkPolicy},
};
use kube::{
    Client,
    api::{Api, ListParams, Resource},
    runtime::reflector,
};
use log::{debug, info, warn};

pub mod resource_parser;

/// Type alias for a thread-safe, readable store of Kubernetes resources.
pub type Store<T> = Arc<reflector::Store<T>>;

/// A trait for types that contain a reflector store for a specific Kubernetes resource.
/// This enables generic, type-safe access to the stores.
pub trait HasStore<K>
where
    K: Resource,
    K::DynamicType: Eq + std::hash::Hash + Clone,
{
    /// Returns a reference to the store for the resource type `K`.
    fn store(&self) -> &Store<K>;
}

/// A central cache holding reflectors for all Kubernetes resources.
#[derive(Clone)]
pub struct ResourceStore {
    pub pods: Store<Pod>,
    pub nodes: Store<Node>,
    pub deployments: Store<Deployment>,
    pub replica_sets: Store<ReplicaSet>,
    pub stateful_sets: Store<StatefulSet>,
    pub daemon_sets: Store<DaemonSet>,
    pub jobs: Store<Job>,
    pub services: Store<Service>,
    pub ingresses: Store<Ingress>,
    pub endpoint_slices: Store<EndpointSlice>,
    pub network_policies: Store<NetworkPolicy>,
}

impl HasStore<Pod> for ResourceStore {
    fn store(&self) -> &Store<Pod> {
        &self.pods
    }
}
impl HasStore<Node> for ResourceStore {
    fn store(&self) -> &Store<Node> {
        &self.nodes
    }
}
impl HasStore<Deployment> for ResourceStore {
    fn store(&self) -> &Store<Deployment> {
        &self.deployments
    }
}
impl HasStore<ReplicaSet> for ResourceStore {
    fn store(&self) -> &Store<ReplicaSet> {
        &self.replica_sets
    }
}
impl HasStore<StatefulSet> for ResourceStore {
    fn store(&self) -> &Store<StatefulSet> {
        &self.stateful_sets
    }
}
impl HasStore<DaemonSet> for ResourceStore {
    fn store(&self) -> &Store<DaemonSet> {
        &self.daemon_sets
    }
}
impl HasStore<Job> for ResourceStore {
    fn store(&self) -> &Store<Job> {
        &self.jobs
    }
}
impl HasStore<Service> for ResourceStore {
    fn store(&self) -> &Store<Service> {
        &self.services
    }
}
impl HasStore<Ingress> for ResourceStore {
    fn store(&self) -> &Store<Ingress> {
        &self.ingresses
    }
}
impl HasStore<EndpointSlice> for ResourceStore {
    fn store(&self) -> &Store<EndpointSlice> {
        &self.endpoint_slices
    }
}
impl HasStore<NetworkPolicy> for ResourceStore {
    fn store(&self) -> &Store<NetworkPolicy> {
        &self.network_policies
    }
}

impl ResourceStore {
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

/// A utility module to create and manage reflectors for Kubernetes resources.
pub mod reflector_builder {
    use futures::TryStreamExt;
    use kube::runtime::{watcher, watcher::Config as WatcherConfig};
    use kube_runtime::WatchStreamExt;

    use super::*;

    /// Creates a new reflector for a Kubernetes resource type.
    pub async fn create_store<K>(client: Client) -> Result<Store<K>>
    where
        K: Resource + Clone + Debug + Send + Sync + 'static + for<'de> serde::Deserialize<'de>,
        K::DynamicType: Default + std::hash::Hash + std::cmp::Eq + Clone,
    {
        let resource_name = K::kind(&K::DynamicType::default()).to_string();
        let api: Api<K> = Api::all(client);

        // Fail fast if the API is unreachable.
        api.list(&ListParams::default().limit(1)).await?;

        let (reader, writer) = reflector::store();
        let reflector = reflector(writer, watcher(api, WatcherConfig::default()));

        tokio::spawn(async move {
            info!("Starting reflector for {resource_name}");
            reflector
                .applied_objects()
                .try_for_each(|resource| {
                    let name = resource.meta().name.as_deref().unwrap_or("unknown");
                    debug!("Applied {resource_name} '{name}' to store");
                    async { Ok(()) }
                })
                .await
                .unwrap_or_else(|e| warn!("Reflector error for {resource_name}: {e}"));
        });

        Ok(Arc::new(reader))
    }
}

/// Builder responsible for the concurrent initialization of the AppStore.
pub struct AppStoreBuilder {
    client: Client,
}

impl AppStoreBuilder {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Initializes all resource reflectors concurrently and builds the AppStore.
    pub async fn build(self) -> Result<ResourceStore> {
        let all_stores_result = futures::try_join!(
            Self::create_resource_store::<Pod>(&self.client, true),
            Self::create_resource_store::<Node>(&self.client, false),
            Self::create_resource_store::<Deployment>(&self.client, false),
            Self::create_resource_store::<ReplicaSet>(&self.client, false),
            Self::create_resource_store::<StatefulSet>(&self.client, false),
            Self::create_resource_store::<DaemonSet>(&self.client, false),
            Self::create_resource_store::<Job>(&self.client, false),
            Self::create_resource_store::<Service>(&self.client, false),
            Self::create_resource_store::<Ingress>(&self.client, false),
            Self::create_resource_store::<EndpointSlice>(&self.client, false),
            Self::create_resource_store::<NetworkPolicy>(&self.client, false),
        );

        match all_stores_result {
            Ok((
                pods,
                nodes,
                deployments,
                replica_sets,
                stateful_sets,
                daemon_sets,
                jobs,
                services,
                ingresses,
                endpoint_slices,
                network_policies,
            )) => Ok(ResourceStore {
                pods,
                nodes,
                deployments,
                replica_sets,
                stateful_sets,
                daemon_sets,
                jobs,
                services,
                ingresses,
                endpoint_slices,
                network_policies,
            }),
            Err(e) => Err(e),
        }
    }

    /// Helper to create a store for a resource, handling failures gracefully.
    async fn create_resource_store<K>(client: &Client, is_critical: bool) -> Result<Store<K>>
    where
        K: Resource + Clone + Debug + Send + Sync + 'static + for<'de> serde::Deserialize<'de>,
        K::DynamicType: Default + std::hash::Hash + std::cmp::Eq + Clone,
    {
        let resource_name = K::kind(&K::DynamicType::default()).to_string();
        match reflector_builder::create_store::<K>(client.clone()).await {
            Ok(store) => Ok(store),
            Err(e) => {
                if is_critical {
                    warn!("Failed to create critical reflector for {resource_name}: {e}");
                    Err(anyhow::anyhow!(
                        "Failed to create critical reflector for {resource_name}: {e}"
                    ))
                } else {
                    warn!(
                        "Failed to create reflector for {resource_name}: {e}. Continuing with an empty store."
                    );
                    let (reader, _) = reflector::store();
                    Ok(Arc::new(reader))
                }
            }
        }
    }
}

/// A high-level client for interacting with Kubernetes resources via the cached AppStore.
pub struct KubeClient {
    #[allow(dead_code)]
    pub client: Client,
    pub app_store: ResourceStore,
}

impl KubeClient {
    /// Creates a new KubeClient, initializing all resource reflectors concurrently.
    pub async fn new() -> Result<Self> {
        let client = Client::try_default().await?;
        let app_store = AppStoreBuilder::new(client.clone()).build().await?;
        Ok(Self { client, app_store })
    }

    /// Looks up a Pod by its IP address.
    pub async fn get_pod_by_ip(&self, ip: Ipv4Addr) -> Option<Arc<Pod>> {
        let ip_str = ip.to_string();
        self.app_store
            .pods
            .state()
            .iter()
            .find(|pod| {
                pod.status
                    .as_ref()
                    .and_then(|status| status.pod_ip.as_deref())
                    .is_some_and(|pod_ip| pod_ip == ip_str)
            })
            .cloned()
    }

    /// Finds all Services whose selectors match the labels of a given Pod.
    pub fn get_services_for_pod(&self, pod: &Pod) -> Vec<Arc<Service>> {
        let pod_labels = match &pod.metadata.labels {
            Some(labels) => labels,
            None => return Vec::new(),
        };

        self.app_store
            .services
            .state()
            .iter()
            .filter(|service| {
                service
                    .spec
                    .as_ref()
                    .and_then(|spec| spec.selector.as_ref())
                    .is_some_and(|selector| {
                        selector.iter().all(|(key, value)| {
                            pod_labels
                                .get(key)
                                .is_some_and(|pod_val| *pod_val == *value)
                        })
                    })
            })
            .cloned()
            .collect()
    }

    /// Finds all Pods owned by a specific controller (e.g., a Deployment or ReplicaSet).
    #[allow(dead_code)]
    pub fn get_pods_by_owner_reference(
        &self,
        kind: &str,
        name: &str,
        namespace: &str,
    ) -> Vec<Arc<Pod>> {
        self.app_store
            .pods
            .state()
            .iter()
            .filter(|pod| pod.meta().namespace.as_deref() == Some(namespace))
            .filter(|pod| {
                pod.meta().owner_references.as_ref().is_some_and(|owners| {
                    owners
                        .iter()
                        .any(|owner| owner.kind == kind && owner.name == name)
                })
            })
            .cloned()
            .collect()
    }

    /// Gathers the names of all discoverable resources within a given namespace.
    #[allow(dead_code)]
    pub fn get_resources_by_namespace(
        &self,
        namespace: &str,
    ) -> HashMap<&'static str, Vec<String>> {
        let mut resources = HashMap::new();

        fn get_names<K>(store: &Store<K>, ns: &str) -> Vec<String>
        where
            K: Resource + Clone,
            K::DynamicType: Eq + std::hash::Hash + Clone,
        {
            store
                .state()
                .iter()
                .filter(|r| r.meta().namespace.as_deref() == Some(ns))
                .filter_map(|r| r.meta().name.clone())
                .collect()
        }

        let mut add = |kind: &'static str, names: Vec<String>| {
            if !names.is_empty() {
                resources.insert(kind, names);
            }
        };

        // Cluster-scoped resources
        let node_names = self
            .app_store
            .nodes
            .state()
            .iter()
            .filter_map(|node| node.meta().name.clone())
            .collect();
        add("Node", node_names);

        // Namespaced resources
        add("Pod", get_names(&self.app_store.pods, namespace));
        add(
            "Deployment",
            get_names(&self.app_store.deployments, namespace),
        );
        add(
            "ReplicaSet",
            get_names(&self.app_store.replica_sets, namespace),
        );
        add(
            "StatefulSet",
            get_names(&self.app_store.stateful_sets, namespace),
        );
        add(
            "DaemonSet",
            get_names(&self.app_store.daemon_sets, namespace),
        );
        add("Job", get_names(&self.app_store.jobs, namespace));
        add("Service", get_names(&self.app_store.services, namespace));
        add("Ingress", get_names(&self.app_store.ingresses, namespace));
        add(
            "EndpointSlice",
            get_names(&self.app_store.endpoint_slices, namespace),
        );
        add(
            "NetworkPolicy",
            get_names(&self.app_store.network_policies, namespace),
        );

        resources
    }
}
