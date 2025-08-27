// k8s.rs - Kubernetes client and resource management
//
// This module provides a high-level, concurrent, and ergonomic interface for
// interacting with Kubernetes resources. It features:
// - A ResourceStore for concurrent initialization and caching of resource reflectors.
// - A high-level Attributor client for querying and correlating resources.
// - Support for Pods, Nodes, key workload types (Deployments, StatefulSets, etc.).
// - Network-related resources like Services, Ingresses and NetworkPolicies.

use std::{collections::HashMap, fmt::Debug, net::IpAddr, sync::Arc};

use anyhow::Result;
use futures::TryStreamExt;
use k8s_openapi::api::{
    apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet},
    batch::v1::Job,
    core::v1::{Node, Pod, Service},
    discovery::v1::EndpointSlice,
    networking::v1::{Ingress, NetworkPolicy},
};
use kube::{
    Client, Discovery,
    api::{Api, ListParams, Resource},
    runtime::reflector,
};
use kube_runtime::{WatchStreamExt, watcher};
use log::{debug, info, warn};

pub mod resource_parser;

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
    pub async fn new(client: Client) -> Result<Self> {
        let all_stores_result = futures::try_join!(
            Self::create_resource_store::<Pod>(&client, true),
            Self::create_resource_store::<Node>(&client, false),
            Self::create_resource_store::<Deployment>(&client, false),
            Self::create_resource_store::<ReplicaSet>(&client, false),
            Self::create_resource_store::<StatefulSet>(&client, false),
            Self::create_resource_store::<DaemonSet>(&client, false),
            Self::create_resource_store::<Job>(&client, false),
            Self::create_resource_store::<Service>(&client, false),
            Self::create_resource_store::<Ingress>(&client, false),
            Self::create_resource_store::<EndpointSlice>(&client, false),
            Self::create_resource_store::<NetworkPolicy>(&client, false),
        );

        all_stores_result.map(
            |(
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
            )| {
                Self {
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
                }
            },
        )
    }

    /// Helper to create a store for a resource, handling failures gracefully.
    async fn create_resource_store<K>(
        client: &Client,
        is_critical: bool,
    ) -> Result<reflector::Store<K>>
    where
        K: Resource + Clone + Debug + Send + Sync + 'static + for<'de> serde::Deserialize<'de>,
        K::DynamicType: Default + std::hash::Hash + std::cmp::Eq + Clone,
    {
        let resource_name = K::kind(&K::DynamicType::default()).to_string();
        match create_store::<K>(client.clone()).await {
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
                    Ok(reader)
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
async fn create_store<K>(client: Client) -> Result<reflector::Store<K>>
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

    Ok(reader)
}

/// A high-level client for querying Kubernetes resources.
pub struct Attributor {
    #[allow(dead_code)]
    pub client: Client,
    pub resource_store: ResourceStore,
    pub discovery: Discovery,
}

impl Attributor {
    /// Creates a new Attributor, initializing all resource reflectors concurrently.
    pub async fn new() -> Result<Self> {
        let client = Client::try_default().await?;
        let resource_store = ResourceStore::new(client.clone()).await?;
        let discovery = Discovery::new(client.clone()).run().await?;
        Ok(Self {
            client,
            resource_store,
            discovery,
        })
    }

    /// Looks up a Pod by its IP address.
    pub async fn get_pod_by_ip(&self, ip: IpAddr) -> Option<Arc<Pod>> {
        let ip_str = ip.to_string();
        self.resource_store
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

    /// Looks up a Node by its name (to find a Pod's host).
    pub async fn get_node_by_name(&self, name: &str) -> Option<Arc<Node>> {
        self.resource_store
            .nodes
            .state()
            .iter()
            .find(|node| node.metadata.name.as_deref() == Some(name))
            .cloned()
    }

    #[allow(dead_code)]
    /// Finds all Services whose selectors match the labels of a given Pod.
    pub fn get_services_for_pod(&self, pod: &Pod) -> Vec<Arc<Service>> {
        let pod_labels = match &pod.metadata.labels {
            Some(labels) => labels,
            None => return Vec::new(),
        };

        self.resource_store
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
        self.resource_store
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

        let mut add = |kind: &'static str, names: Vec<String>| {
            if !names.is_empty() {
                resources.insert(kind, names);
            }
        };

        macro_rules! get_names {
            ($resource:ty) => {
                self.resource_store
                    .get_by_namespace::<$resource>(namespace)
                    .iter()
                    .filter_map(|r| r.meta().name.clone())
                    .collect()
            };
        }

        // Cluster-scoped resources
        let node_names = self
            .resource_store
            .nodes
            .state()
            .iter()
            .filter_map(|node| node.meta().name.clone())
            .collect();
        add("Node", node_names);

        // Namespaced resources
        add("Pod", get_names!(Pod));
        add("Deployment", get_names!(Deployment));
        add("ReplicaSet", get_names!(ReplicaSet));
        add("StatefulSet", get_names!(StatefulSet));
        add("DaemonSet", get_names!(DaemonSet));
        add("Job", get_names!(Job));
        add("Service", get_names!(Service));
        add("Ingress", get_names!(Ingress));
        add("EndpointSlice", get_names!(EndpointSlice));
        add("NetworkPolicy", get_names!(NetworkPolicy));

        resources
    }
}
