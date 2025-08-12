// k8s.rs - Kubernetes client and resource management
//
// This module provides functionality for interacting with Kubernetes resources.
// It includes:
// - A generic trait for Kubernetes resources (KubeResource)
// - A reflector implementation for watching Kubernetes resources
// - A client for accessing and querying Kubernetes resources
// - Helper methods for looking up resources by various criteria

use std::{collections::HashMap, fmt::Debug, net::Ipv4Addr, sync::Arc};

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
    Client,
    api::{Api, ListParams, Resource},
    runtime::{WatchStreamExt, reflector, watcher, watcher::Config as WatcherConfig},
};
use log::{debug, info, warn};

/// Type alias for a store of Kubernetes resources
pub type Store<T> = Arc<reflector::Store<T>>;

/// Store for all Kubernetes resources used by the application
///
/// This struct holds references to all the Kubernetes resource stores
/// that the application needs to access. Each store is a reflector that
/// watches for changes to the corresponding resource type.
#[derive(Clone)]
pub struct AppStore {
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
    // These could be implemented from gateway-api-rs but it's still in development
    // https://github.com/kube-rs/gateway-api-rs
    // pub gateway: Store<Gateway>,
    // pub gateway_class: Store<GatewayClass>,
    // pub http_route: Store<HTTPRoute>,
}

/// A utility module to create and manage reflectors for Kubernetes resources.
pub mod reflector_builder {
    use std::fmt::Debug;

    use futures::TryStreamExt;
    use kube::runtime::{reflector, watcher, watcher::Config as WatcherConfig};
    use log::{debug, info, warn};

    use super::*;

    /// Creates a new reflector for a Kubernetes resource type.
    ///
    /// This function creates a reflector that watches for changes to the specified
    /// resource. The reflector runs in a background task and maintains a local
    /// in-memory store of the resources.
    ///
    /// # Arguments
    /// * `client` - The Kubernetes client for API requests.
    ///
    /// # Returns
    /// A `Result` containing the thread-safe store for the resource.
    pub async fn create_store<K>(client: Client) -> Result<Store<K>>
    where
        K: Resource + Clone + Debug + Send + Sync + 'static + for<'de> serde::Deserialize<'de>,
        K::DynamicType: Default + std::hash::Hash + std::cmp::Eq + Clone,
    {
        // Derive the resource name directly from the Kubernetes resource type
        let resource_name = K::kind(&K::DynamicType::default()).to_string();

        let api: Api<K> = Api::all(client);

        // Connectivity check: perform a lightweight list to fail fast if unreachable
        let lp = ListParams::default().limit(1);
        let _ = api.list(&lp).await?;

        // Create the reflector without any label filter to include all resources
        let filter = WatcherConfig::default();

        // Create the reflector
        let (reader, writer) = reflector::store();
        let reflector = reflector(writer, watcher(api.clone(), filter));

        // Clone the resource_name to create an owned String that can be moved into the spawned task
        let resource_name = resource_name.to_string();

        // Start the reflector in a separate task
        tokio::spawn(async move {
            info!("Starting {} reflector", resource_name);
            reflector
                .applied_objects()
                .try_for_each(|resource| {
                    let resource_name_clone = resource_name.clone();
                    async move {
                        let name = resource.meta().name.as_deref().unwrap_or("unknown");
                        debug!("{} applied to store: {}", resource_name_clone, name);
                        Ok(())
                    }
                })
                .await
                .unwrap_or_else(|e| warn!("{} reflector error: {}", resource_name, e));
        });

        Ok(Arc::new(reader))
    }
}

/// A wrapper around the Kubernetes client and resource stores
///
/// This struct provides a high-level interface for interacting with
/// Kubernetes resources. It manages reflectors for various resource types
/// and provides methods for querying those resources.
pub struct KubeClient {
    /// The Kubernetes client
    client: Client,
    /// The app store that caches resources
    pub app_store: AppStore,
}

impl KubeClient {
    /// Creates a new KubeClient and starts all reflectors.
    ///
    /// This method initializes the Kubernetes client and creates reflectors
    /// for all the resource types required by the application.
    /// It handles errors gracefully for non-critical resources.
    ///
    /// # Returns
    /// A `Result` containing the initialized `KubeClient`.
    pub async fn new() -> Result<Self> {
        let client = Client::try_default().await?;

        // Helper to create a store for a resource, handling failures.
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
                        warn!(
                            "Failed to create critical reflector for {}: {}",
                            resource_name, e
                        );
                        Err(anyhow::anyhow!(
                            "Failed to create critical reflector for {}: {}",
                            resource_name,
                            e
                        ))
                    } else {
                        warn!(
                            "Failed to create reflector for {}: {}. Continuing with an empty store.",
                            resource_name, e
                        );
                        // For non-critical failures, return an empty store to allow the application to proceed.
                        let (reader, _) = reflector::store();
                        Ok(Arc::new(reader))
                    }
                }
            }
        }

        // Initialize reflectors. Only the Pod reflector is considered critical.
        let pods = create_resource_store::<Pod>(&client, true).await?;
        let nodes = create_resource_store::<Node>(&client, false).await?;
        let deployments = create_resource_store::<Deployment>(&client, false).await?;
        let replica_sets = create_resource_store::<ReplicaSet>(&client, false).await?;
        let stateful_sets = create_resource_store::<StatefulSet>(&client, false).await?;
        let daemon_sets = create_resource_store::<DaemonSet>(&client, false).await?;
        let jobs = create_resource_store::<Job>(&client, false).await?;
        let services = create_resource_store::<Service>(&client, false).await?;
        let ingresses = create_resource_store::<Ingress>(&client, false).await?;
        let endpoint_slices = create_resource_store::<EndpointSlice>(&client, false).await?;
        let network_policies = create_resource_store::<NetworkPolicy>(&client, false).await?;

        Ok(Self {
            client,
            app_store: AppStore {
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
            },
        })
    }

    /// Generic method to find resources of a specific type by namespace.
    pub fn get_resources_of_type_by_namespace<K>(
        &self,
        store: &Store<K>,
        namespace: &str,
    ) -> Vec<Arc<K>>
    where
        K: Resource + Clone,
        K::DynamicType: std::hash::Hash + std::cmp::Eq + Clone,
    {
        store
            .state()
            .iter()
            .filter(|resource| resource.meta().namespace.as_deref() == Some(namespace))
            .cloned()
            .collect()
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
                    .map_or(false, |pod_ip| pod_ip == ip_str)
            })
            .cloned()
    }

    /// Looks up a Service by its name.
    pub fn get_service_by_name(&self, name: &str) -> Option<Arc<Service>> {
        self.app_store
            .services
            .state()
            .iter()
            .find(|service| service.meta().name.as_deref() == Some(name))
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
                    .map_or(false, |selector| {
                        selector.iter().all(|(key, value)| {
                            pod_labels
                                .get(key)
                                .map_or(false, |pod_val| pod_val.to_string() == value.to_string())
                        })
                    })
            })
            .cloned()
            .collect()
    }

    /// Finds all Deployments in a specific namespace.
    pub fn get_deployments_by_namespace(&self, namespace: &str) -> Vec<Arc<Deployment>> {
        self.get_resources_of_type_by_namespace(&self.app_store.deployments, namespace)
    }

    /// Finds all Pods owned by a specific controller (e.g., a Deployment or ReplicaSet).
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
                pod.meta()
                    .owner_references
                    .as_ref()
                    .map_or(false, |owners| {
                        owners
                            .iter()
                            .any(|owner| owner.kind == kind && owner.name == name)
                    })
            })
            .cloned()
            .collect()
    }

    /// Gathers all discoverable resources within a given namespace.
    pub fn get_resources_by_namespace(
        &self,
        namespace: &str,
    ) -> HashMap<&'static str, Vec<String>> {
        let mut resources = HashMap::new();

        let mut add_resources = |kind: &'static str, names: Vec<String>| {
            if !names.is_empty() {
                resources.insert(kind, names);
            }
        };

        fn get_resource_names<K>(store: &Store<K>, ns: &str) -> Vec<String>
        where
            K: Resource + Clone,
            K::DynamicType: std::hash::Hash + std::cmp::Eq + Clone,
        {
            store
                .state()
                .iter()
                .filter(|resource| resource.meta().namespace.as_deref() == Some(ns))
                .filter_map(|resource| resource.meta().name.clone())
                .collect()
        }

        let node_names = self
            .app_store
            .nodes
            .state()
            .iter()
            .filter_map(|node| node.metadata.name.clone())
            .collect();
        add_resources("Node", node_names);

        // Namespaced resources.
        add_resources("Pod", get_resource_names(&self.app_store.pods, namespace));
        add_resources(
            "Deployment",
            get_resource_names(&self.app_store.deployments, namespace),
        );
        add_resources(
            "ReplicaSet",
            get_resource_names(&self.app_store.replica_sets, namespace),
        );
        add_resources(
            "StatefulSet",
            get_resource_names(&self.app_store.stateful_sets, namespace),
        );
        add_resources(
            "DaemonSet",
            get_resource_names(&self.app_store.daemon_sets, namespace),
        );
        add_resources("Job", get_resource_names(&self.app_store.jobs, namespace));
        add_resources(
            "Service",
            get_resource_names(&self.app_store.services, namespace),
        );
        add_resources(
            "Ingress",
            get_resource_names(&self.app_store.ingresses, namespace),
        );
        add_resources(
            "EndpointSlice",
            get_resource_names(&self.app_store.endpoint_slices, namespace),
        );
        add_resources(
            "NetworkPolicy",
            get_resource_names(&self.app_store.network_policies, namespace),
        );

        resources
    }

    /// Finds all NetworkPolicies in a specific namespace.
    pub fn get_network_policies_by_namespace(&self, namespace: &str) -> Vec<Arc<NetworkPolicy>> {
        self.get_resources_of_type_by_namespace(&self.app_store.network_policies, namespace)
    }
}
