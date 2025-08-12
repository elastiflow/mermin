use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::{env, path::Path};

use anyhow::Result;
use futures::TryStreamExt;
use k8s_openapi::api::core::v1::Pod;
use kube::{
    api::{Api, ListParams},
    Client, Config as KubeConfig,
};
use kube::runtime::{reflector, watcher, WatchStreamExt, watcher::Config as WatcherConfig};
use kube_runtime::reflector::Store;
use log::{debug, info, warn};
use mermin_common::PacketMeta;

/// A wrapper around the Kubernetes client and Pod store
pub struct KubeClient {
    /// The Kubernetes client
    client: Client,
    /// The Pod store that caches Pod resources
    pod_store: Store<Pod>,
}

impl KubeClient {
    /// Create a new KubeClient and start the Pod reflector
    pub async fn new() -> Result<Self> {
        // Prefer in-cluster configuration when running inside Kubernetes, otherwise infer

        let client = Client::try_default().await?;

        // Create the Pod API
        let pods: Api<Pod> = Api::all(client.clone());

        // Connectivity check: perform a lightweight list to fail fast if unreachable
        // Note: limit(1) reduces load while still proving connectivity
        let lp = ListParams::default().limit(1);
        let _ = pods.list(&lp).await?;

        let pod_filter = WatcherConfig::default().labels("kubernetes.io/arch=amd64");

        // Create the Pod reflector
        let (reader, writer) = reflector::store();
        let pod_reflector = reflector(
            writer,
            watcher(pods, pod_filter),
        );

        // Start the Pod reflector in a separate task
        tokio::spawn(async move {
            info!("Starting Pod reflector");
            pod_reflector
                .applied_objects()
                .try_for_each(|pod| async move {
                    debug!("Pod applied: {}", pod.metadata.name.as_deref().unwrap_or("unknown"));
                    Ok(())
                })
                .await
                .unwrap_or_else(|e| warn!("Pod reflector error: {}", e));
        });

        Ok(Self {
            client,
            pod_store: reader,
        })
    }

    /// Look up a Pod by its IP address
    pub async fn get_pod_by_ip(&self, ip: Ipv4Addr) -> Option<Arc<Pod>> {
        let ip_str = ip.to_string();
        println!("Getting POD with IP {:?}", ip_str);
        // Find the Pod with the matching IP address
        for pod in self.pod_store.state() {
            if let Some(pod_ip) = pod.status.as_ref().and_then(|s| s.pod_ip.as_ref()) {
                println!("{:?}", pod_ip);
                print!("{:?}", ip_str);
                if *pod_ip == ip_str {
                    return Some(pod.clone());
                }
            }
        }

        None
    }

    /// Get a map of all Pod IPs to Pod names
    pub async fn get_pod_ip_map(&self) -> HashMap<String, String> {
        let mut ip_map = HashMap::new();

        for pod in self.pod_store.state() {
            if let (Some(name), Some(status)) = (&pod.metadata.name, &pod.status) {
                if let Some(pod_ip) = &status.pod_ip {
                    ip_map.insert(pod_ip.clone(), name.clone());
                }
            }
        }

        ip_map
    }
}