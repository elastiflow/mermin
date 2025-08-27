use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use anyhow::Result;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{DynamicObject, GroupVersionKind},
    discovery::{Discovery, Scope},
};
use mermin_common::{IpAddrType, PacketMeta};

use crate::k8s::Attributor;

/// Holds metadata for a single Kubernetes object.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct K8sObjectMeta {
    pub kind: String,
    pub name: String,
    pub namespace: Option<String>,
    pub labels: Option<HashMap<String, String>>,
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
            namespace: resource.namespace(),
            labels: (!resource.labels().is_empty())
                .then(|| resource.labels().clone().into_iter().collect()),
            annotations: (!resource.annotations().is_empty())
                .then(|| resource.annotations().clone().into_iter().collect()),
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum EnrichedInfo {
    Pod {
        pod: K8sObjectMeta,
        node: Option<K8sObjectMeta>,
        owners: Vec<K8sObjectMeta>,
    },
    Node {
        node: K8sObjectMeta,
    },
}

#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct EnrichedFlowData {
    pub id: String,
    pub source: Option<EnrichedInfo>,
    pub destination: Option<EnrichedInfo>,
}

/// Recursively discovers the entire ownership chain for a given object.
pub async fn find_owner_chain(
    client: Client,
    discovery: &Discovery,
    initial_owners: Vec<OwnerReference>,
    initial_namespace: &str,
) -> Vec<K8sObjectMeta> {
    let chain = Vec::new();
    let mut owners_to_process: VecDeque<(OwnerReference, String)> = initial_owners
        .into_iter()
        .map(|owner| (owner, initial_namespace.to_string()))
        .collect();

    while let Some((owner_ref, namespace)) = owners_to_process.pop_front() {
        let gvk = GroupVersionKind::from(owner_ref.clone());
        if let Some((resource, capabilities)) = discovery.resolve_gvk(&gvk) {
            let _api: Api<DynamicObject> = match capabilities.scope {
                Scope::Cluster => Api::all_with(client.clone(), &resource),
                Scope::Namespaced => Api::namespaced_with(client.clone(), &namespace, &resource),
            };

            // TODO: convert the api result to K8sObjectMeta and return it
            // chain.push(...)
        } else {
            eprintln!(
                "Could not discover ApiResource for GVK: {}/{} {}",
                gvk.group, gvk.version, owner_ref.kind
            );
        }
    }
    chain
}

/// Enriches a single side of a flow (source or destination) based on its IP address.
async fn enrich_side(ip: IpAddr, attributor: &Attributor) -> Option<EnrichedInfo> {
    if let Some(pod) = attributor.get_pod_by_ip(ip).await {
        let pod_meta = K8sObjectMeta::from(pod.as_ref());

        let node_meta = if let Some(node_name) = pod.spec.as_ref()?.node_name.as_deref() {
            attributor
                .get_node_by_name(node_name)
                .await
                .map(|node| K8sObjectMeta::from(node.as_ref()))
        } else {
            None
        };

        let owners = if let Some(owner_refs) = &pod.metadata.owner_references {
            find_owner_chain(
                attributor.client.clone(),
                &attributor.discovery,
                owner_refs.clone(),
                &pod.namespace().unwrap_or_default(),
            )
            .await
        } else {
            Vec::new()
        };

        return Some(EnrichedInfo::Pod {
            pod: pod_meta,
            node: node_meta,
            owners,
        });
    }

    if let Some(node) = attributor.get_node_by_ip(ip).await {
        return Some(EnrichedInfo::Node {
            node: K8sObjectMeta::from(node.as_ref()),
        });
    }

    None
}

/// Main function to parse a packet and enrich it with Kubernetes metadata.
pub async fn parse_packet(
    packet: &PacketMeta,
    attributor: &Attributor,
    community_id: String,
) -> Result<EnrichedFlowData> {
    let (src_ip, dst_ip) = match packet.ip_addr_type {
        IpAddrType::Ipv4 => (
            IpAddr::V4(Ipv4Addr::from(packet.src_ipv4_addr)),
            IpAddr::V4(Ipv4Addr::from(packet.dst_ipv4_addr)),
        ),
        IpAddrType::Ipv6 => (
            IpAddr::V6(Ipv6Addr::from(packet.src_ipv6_addr)),
            IpAddr::V6(Ipv6Addr::from(packet.dst_ipv6_addr)),
        ),
    };

    let (source_info, destination_info) = tokio::join!(
        enrich_side(src_ip, attributor),
        enrich_side(dst_ip, attributor)
    );

    Ok(EnrichedFlowData {
        id: community_id,
        source: source_info,
        destination: destination_info,
    })
}
