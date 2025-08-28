use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use anyhow::Result;
use k8s_openapi::{
    api::{
        apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet},
        batch::v1::Job,
    },
    apimachinery::pkg::apis::meta::v1::OwnerReference,
};
use kube::{Resource, ResourceExt};
use log::warn;
use mermin_common::{IpAddrType, PacketMeta};
use network_types::ip::IpProto;

use crate::k8s::Attributor;

/// Holds metadata for a single Kubernetes object.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct K8sObjectMeta {
    pub kind: String,
    pub name: String,
    pub uid: Option<String>,
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
#[allow(dead_code)]
pub enum EnrichedInfo {
    Pod {
        pod: K8sObjectMeta,
        owners: Vec<WorkloadOwner>,
    },
    Node {
        node: K8sObjectMeta,
    },
    Service {
        service: K8sObjectMeta,
        backend_ips: Vec<String>,
    },
    EndpointSlice {
        slice: K8sObjectMeta,
    },
}

#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct EnrichedFlowData {
    pub id: String,
    pub source: Option<EnrichedInfo>,
    pub destination: Option<EnrichedInfo>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct FlowSide {
    ip: IpAddr,
    port: u16,
    protocol: IpProto,
}

fn get_owner_from_store(
    attributor: &Attributor,
    owner_ref: &OwnerReference,
    namespace: &str,
) -> Option<(WorkloadOwner, Option<Vec<OwnerReference>>)> {
    let name = &owner_ref.name;
    macro_rules! find_in_store {
        ($store_type:ty, $variant:ident) => {
            attributor
                .resource_store
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
                "Owner lookup for kind '{}' is not implemented.",
                owner_ref.kind
            );
            None
        }
    }
}

/// Recursively discovers the entire ownership chain for a given object.
pub fn find_owner_chain(
    attributor: &Attributor,
    initial_owners: Vec<OwnerReference>,
    initial_namespace: &str,
    max_depth: usize,
) -> Vec<WorkloadOwner> {
    let mut chain = Vec::new();
    let mut owners_to_process: VecDeque<(OwnerReference, String, usize)> = initial_owners
        .into_iter()
        .map(|owner| (owner, initial_namespace.to_string(), 1))
        .collect();

    while let Some((owner_ref, namespace, depth)) = owners_to_process.pop_front() {
        if depth > max_depth {
            continue;
        }

        if let Some((owner_obj, next_owners_opt)) =
            get_owner_from_store(attributor, &owner_ref, &namespace)
        {
            if let Some(next_owners) = next_owners_opt {
                let owner_namespace = match &owner_obj {
                    WorkloadOwner::ReplicaSet(m) => m.namespace.clone(),
                    WorkloadOwner::Deployment(m) => m.namespace.clone(),
                    WorkloadOwner::StatefulSet(m) => m.namespace.clone(),
                    WorkloadOwner::DaemonSet(m) => m.namespace.clone(),
                    WorkloadOwner::Job(m) => m.namespace.clone(),
                }
                .unwrap_or(namespace);

                for next_owner in next_owners {
                    owners_to_process.push_back((next_owner, owner_namespace.clone(), depth + 1));
                }
            }
            chain.push(owner_obj);
        } else {
            warn!(
                "Failed to find owner {} ({}) in store for namespace {}",
                owner_ref.name, owner_ref.kind, namespace
            );
        }
    }
    chain
}

/// Enriches a single side of a flow (source or destination) based on its IP address.
async fn enrich_side(side: &FlowSide, attributor: &Attributor) -> Option<EnrichedInfo> {
    if let Some(pod) = attributor.get_pod_by_ip(side.ip).await {
        let pod_meta = K8sObjectMeta::from(pod.as_ref());
        let owners = if let Some(owner_refs) = &pod.metadata.owner_references {
            find_owner_chain(
                attributor,
                owner_refs.clone(),
                &pod.namespace().unwrap_or_default(),
                10, // Replace with conf value when available
            )
        } else {
            Vec::new()
        };
        return Some(EnrichedInfo::Pod {
            pod: pod_meta,
            owners,
        });
    }

    if let Some(node) = attributor.get_node_by_ip(side.ip).await {
        return Some(EnrichedInfo::Node {
            node: K8sObjectMeta::from(node.as_ref()),
        });
    }

    if let Some(service) = attributor
        .get_service_by_flow_details(side.ip, side.port, side.protocol)
        .await
    {
        let service_meta = K8sObjectMeta::from(service.as_ref());
        let backend_ips = attributor.resolve_service_ip_to_backend_ips(side.ip).await;

        return Some(EnrichedInfo::Service {
            service: service_meta,
            backend_ips: backend_ips.unwrap(),
        });
    }

    if let Some(slice) = attributor.get_endpointslice_by_ip(side.ip).await {
        return Some(EnrichedInfo::EndpointSlice {
            slice: K8sObjectMeta::from(slice.as_ref()),
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
    let source_side = FlowSide {
        ip: match packet.ip_addr_type {
            IpAddrType::Ipv4 => IpAddr::V4(Ipv4Addr::from(packet.src_ipv4_addr)),
            IpAddrType::Ipv6 => IpAddr::V6(Ipv6Addr::from(packet.src_ipv6_addr)),
        },
        port: u16::from_be_bytes(packet.src_port),
        protocol: packet.proto,
    };

    let destination_side = FlowSide {
        ip: match packet.ip_addr_type {
            IpAddrType::Ipv4 => IpAddr::V4(Ipv4Addr::from(packet.dst_ipv4_addr)),
            IpAddrType::Ipv6 => IpAddr::V6(Ipv6Addr::from(packet.dst_ipv6_addr)),
        },
        port: u16::from_be_bytes(packet.dst_port),
        protocol: packet.proto,
    };

    let (source_info, destination_info) = tokio::join!(
        enrich_side(&source_side, attributor),
        enrich_side(&destination_side, attributor)
    );

    Ok(EnrichedFlowData {
        id: community_id,
        source: source_info,
        destination: destination_info,
    })
}
