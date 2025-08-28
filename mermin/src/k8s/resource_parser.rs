use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use mermin_common::{IpAddrType, PacketMeta};
use network_types::ip::IpProto;

use crate::k8s::{Attributor, EnrichedInfo, K8sObjectMeta};

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

/// Enriches a single side of a flow (source or destination) based on its IP address.
async fn enrich_side(side: &FlowSide, attributor: &Attributor) -> Option<EnrichedInfo> {
    if let Some(pod) = attributor.get_pod_by_ip(side.ip).await {
        let pod_meta = K8sObjectMeta::from(pod.as_ref());
        let owner = attributor.get_top_level_controller(&pod);
        return Some(EnrichedInfo::Pod {
            pod: pod_meta,
            owner,
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
            backend_ips: backend_ips.unwrap_or_default(),
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
