use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use log::info;
use mermin_common::{IpAddrType, PacketMeta};

use crate::{otlp::filter::PacketFilter, runtime::props::TracePipeline};

/// Custom error type for router operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterError {
    UnknownIpAddrType,
}

impl std::fmt::Display for RouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouterError::UnknownIpAddrType => write!(f, "unknown ip address type"),
        }
    }
}

impl std::error::Error for RouterError {}

/// Extract IP addresses from PacketMeta fields
fn extract_ip_addresses(
    ip_addr_type: IpAddrType,
    src_ipv4_addr: [u8; 4],
    dst_ipv4_addr: [u8; 4],
    src_ipv6_addr: [u8; 16],
    dst_ipv6_addr: [u8; 16],
) -> Result<(IpAddr, IpAddr), RouterError> {
    match ip_addr_type {
        IpAddrType::Unknown => Err(RouterError::UnknownIpAddrType),
        IpAddrType::Ipv4 => {
            let src = IpAddr::V4(Ipv4Addr::from(src_ipv4_addr));
            let dst = IpAddr::V4(Ipv4Addr::from(dst_ipv4_addr));
            Ok((src, dst))
        }
        IpAddrType::Ipv6 => {
            let src = IpAddr::V6(Ipv6Addr::from(src_ipv6_addr));
            let dst = IpAddr::V6(Ipv6Addr::from(dst_ipv6_addr));
            Ok((src, dst))
        }
    }
}

/// Holds the routing and filtering logic for all configured agent pipelines.
pub struct PipelineRouter {
    pipelines: HashMap<String, PipelineWithFilter>,
}

struct PipelineWithFilter {
    filter: PacketFilter,
}

impl PipelineRouter {
    /// Creates a new router from the resolved agent traces configuration.
    pub fn new(agent_traces: &HashMap<String, TracePipeline>) -> Self {
        let mut pipelines = HashMap::new();

        for (name, pipeline_config) in agent_traces {
            info!("compiling filter for agent pipeline: '{name}'");

            // Create a specific PacketFilter for this pipeline.
            let filter = PacketFilter::new(
                pipeline_config.source_filter.clone(),
                pipeline_config.destination_filter.clone(),
            );

            pipelines.insert(name.clone(), PipelineWithFilter { filter });
        }

        Self { pipelines }
    }

    /// Routes a PacketMeta and returns a list of pipelines it should be sent to.
    pub fn route_packet(&self, packet: &PacketMeta) -> Result<Vec<String>, RouterError> {
        // Extract IP addresses from PacketMeta
        let (src_ip, dst_ip) = extract_ip_addresses(
            packet.ip_addr_type,
            packet.src_ipv4_addr,
            packet.dst_ipv4_addr,
            packet.src_ipv6_addr,
            packet.dst_ipv6_addr,
        )?;

        // Extract ports from PacketMeta
        let src_port = packet.src_port();
        let dst_port = packet.dst_port();

        let mut matching_pipelines = Vec::new();

        // Apply each pipeline's filter
        for (name, pipeline) in &self.pipelines {
            if pipeline
                .filter
                .should_produce_span(src_ip, src_port, dst_ip, dst_port)
            {
                matching_pipelines.push(name.clone());
            }
        }

        Ok(matching_pipelines)
    }
}
