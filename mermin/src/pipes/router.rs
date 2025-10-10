use std::collections::HashMap;

use log::info;
use mermin_common::PacketMeta;

use crate::{
    ip::{Error, resolve_addrs},
    pipes::filter::PacketFilter,
    runtime::props::TracePipeline,
};

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
    pub fn route_packet(&self, packet: &PacketMeta) -> Result<Vec<String>, Error> {
        // Extract IP addresses from PacketMeta
        let (src_ip, dst_ip) = resolve_addrs(
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
                .should_process(src_ip, src_port, dst_ip, dst_port)
            {
                matching_pipelines.push(name.clone());
            }
        }

        Ok(matching_pipelines)
    }
}
