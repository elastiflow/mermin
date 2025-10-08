use std::collections::HashMap;

use log::info;

use crate::{otlp::filter::PacketFilter, runtime::props::TracePipeline, span::flow::FlowSpan};

/// Holds the routing and filtering logic for all configured agent pipelines.
pub struct PipelineRouter {
    pipelines: HashMap<String, PipelineWithFilter>,
}

struct PipelineWithFilter {
    filter: PacketFilter,
    // You might also store resolved exporters here later.
    // exporters: Vec<ResolvedExporter>,
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

    /// Takes a FlowSpan and returns a list of pipelines it should be sent to.
    pub fn route(&self, span: &FlowSpan) -> Vec<String> {
        let mut matching_pipelines = Vec::new();

        for (name, pipeline) in &self.pipelines {
            if pipeline.filter.should_produce_span(
                span.attributes.source_address,
                span.attributes.source_port,
                span.attributes.destination_address,
                span.attributes.destination_port,
            ) {
                matching_pipelines.push(name.clone());
            }
        }

        matching_pipelines
    }
}
