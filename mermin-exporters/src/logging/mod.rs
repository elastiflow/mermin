use async_trait::async_trait;
use mermincore::{
    k8s::resource_parser::EnrichedFlowData,
    ports::FlowExporterPort,
};
use std::sync::Arc;
use tracing::info;
use anyhow::Result;

/// An adapter that implements the FlowExporterPort by logging the flow data.
/// This is useful for local development, debugging, or as a default exporter.
pub struct LoggingExporterAdapter;

impl LoggingExporterAdapter {
    /// Creates a new instance of the adapter.
    pub fn new() -> Self {
        Self
    }
}

// The Default trait is a good pattern for simple constructors.
impl Default for LoggingExporterAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FlowExporterPort for LoggingExporterAdapter {
    /// The implementation of the export_flow method.
    /// Instead of sending data to an external service, it just logs it.
    async fn export_flow(&self, packet: Result<EnrichedFlowData>) {
        // The `info!` macro is from the `tracing` crate.
        // `packet = ?packet` creates a structured log field named "packet"
        // containing the debug-formatted output of your struct.
        tracing::log::info!("Enriched packet: {enriched_packet:?}");
    }
}
