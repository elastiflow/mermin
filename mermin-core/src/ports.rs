use crate::k8s::resource_parser::{EnrichedFlowData};
use async_trait::async_trait;
use anyhow::Result;

/// This is the Output Port.
/// The core application logic will use this trait to send data out,
/// remaining completely unaware of the final destination (OTLP, Kafka, etc.).
#[async_trait]
pub trait FlowExporterPort: Send + Sync {
    async fn export_flow(&self, packet: Result<EnrichedFlowData>);
}

