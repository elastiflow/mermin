use async_trait::async_trait;
use anyhow::Result;
use crate::flow::base::EnrichedFlowData;

#[async_trait]
pub trait FlowExporter: Send + Sync {
    async fn export_flow(&self, packet: Result<EnrichedFlowData>);
    async fn shutdown(&self) -> Result<()>;
}

