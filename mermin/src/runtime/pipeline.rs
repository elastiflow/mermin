use std::{sync::Arc, time::Duration};

use anyhow::Result;
use log::{debug, error, info, warn};
use mermin_common::PacketMeta;
use tokio::{
    sync::{mpsc, oneshot},
    time::interval,
};

use crate::{
    community_id::CommunityIdGenerator,
    flow::FlowRecord,
    flow_manager::FlowManager,
    k8s::Attributor,
    runtime::conf::{Config, pipeline::PipelineConf},
};

/// Events that flow through the processing pipeline
#[derive(Debug, Clone)]
pub enum Event {
    /// A new packet has been received from eBPF
    PacketReceived {
        packet: PacketMeta,
        community_id: String,
    },
    /// Request to expire flows based on configuration
    ExpireFlows,
    /// Request to release a specific flow
    ReleaseFlow {
        community_id: String,
        response: oneshot::Sender<Option<FlowRecord>>,
    },
    /// Shutdown signal
    Shutdown,
}

/// Enriched flow data for downstream processing
#[derive(Debug, Clone)]
pub struct EnrichedFlowEvent {
    pub flow_record: FlowRecord,
    pub packet: PacketMeta,
    pub is_new_flow: bool,
    pub kubernetes_metadata: Option<String>,
}

/// High-performance flow processing pipeline using channels
pub struct Pipeline {
    config: PipelineConf,
    flow_event_tx: mpsc::Sender<Event>,
    enriched_event_rx: mpsc::Receiver<EnrichedFlowEvent>,
}

impl Pipeline {
    /// Create a new processing pipeline
    pub fn new(
        app_config: Config,
        community_id_gen: Arc<CommunityIdGenerator>,
        kube_client: Option<Arc<Attributor>>,
    ) -> Self {
        let pipeline_config = app_config.pipeline.clone();
        let (flow_event_tx, flow_event_rx) = mpsc::channel(pipeline_config.packet_channel_capacity);
        let (enriched_event_tx, enriched_event_rx) =
            mpsc::channel(pipeline_config.enrichment_channel_capacity);

        // Start the flow processing workers
        Self::start_flow_workers(
            app_config.clone(),
            flow_event_rx,
            enriched_event_tx.clone(),
            pipeline_config.flow_workers,
        );

        // Start the enrichment workers
        if let Some(client) = kube_client {
            Self::start_enrichment_workers(
                client,
                enriched_event_tx,
                pipeline_config.enrichment_workers,
            );
        }

        // Start the flow expiration timer
        Self::start_expiration_timer(flow_event_tx.clone(), app_config.flow.expiry_interval);

        Self {
            config: pipeline_config,
            flow_event_tx,
            enriched_event_rx,
        }
    }

    /// Get a sender handle for sending flow events
    pub fn sender(&self) -> mpsc::Sender<Event> {
        self.flow_event_tx.clone()
    }

    /// Get the receiver for enriched flow events
    pub async fn recv_enriched_event(&mut self) -> Option<EnrichedFlowEvent> {
        self.enriched_event_rx.recv().await
    }

    /// Send a packet event to the pipeline
    pub async fn send_packet(&self, packet: PacketMeta, community_id: String) -> Result<()> {
        self.flow_event_tx
            .send(Event::PacketReceived {
                packet,
                community_id,
            })
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send packet event: {}", e))
    }

    /// Release a specific flow
    pub async fn release_flow(&self, community_id: String) -> Result<Option<FlowRecord>> {
        let (tx, rx) = oneshot::channel();
        self.flow_event_tx
            .send(Event::ReleaseFlow {
                community_id,
                response: tx,
            })
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send release request: {}", e))?;

        rx.await
            .map_err(|e| anyhow::anyhow!("Failed to receive release response: {}", e))
    }

    /// Shutdown the pipeline
    pub async fn shutdown(&self) -> Result<()> {
        self.flow_event_tx
            .send(Event::Shutdown)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send shutdown signal: {}", e))
    }

    /// Start flow processing workers
    fn start_flow_workers(
        config: Config,
        mut flow_event_rx: mpsc::Receiver<Event>,
        enriched_event_tx: mpsc::Sender<EnrichedFlowEvent>,
        _worker_count: usize,
    ) {
        // Currently using a single worker to maintain flow consistency.
        // Multiple workers would require flow sharding by Community ID hash
        // to avoid concurrent access to the same flow records.
        tokio::spawn(async move {
            let mut flow_manager = FlowManager::new(config.flow);
            info!("Flow processing worker started");

            while let Some(event) = flow_event_rx.recv().await {
                match event {
                    Event::PacketReceived {
                        packet,
                        community_id,
                    } => {
                        // Process the packet
                        let is_new_flow = flow_manager
                            .store_mut()
                            .add_packet(community_id.clone(), &packet);

                        if is_new_flow {
                            debug!("Created new flow: {}", community_id);
                        }

                        // Get the flow record for enrichment
                        if let Some(flow_record) = flow_manager.store().get_flow(&community_id) {
                            let enriched_event = EnrichedFlowEvent {
                                flow_record: flow_record.clone(),
                                packet,
                                is_new_flow,
                                kubernetes_metadata: None, // Will be filled by enrichment workers
                            };

                            if let Err(e) = enriched_event_tx.send(enriched_event).await {
                                warn!("Failed to send enriched event: {}", e);
                            }
                        }
                    }
                    Event::ExpireFlows => {
                        let released_flows = flow_manager.release_expired_flows();
                        if !released_flows.is_empty() {
                            info!("Released {} expired flows", released_flows.len());
                        }
                    }
                    Event::ReleaseFlow {
                        community_id,
                        response,
                    } => {
                        let released = flow_manager.release_flow(&community_id);
                        if let Err(_) = response.send(released) {
                            warn!("Failed to send release response");
                        }
                    }
                    Event::Shutdown => {
                        info!("Flow processing worker shutting down");
                        break;
                    }
                }
            }
        });
    }

    /// Start Kubernetes enrichment workers
    fn start_enrichment_workers(
        kube_client: Arc<Attributor>,
        enriched_event_tx: mpsc::Sender<EnrichedFlowEvent>,
        worker_count: usize,
    ) {
        for worker_id in 0..worker_count {
            let _client = kube_client.clone();
            let _tx = enriched_event_tx.clone();

            tokio::spawn(async move {
                info!("Kubernetes enrichment worker {} started", worker_id);

                // In a real implementation, you'd receive events from a channel
                // and enrich them with Kubernetes metadata
                // This is a placeholder for the enrichment logic

                // Example enrichment loop would look like:
                // while let Some(event) = enrichment_rx.recv().await {
                //     let enriched = enrich_with_k8s(event, &_client).await;
                //     _tx.send(enriched).await.ok();
                // }
            });
        }
    }

    /// Start the flow expiration timer
    fn start_expiration_timer(flow_event_tx: mpsc::Sender<Event>, expiration_interval: Duration) {
        tokio::spawn(async move {
            let mut timer = interval(expiration_interval);
            info!(
                "Flow expiration timer started (interval: {:?})",
                expiration_interval
            );

            loop {
                timer.tick().await;

                if let Err(e) = flow_event_tx.send(Event::ExpireFlows).await {
                    error!("Failed to send expiration event: {}", e);
                    break;
                }
            }
        });
    }
}

/// Metrics and monitoring for the pipeline
#[derive(Debug, Default)]
pub struct PipelineMetrics {
    pub packets_processed: u64,
    pub flows_created: u64,
    pub flows_expired: u64,
    pub enrichment_queue_size: usize,
    pub processing_latency_ms: f64,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use mermin_common::IpAddrType;
    use network_types::ip::IpProto;

    use super::*;
    use crate::runtime::conf::{flow::Flow as FlowConfig, pipeline::Pipeline as PipelineConf};

    fn create_test_config() -> Config {
        Config {
            interface: vec!["test".to_string()],
            config_path: None,
            auto_reload: false,
            log_level: tracing::Level::INFO,
            flow: FlowConfig {
                expiry_interval: Duration::from_secs(1),
                max_active_life: Duration::from_secs(60),
                flow_generic: Duration::from_secs(30),
                icmp: Duration::from_secs(10),
                tcp: Duration::from_secs(20),
                tcp_fin: Duration::from_secs(5),
                tcp_rst: Duration::from_secs(5),
                udp: Duration::from_secs(20),
            },
            pipeline: PipelineConf::default(),
        }
    }

    fn create_test_packet() -> PacketMeta {
        PacketMeta {
            ip_addr_type: IpAddrType::Ipv4,
            src_ipv4_addr: [10, 0, 0, 1],
            dst_ipv4_addr: [10, 0, 0, 2],
            src_ipv6_addr: [0; 16],
            dst_ipv6_addr: [0; 16],
            src_port: 8080u16.to_be_bytes(),
            dst_port: 80u16.to_be_bytes(),
            l3_octet_count: 1500,
            proto: IpProto::Tcp,
        }
    }

    #[tokio::test]
    async fn test_pipeline_creation() {
        let config = create_test_config();
        let community_id_gen = Arc::new(CommunityIdGenerator::new(0));

        let pipeline = Pipeline::new(
            config,
            community_id_gen,
            None, // No K8s client for test
        );

        // Test sending a packet
        let packet = create_test_packet();
        let result = pipeline.send_packet(packet, "test_flow".to_string()).await;
        assert!(result.is_ok());
    }
}
