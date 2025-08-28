use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::runtime::conf::conf_serde::duration;

/// Configuration for the high-performance flow processing pipeline.
///
/// The pipeline architecture provides optimal performance through parallel processing
/// of network flows using channel-based communication between specialized workers.
/// This configuration allows tuning the pipeline for different deployment scenarios
/// from high-traffic enterprise environments to memory-constrained edge deployments.
///
/// # Architecture Overview
///
/// ```text
/// eBPF Ring Buffer → Packet Reader → Flow Workers → Flow Store
///                                 ↓
///                     Enrichment Workers → Output
/// ```
///
/// # Performance Characteristics
///
/// - **Throughput**: Thousands of packets per second with parallel processing
/// - **Latency**: Low-latency packet processing with non-blocking operations  
/// - **Scalability**: Configurable workers and buffers scale with available resources
/// - **Reliability**: Fault-tolerant design with graceful degradation under load
///
/// # Configuration Guidelines
///
/// - **packet_channel_capacity**: Start with 10K, increase for high-traffic environments
/// - **flow_workers**: Typically 1-2 per CPU core for optimal performance
/// - **enrichment_workers**: Usually 1 is sufficient unless K8s API is slow
/// - **enable_backpressure**: Always true for production deployments
/// - **enable_metrics**: Enable for production monitoring, disable to reduce overhead
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PipelineConf {
    /// Capacity of the channel for packet events between the ring buffer reader and flow workers
    /// - Default: 10000
    /// - Example: Increase for high-traffic environments, decrease for memory-constrained systems
    #[serde(default = "defaults::packet_channel_capacity")]
    pub packet_channel_capacity: usize,

    /// Capacity of the channel for enriched flow events
    /// - Default: 1000
    /// - Example: Should be smaller than packet_channel_capacity as enriched events are processed slower
    #[serde(default = "defaults::enrichment_channel_capacity")]
    pub enrichment_channel_capacity: usize,

    /// Number of worker tasks for flow processing
    /// - Default: 2
    /// - Example: Increase for high CPU systems, keep at 1-2 for most deployments
    #[serde(default = "defaults::flow_workers")]
    pub flow_workers: usize,

    /// Number of worker tasks for Kubernetes enrichment
    /// - Default: 1
    /// - Example: Increase if K8s API calls are slow, but don't exceed K8s API rate limits
    #[serde(default = "defaults::enrichment_workers")]
    pub enrichment_workers: usize,

    /// Interval for logging pipeline statistics
    /// - Default: 30s
    /// - Example: Set to 10s for more frequent monitoring, 60s for less verbose logging
    #[serde(default = "defaults::stats_interval", with = "duration")]
    pub stats_interval: Duration,

    /// Maximum time to wait for graceful shutdown of pipeline components
    /// - Default: 5s
    /// - Example: Increase for environments with slow disk I/O or network operations
    #[serde(default = "defaults::shutdown_timeout", with = "duration")]
    pub shutdown_timeout: Duration,

    /// Whether to enable backpressure handling when channels are full
    /// - Default: true
    /// - Example: Set to false if you prefer dropping packets over blocking
    #[serde(default = "defaults::enable_backpressure")]
    pub enable_backpressure: bool,

    /// Whether to enable detailed performance metrics collection
    /// - Default: false
    /// - Example: Enable for production monitoring, disable for reduced overhead
    #[serde(default = "defaults::enable_metrics")]
    pub enable_metrics: bool,
}

impl Default for PipelineConf {
    fn default() -> Self {
        Self {
            packet_channel_capacity: defaults::packet_channel_capacity(),
            enrichment_channel_capacity: defaults::enrichment_channel_capacity(),
            flow_workers: defaults::flow_workers(),
            enrichment_workers: defaults::enrichment_workers(),
            stats_interval: defaults::stats_interval(),
            shutdown_timeout: defaults::shutdown_timeout(),
            enable_backpressure: defaults::enable_backpressure(),
            enable_metrics: defaults::enable_metrics(),
        }
    }
}

mod defaults {
    use std::time::Duration;

    pub fn packet_channel_capacity() -> usize {
        10000
    }

    pub fn enrichment_channel_capacity() -> usize {
        1000
    }

    pub fn flow_workers() -> usize {
        2
    }

    pub fn enrichment_workers() -> usize {
        1
    }

    pub fn stats_interval() -> Duration {
        Duration::from_secs(30)
    }

    pub fn shutdown_timeout() -> Duration {
        Duration::from_secs(5)
    }

    pub fn enable_backpressure() -> bool {
        true
    }

    pub fn enable_metrics() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_defaults() {
        let pipeline = PipelineConf::default();

        assert_eq!(pipeline.packet_channel_capacity, 10000);
        assert_eq!(pipeline.enrichment_channel_capacity, 1000);
        assert_eq!(pipeline.flow_workers, 2);
        assert_eq!(pipeline.enrichment_workers, 1);
        assert_eq!(pipeline.stats_interval, Duration::from_secs(30));
        assert_eq!(pipeline.shutdown_timeout, Duration::from_secs(5));
        assert!(pipeline.enable_backpressure);
        assert!(!pipeline.enable_metrics);
    }

    #[test]
    fn test_pipeline_serialization() {
        let pipeline = PipelineConf::default();

        // Test that it can be serialized and deserialized
        let serialized = serde_yaml::to_string(&pipeline).expect("should serialize");
        let deserialized: PipelineConf =
            serde_yaml::from_str(&serialized).expect("should deserialize");

        assert_eq!(
            pipeline.packet_channel_capacity,
            deserialized.packet_channel_capacity
        );
        assert_eq!(pipeline.flow_workers, deserialized.flow_workers);
        assert_eq!(
            pipeline.enable_backpressure,
            deserialized.enable_backpressure
        );
    }
}
