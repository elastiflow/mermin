use std::{net::Ipv4Addr, time::Duration};

use serde::{Deserialize, Serialize};

use crate::runtime::conf::conf_serde::duration;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MetricsOptions {
    /// Enable the metrics server.
    pub enabled: bool,
    /// The network address the metrics server will listen on.
    pub listen_address: String,
    /// The port the metrics server will listen on.
    pub port: u16,
    /// Enable debug metrics with high-cardinality labels (per-interface, per-task, etc.).
    /// WARNING: This will significantly increase memory usage. Do not use in production unless necessary.
    pub debug_metrics_enabled: bool,
    /// Time-to-live for stale metrics after resource deletion.
    /// Examples: "5m", "300s", "1h"
    /// 0s = immediate cleanup, >0s = cleanup after TTL expires.
    /// Only applies when debug_metrics_enabled = true.
    #[serde(with = "duration")]
    pub stale_metric_ttl: Duration,

    /// Optional histogram bucket overrides, keyed by metric name.
    /// Omit the block to use default buckets for all histograms.
    #[serde(default)]
    pub histogram_buckets: Option<HistogramBuckets>,
}

impl Default for MetricsOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_address: Ipv4Addr::UNSPECIFIED.to_string(),
            port: 10250,
            debug_metrics_enabled: false,
            stale_metric_ttl: Duration::from_secs(300),
            histogram_buckets: None,
        }
    }
}

/// Optional histogram bucket overrides keyed by metric name.
///
/// All fields are optional; omit the block or individual keys to use default buckets.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct HistogramBuckets {
    /// Custom buckets for `mermin_pipeline_duration_seconds` histogram.
    /// If not specified, uses default buckets optimized for pipeline stages (10μs to 60s).
    pub mermin_pipeline_duration_seconds: Option<Vec<f64>>,

    /// Custom buckets for `mermin_export_batch_size` histogram.
    /// If not specified, uses default buckets: [1, 10, 50, 100, 250, 500, 1000].
    pub mermin_export_batch_size: Option<Vec<f64>>,

    /// Custom buckets for `mermin_k8s_watcher_ip_index_update_duration_seconds` histogram.
    /// If not specified, uses default buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0].
    pub mermin_k8s_watcher_ip_index_update_duration_seconds: Option<Vec<f64>>,

    /// Custom buckets for `mermin_taskmanager_shutdown_duration_seconds` histogram.
    /// If not specified, uses default buckets: [0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 120.0].
    pub mermin_taskmanager_shutdown_duration_seconds: Option<Vec<f64>>,
}
