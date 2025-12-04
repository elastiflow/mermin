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
}

impl Default for MetricsOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_address: Ipv4Addr::UNSPECIFIED.to_string(),
            port: 10250,
            debug_metrics_enabled: false,
            stale_metric_ttl: Duration::from_secs(300),
        }
    }
}
