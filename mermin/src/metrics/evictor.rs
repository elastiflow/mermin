//! Metric cleanup tracker for managing stale metrics with configurable TTL.
//!
//! This module provides infrastructure to automatically clean up metrics for deleted resources
//! (interfaces, K8s objects) after a configurable time-to-live period.
//!
//! ## Problem
//!
//! High-cardinality debug metrics (with per-interface labels) can cause unbounded
//! memory growth in production environments when resources are frequently created and destroyed.
//! Prometheus doesn't automatically remove metric series even when resources no longer exist.
//!
//! ## Solution
//!
//! The [`MetricsEvictor`] schedules cleanup of metrics after a resource is deleted,
//! allowing a TTL grace period for resources that might come back (e.g., pod restarts).
//!
//! ## Usage
//!
//! - TTL = 0s: Immediate cleanup when resource deleted
//! - TTL > 0s: Cleanup after grace period expires
//! - Cleanup runs in background task spawned by main

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::time::Instant;
use tracing::debug;

use crate::metrics;

#[derive(Clone)]
pub struct MetricsEvictor {
    interface_metrics: Arc<Mutex<HashMap<String, Instant>>>,
    k8s_resource_metrics: Arc<Mutex<HashMap<String, Instant>>>,
    ttl: Duration,
}

impl MetricsEvictor {
    pub fn new(ttl: Duration) -> Self {
        Self {
            interface_metrics: Arc::new(Mutex::new(HashMap::new())),
            k8s_resource_metrics: Arc::new(Mutex::new(HashMap::new())),
            ttl,
        }
    }

    pub fn mark_interface_active(&self, iface: &str) {
        self.interface_metrics.lock().unwrap().remove(iface);
    }

    pub fn schedule_interface_cleanup(&self, iface: String) {
        if self.ttl.is_zero() {
            metrics::registry::remove_interface_metrics(&iface);
        } else {
            let cleanup_time = Instant::now() + self.ttl;
            self.interface_metrics
                .lock()
                .unwrap()
                .insert(iface, cleanup_time);
        }
    }

    pub fn schedule_k8s_cleanup(&self, resource: String) {
        if self.ttl.is_zero() {
            metrics::registry::remove_k8s_resource_metrics(&resource);
        } else {
            let cleanup_time = Instant::now() + self.ttl;
            self.k8s_resource_metrics
                .lock()
                .unwrap()
                .insert(resource, cleanup_time);
        }
    }

    pub async fn run(self, mut shutdown_rx: tokio::sync::broadcast::Receiver<()>) {
        if self.ttl.is_zero() {
            return;
        }

        // Check at least every 30 seconds, or every TTL/4 (whichever is longer)
        // This ensures we don't check too frequently for very long TTLs,
        // while still being responsive for short TTLs.
        let check_interval = Duration::from_secs(30.max(self.ttl.as_secs() / 4));
        debug_assert!(
            check_interval >= Duration::from_secs(30),
            "check interval should be at least 30 seconds"
        );

        loop {
            tokio::select! {
                _ = tokio::time::sleep(check_interval) => {
                    let now = Instant::now();

                    self.interface_metrics.lock().unwrap().retain(|iface, &mut cleanup_time| {
                        if now >= cleanup_time {
                            metrics::registry::remove_interface_metrics(iface);
                            false
                        } else {
                            true
                        }
                    });

                    self.k8s_resource_metrics
                        .lock()
                        .unwrap()
                        .retain(|resource, &mut cleanup_time| {
                            if now >= cleanup_time {
                                metrics::registry::remove_k8s_resource_metrics(resource);
                                false
                            } else {
                                true
                            }
                        });
                }
                _ = shutdown_rx.recv() => {
                    debug!(
                        event.name = "metrics.cleanup.shutdown",
                        pending_interfaces = self.interface_metrics.lock().unwrap().len(),
                        pending_k8s_resources = self.k8s_resource_metrics.lock().unwrap().len(),
                        "metric cleanup loop shutting down"
                    );
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time;

    use super::*;

    #[test]
    fn test_cleanup_tracker_creation() {
        let tracker = MetricsEvictor::new(Duration::from_secs(300));
        assert_eq!(tracker.interface_metrics.lock().unwrap().len(), 0);
        assert_eq!(tracker.k8s_resource_metrics.lock().unwrap().len(), 0);
        assert_eq!(tracker.ttl, Duration::from_secs(300));
    }

    #[tokio::test]
    async fn test_cleanup_tracker_basic_flow() {
        let tracker = MetricsEvictor::new(Duration::from_secs(1));

        tracker.schedule_interface_cleanup("test-iface".to_string());
        assert_eq!(tracker.interface_metrics.lock().unwrap().len(), 1);
        assert!(
            tracker
                .interface_metrics
                .lock()
                .unwrap()
                .contains_key("test-iface")
        );

        tracker.mark_interface_active("test-iface");
        assert_eq!(tracker.interface_metrics.lock().unwrap().len(), 0);

        tracker.schedule_interface_cleanup("test-iface".to_string());
        assert_eq!(tracker.interface_metrics.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_immediate_cleanup_with_zero_ttl() {
        use crate::metrics::opts::MetricsOptions;
        let metrics_opts = MetricsOptions::default();
        let bucket_config = metrics::registry::HistogramBucketConfig::from(&metrics_opts);
        let _ = metrics::registry::init_registry(true, bucket_config);

        let tracker = MetricsEvictor::new(Duration::ZERO);
        tracker.schedule_interface_cleanup("immediate-cleanup-iface".to_string());
        tracker.schedule_k8s_cleanup("immediate-cleanup-resource".to_string());
        assert_eq!(tracker.interface_metrics.lock().unwrap().len(), 0);
        assert_eq!(tracker.k8s_resource_metrics.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_cleanup_loop_shutdown() {
        let tracker = MetricsEvictor::new(Duration::from_secs(60));
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

        let handle = tokio::spawn(async move {
            tracker.run(shutdown_rx).await;
        });

        time::sleep(Duration::from_millis(10)).await;
        let _ = shutdown_tx.send(());

        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("cleanup loop should exit within 1 second")
            .expect("cleanup loop task should not panic");
    }

    #[tokio::test]
    async fn test_cleanup_loop_disabled_with_zero_ttl() {
        let tracker = MetricsEvictor::new(Duration::ZERO);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        tracker.run(shutdown_rx).await;
    }
}
