//! Metric cleanup tracker for managing stale metrics with configurable TTL.
//!
//! This module provides infrastructure to automatically clean up metrics for deleted resources
//! (interfaces, K8s objects, tasks) after a configurable time-to-live period.
//!
//! ## Problem
//!
//! High-cardinality debug metrics (with per-interface, per-task labels) can cause unbounded
//! memory growth in production environments when resources are frequently created and destroyed.
//! Prometheus doesn't automatically remove metric series even when resources no longer exist.
//!
//! ## Solution
//!
//! The [`MetricCleanupTracker`] schedules cleanup of metrics after a resource is deleted,
//! allowing a TTL grace period for resources that might come back (e.g., pod restarts).
//!
//! ## Usage
//!
//! - Only needed when `debug_metrics_enabled = true`
//! - TTL = 0s: Immediate cleanup when resource deleted
//! - TTL > 0s: Cleanup after grace period expires
//! - Cleanup runs in background task spawned by main

use std::{sync::Arc, time::Duration};

use dashmap::DashMap;
use tokio::time::Instant;
use tracing::{debug, trace};

use crate::metrics;

/// Tracks resources and schedules cleanup of their associated metrics after TTL expires.
///
/// When a resource is deleted (interface removed, K8s object deleted, task completed),
/// this tracker schedules cleanup of the metrics. If TTL > 0, metrics persist for the TTL
/// duration to handle brief resource downtimes. If TTL = 0, cleanup is immediate.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use mermin::metrics::cleanup::MetricCleanupTracker;
///
/// let tracker = MetricCleanupTracker::new(Duration::from_secs(300), true);
///
/// tracker.mark_interface_active("eth0");
///
/// tracker.schedule_interface_cleanup("eth0".to_string());
/// ```
#[derive(Clone)]
pub struct MetricCleanupTracker {
    /// Tracks when each interface was scheduled for cleanup
    interface_metrics: Arc<DashMap<String, Instant>>,
    /// Tracks when each K8s resource was scheduled for cleanup
    k8s_resource_metrics: Arc<DashMap<String, Instant>>,
    /// Tracks when each task was scheduled for cleanup
    task_metrics: Arc<DashMap<String, Instant>>,
    /// Time-to-live for metrics after resource deletion
    ttl: Duration,
    /// Whether debug metrics are enabled (cleanup only needed when debug metrics are registered)
    debug_enabled: bool,
}

impl MetricCleanupTracker {
    /// Create a new cleanup tracker.
    pub fn new(ttl: Duration, debug_enabled: bool) -> Self {
        Self {
            interface_metrics: Arc::new(DashMap::new()),
            k8s_resource_metrics: Arc::new(DashMap::new()),
            task_metrics: Arc::new(DashMap::new()),
            ttl,
            debug_enabled,
        }
    }

    /// Mark an interface as active (removes from cleanup schedule if present).
    ///
    /// Call this when an interface is created or used to prevent premature cleanup.
    ///
    /// # Note
    ///
    /// The internal `debug_enabled` check provides defense-in-depth: even if callers
    /// mistakenly call this when debug metrics are disabled, it's a safe no-op.
    pub fn mark_interface_active(&self, iface: &str) {
        if self.debug_enabled {
            self.interface_metrics.remove(iface);
        }
    }

    /// Schedule cleanup for an interface's metrics.
    ///
    /// If TTL = 0, cleanup happens immediately. Otherwise, cleanup is scheduled
    /// for TTL duration from now.
    ///
    /// # Note
    ///
    /// The internal `debug_enabled` check provides defense-in-depth: even if callers
    /// mistakenly call this when debug metrics are disabled, it's a safe no-op.
    pub fn schedule_interface_cleanup(&self, iface: String) {
        if !self.debug_enabled {
            return;
        }

        if self.ttl.is_zero() {
            metrics::registry::remove_interface_metrics(&iface);
        } else {
            let cleanup_time = Instant::now() + self.ttl;
            self.interface_metrics.insert(iface, cleanup_time);
        }
    }

    /// Mark a K8s resource as active (removes from cleanup schedule if present).
    #[allow(dead_code)]
    pub fn mark_k8s_resource_active(&self, resource: &str) {
        if self.debug_enabled {
            self.k8s_resource_metrics.remove(resource);
        }
    }

    /// Schedule cleanup for a K8s resource's metrics.
    pub fn schedule_k8s_cleanup(&self, resource: String) {
        if !self.debug_enabled {
            return;
        }

        if self.ttl.is_zero() {
            metrics::registry::remove_k8s_resource_metrics(&resource);
        } else {
            let cleanup_time = Instant::now() + self.ttl;
            self.k8s_resource_metrics.insert(resource, cleanup_time);
        }
    }

    /// Mark a task as active (removes from cleanup schedule if present).
    #[allow(dead_code)]
    pub fn mark_task_active(&self, task_name: &str) {
        if self.debug_enabled {
            self.task_metrics.remove(task_name);
        }
    }

    /// Schedule cleanup for a task's metrics.
    #[allow(dead_code)]
    pub fn schedule_task_cleanup(&self, task_name: String) {
        if !self.debug_enabled {
            return;
        }

        if self.ttl.is_zero() {
            metrics::registry::remove_task_metrics(&task_name);
        } else {
            let cleanup_time = Instant::now() + self.ttl;
            self.task_metrics.insert(task_name, cleanup_time);
        }
    }

    /// Run the background cleanup loop.
    ///
    /// Periodically scans for expired metrics and removes them.
    /// Should be spawned as a background task.
    ///
    /// The loop will exit gracefully when receiving a shutdown signal.
    pub async fn run_cleanup_loop(self, mut shutdown_rx: tokio::sync::broadcast::Receiver<()>) {
        if !self.debug_enabled || self.ttl.is_zero() {
            debug!(
                event.name = "metrics.cleanup.loop_disabled",
                debug_enabled = self.debug_enabled,
                ttl_seconds = self.ttl.as_secs(),
                "metric cleanup background loop not needed"
            );
            return;
        }

        // Check at least every 30 seconds, or every TTL/4 (whichever is longer)
        // This ensures we don't check too frequently for very long TTLs,
        // while still being responsive for short TTLs.
        let check_interval = Duration::from_secs(30.max(self.ttl.as_secs() / 4));

        // Invariant: check_interval is always >= 30 seconds
        debug_assert!(
            check_interval >= Duration::from_secs(30),
            "check interval should be at least 30 seconds"
        );

        loop {
            tokio::select! {
                _ = tokio::time::sleep(check_interval) => {
                    // Perform cleanup sweep
                    let now = Instant::now();
                    let mut cleaned_interfaces = 0;
                    let mut cleaned_k8s = 0;
                    let mut cleaned_tasks = 0;

                    self.interface_metrics.retain(|iface, &mut cleanup_time| {
                        if now >= cleanup_time {
                            metrics::registry::remove_interface_metrics(iface);
                            trace!(
                                event.name = "metrics.cleanup.interface_expired",
                                interface = %iface,
                                "cleaned up expired interface metrics"
                            );
                            cleaned_interfaces += 1;
                            false
                        } else {
                            true
                        }
                    });

                    self.k8s_resource_metrics
                        .retain(|resource, &mut cleanup_time| {
                            if now >= cleanup_time {
                                metrics::registry::remove_k8s_resource_metrics(resource);
                                trace!(
                                    event.name = "metrics.cleanup.k8s_resource_expired",
                                    resource = %resource,
                                    "cleaned up expired K8s resource metrics"
                                );
                                cleaned_k8s += 1;
                                false
                            } else {
                                true
                            }
                        });

                    self.task_metrics.retain(|task_name, &mut cleanup_time| {
                        if now >= cleanup_time {
                            metrics::registry::remove_task_metrics(task_name);
                            trace!(
                                event.name = "metrics.cleanup.task_expired",
                                task_name = %task_name,
                                "cleaned up expired task metrics"
                            );
                            cleaned_tasks += 1;
                            false
                        } else {
                            true
                        }
                    });

                    if cleaned_interfaces > 0 || cleaned_k8s > 0 || cleaned_tasks > 0 {
                        trace!(
                            event.name = "metrics.cleanup.sweep_completed",
                            cleaned_interfaces,
                            cleaned_k8s_resources = cleaned_k8s,
                            cleaned_tasks,
                            pending_interfaces = self.interface_metrics.len(),
                            pending_k8s_resources = self.k8s_resource_metrics.len(),
                            pending_tasks = self.task_metrics.len(),
                            "metric cleanup sweep completed"
                        );
                    }
                }
                _ = shutdown_rx.recv() => {
                    debug!(
                        event.name = "metrics.cleanup.shutdown",
                        pending_interfaces = self.interface_metrics.len(),
                        pending_k8s_resources = self.k8s_resource_metrics.len(),
                        pending_tasks = self.task_metrics.len(),
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
        let tracker = MetricCleanupTracker::new(Duration::from_secs(300), true);

        // Verify tracker starts with empty state
        assert_eq!(tracker.interface_metrics.len(), 0);
        assert_eq!(tracker.k8s_resource_metrics.len(), 0);
        assert_eq!(tracker.task_metrics.len(), 0);
        assert_eq!(tracker.ttl, Duration::from_secs(300));
        assert!(tracker.debug_enabled);
    }

    #[test]
    fn test_cleanup_tracker_disabled_when_debug_off() {
        let tracker = MetricCleanupTracker::new(Duration::from_secs(300), false);

        // Schedule cleanups - should be no-ops when debug is disabled
        tracker.schedule_interface_cleanup("eth0".to_string());
        tracker.schedule_k8s_cleanup("Pod".to_string());
        tracker.schedule_task_cleanup("test-task".to_string());

        // Verify nothing was scheduled (no-op behavior)
        assert_eq!(tracker.interface_metrics.len(), 0);
        assert_eq!(tracker.k8s_resource_metrics.len(), 0);
        assert_eq!(tracker.task_metrics.len(), 0);
    }

    #[tokio::test]
    async fn test_cleanup_tracker_basic_flow() {
        // Create tracker with 1 second TTL
        let tracker = MetricCleanupTracker::new(Duration::from_secs(1), true);

        // Schedule cleanup for an interface
        tracker.schedule_interface_cleanup("test-iface".to_string());
        assert_eq!(tracker.interface_metrics.len(), 1);
        assert!(tracker.interface_metrics.contains_key("test-iface"));

        // Mark the same interface as active (should remove from cleanup schedule)
        tracker.mark_interface_active("test-iface");
        assert_eq!(tracker.interface_metrics.len(), 0);

        // Schedule again
        tracker.schedule_interface_cleanup("test-iface".to_string());
        assert_eq!(tracker.interface_metrics.len(), 1);
    }

    #[tokio::test]
    async fn test_immediate_cleanup_with_zero_ttl() {
        let _ = metrics::registry::init_registry(true);

        // Create tracker with immediate cleanup (TTL=0)
        let tracker = MetricCleanupTracker::new(Duration::ZERO, true);

        // Schedule cleanup - should happen immediately (not scheduled for later)
        tracker.schedule_interface_cleanup("immediate-cleanup-iface".to_string());
        tracker.schedule_k8s_cleanup("immediate-cleanup-resource".to_string());
        tracker.schedule_task_cleanup("immediate-cleanup-task".to_string());

        // Verify nothing was scheduled (cleanup happened immediately)
        assert_eq!(tracker.interface_metrics.len(), 0);
        assert_eq!(tracker.k8s_resource_metrics.len(), 0);
        assert_eq!(tracker.task_metrics.len(), 0);
    }

    #[tokio::test]
    async fn test_cleanup_loop_shutdown() {
        let tracker = MetricCleanupTracker::new(Duration::from_secs(60), true);
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

        // Spawn cleanup loop
        let handle = tokio::spawn(async move {
            tracker.run_cleanup_loop(shutdown_rx).await;
        });

        // Give it a moment to start
        time::sleep(Duration::from_millis(10)).await;

        // Send shutdown signal
        let _ = shutdown_tx.send(());

        // Loop should exit gracefully
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("cleanup loop should exit within 1 second")
            .expect("cleanup loop task should not panic");
    }

    #[tokio::test]
    async fn test_cleanup_loop_disabled_with_zero_ttl() {
        let tracker = MetricCleanupTracker::new(Duration::ZERO, true);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

        // Should return immediately without looping
        tracker.run_cleanup_loop(shutdown_rx).await;

        // If we get here, the function returned immediately (good!)
    }
}
