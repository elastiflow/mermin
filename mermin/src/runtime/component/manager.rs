use std::{sync::Arc, time::Duration};

use tokio::{
    sync::{broadcast, watch},
    time::Instant,
};
use tracing::{trace, warn};

use super::{
    error::{JoinError, ShutdownResult},
    handle::Handle,
};
use crate::{
    metrics,
    runtime::{conf::Conf, shutdown::ShutdownConfig},
};

/// Unified manager for all runtime components (async tasks and OS threads).
///
/// Components are registered in startup order and shut down in **reverse** order,
/// ensuring producers stop before consumers so channels can drain.
pub struct ComponentManager {
    handles: Vec<Handle>,
    shutdown_tx: broadcast::Sender<()>,
    config_tx: watch::Sender<Arc<Conf>>,
    config_rx: watch::Receiver<Arc<Conf>>,
}

impl ComponentManager {
    /// Create a new `ComponentManager` seeded with the initial configuration.
    pub fn new(initial_config: Conf) -> Self {
        let (shutdown_tx, _) = broadcast::channel(16);
        let (config_tx, config_rx) = watch::channel(Arc::new(initial_config));
        Self {
            handles: Vec::new(),
            shutdown_tx,
            config_tx,
            config_rx,
        }
    }

    /// Get a shutdown signal receiver. Components should `select!` on this
    /// to know when to begin their graceful shutdown.
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Get a config watch receiver. Hot-reloadable components use this to
    /// receive updated configuration without a restart.
    pub fn config_receiver(&self) -> watch::Receiver<Arc<Conf>> {
        self.config_rx.clone()
    }

    /// Broadcast a new configuration to all components watching for changes.
    pub fn reload_config(&self, new_config: Conf) {
        let _ = self.config_tx.send(Arc::new(new_config));
    }

    /// Register a component handle. Components are shut down in reverse
    /// registration order.
    pub fn register(&mut self, handle: Handle) {
        trace!(
            event.name = "component.registered",
            component.name = %handle.name(),
            "registered component"
        );
        self.handles.push(handle);
    }

    /// Shut down all registered components in reverse registration order.
    ///
    /// 1. Broadcast the shutdown signal to all `broadcast::Receiver`s.
    /// 2. For each component (in reverse order), signal its eventfd (if any)
    ///    and join. The total shutdown sequence is bounded by `config.timeout`;
    ///    each component gets whatever time remains in the budget.
    pub async fn shutdown(self, config: ShutdownConfig) -> ShutdownResult {
        let shutdown_start = Instant::now();
        let component_count = self.handles.len();

        trace!(
            event.name = "component_manager.shutdown.started",
            timeout_seconds = config.timeout.as_secs(),
            component_count = component_count,
            "starting component shutdown sequence"
        );

        // Broadcast shutdown signal to all subscribers
        let _ = self.shutdown_tx.send(());
        let mut components_completed: usize = 0;
        let mut failed_names: Vec<String> = Vec::new();

        // Shut down in reverse registration order
        let handles: Vec<Handle> = self.handles.into_iter().rev().collect();

        for handle in handles {
            let name = handle.name().to_string();
            handle.signal_shutdown();

            let remaining = config.timeout.saturating_sub(shutdown_start.elapsed());
            if remaining.is_zero() {
                failed_names.push(name);
                continue;
            }

            if let Err(e) = join_handle_with_timeout(handle, remaining).await {
                warn!(
                    event.name = "component_manager.shutdown.component_failed",
                    component.name = %name,
                    error.message = %e,
                    "component failed to shut down"
                );
                failed_names.push(name);
            } else {
                components_completed += 1;
            }
        }

        let duration = shutdown_start.elapsed();
        metrics::registry::shutdown_duration_seconds().observe(duration.as_secs_f64());

        if failed_names.is_empty() {
            ShutdownResult::Graceful {
                duration,
                components_completed,
            }
        } else {
            let components_failed = failed_names.len();
            warn!(
                event.name = "component_manager.shutdown.completed_with_failures",
                duration_ms = duration.as_millis(),
                components_completed,
                components_failed,
                failed = ?failed_names,
                "shutdown completed but some components failed or timed out"
            );
            ShutdownResult::ForcedTermination {
                duration,
                components_completed,
                components_failed,
                failed_names,
            }
        }
    }
}

/// Join a component handle with a timeout.
///
/// For async handles, awaits the `JoinHandle` directly.
/// For thread handles, uses `spawn_blocking` to avoid blocking the tokio runtime.
async fn join_handle_with_timeout(
    handle: Handle,
    timeout: Duration,
) -> Result<(), super::error::JoinError> {
    match handle {
        Handle::Async { join, .. } => match tokio::time::timeout(timeout, join).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(if e.is_cancelled() {
                JoinError::Cancelled
            } else {
                JoinError::AsyncPanic(format!("{e}"))
            }),
            Err(_) => Err(JoinError::Timeout(timeout)),
        },
        Handle::Thread { join, .. } => {
            match tokio::time::timeout(timeout, tokio::task::spawn_blocking(move || join.join()))
                .await
            {
                Ok(Ok(Ok(()))) => Ok(()),
                Ok(Ok(Err(_))) => Err(JoinError::ThreadPanic),
                Ok(Err(_)) => Err(JoinError::SpawnBlockingFailed),
                Err(_) => Err(JoinError::Timeout(timeout)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use tokio::time::{Duration, sleep};

    use super::*;
    use crate::metrics::{opts::MetricsOptions, registry::HistogramBucketConfig};

    fn init_test_metrics() {
        let metrics_opts = MetricsOptions::default();
        let bucket_config = HistogramBucketConfig::from(&metrics_opts);
        let _ = crate::metrics::registry::init_registry(false, bucket_config);
    }

    fn test_conf() -> Conf {
        Conf::default()
    }

    #[tokio::test]
    async fn test_async_task_shutdown_with_broadcast() {
        init_test_metrics();
        let mut mgr = ComponentManager::new(test_conf());
        let completed = Arc::new(AtomicBool::new(false));
        let completed_clone = completed.clone();

        let mut shutdown_rx = mgr.subscribe();
        let join = tokio::spawn(async move {
            let _ = shutdown_rx.recv().await;
            completed_clone.store(true, Ordering::SeqCst);
        });
        mgr.register(Handle::async_task("test-task", join));

        let config = ShutdownConfig {
            timeout: Duration::from_secs(5),
            ..Default::default()
        };
        let result = mgr.shutdown(config).await;

        assert!(completed.load(Ordering::SeqCst));
        assert!(matches!(
            result,
            ShutdownResult::Graceful {
                components_completed: 1,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_all_registered_components_complete_on_shutdown() {
        init_test_metrics();
        let mut mgr = ComponentManager::new(test_conf());
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));

        for i in 0..3 {
            let order_clone = order.clone();
            let mut shutdown_rx = mgr.subscribe();
            let join = tokio::spawn(async move {
                let _ = shutdown_rx.recv().await;
                // Small staggered sleep so completion order is deterministic
                sleep(Duration::from_millis(10 * (3 - i) as u64)).await;
                order_clone.lock().unwrap().push(i);
            });
            mgr.register(Handle::async_task(format!("task-{i}"), join));
        }

        let config = ShutdownConfig {
            timeout: Duration::from_secs(5),
            ..Default::default()
        };
        let result = mgr.shutdown(config).await;

        // All should complete since they respond to shutdown
        assert!(matches!(
            result,
            ShutdownResult::Graceful {
                components_completed: 3,
                ..
            }
        ));
        // Verify all tasks actually ran
        let completed = order.lock().unwrap();
        assert_eq!(completed.len(), 3);
    }

    #[tokio::test]
    async fn test_thread_shutdown() {
        init_test_metrics();
        let mut mgr = ComponentManager::new(test_conf());
        let completed = Arc::new(AtomicBool::new(false));
        let completed_clone = completed.clone();

        let handle = std::thread::spawn(move || {
            // Simulate some work
            std::thread::sleep(Duration::from_millis(10));
            completed_clone.store(true, Ordering::SeqCst);
        });
        mgr.register(Handle::thread("test-thread", handle));

        let config = ShutdownConfig {
            timeout: Duration::from_secs(5),
            ..Default::default()
        };
        let result = mgr.shutdown(config).await;

        assert!(completed.load(Ordering::SeqCst));
        assert!(matches!(
            result,
            ShutdownResult::Graceful {
                components_completed: 1,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_empty_manager_shutdown() {
        init_test_metrics();
        let mgr = ComponentManager::new(test_conf());
        let config = ShutdownConfig {
            timeout: Duration::from_secs(1),
            ..Default::default()
        };
        let result = mgr.shutdown(config).await;
        assert!(matches!(
            result,
            ShutdownResult::Graceful {
                components_completed: 0,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_config_reload_via_watch() {
        let conf = test_conf();
        let mgr = ComponentManager::new(conf.clone());
        let mut rx = mgr.config_receiver();

        // Initial value should match
        assert_eq!(rx.borrow_and_update().log_color, conf.log_color);

        // Send a new config with a different value
        let mut new_conf = conf.clone();
        new_conf.log_color = !conf.log_color;
        mgr.reload_config(new_conf.clone());

        // Receiver should see the change
        rx.changed().await.unwrap();
        assert_eq!(rx.borrow_and_update().log_color, new_conf.log_color);
    }
}
