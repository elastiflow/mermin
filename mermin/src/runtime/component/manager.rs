use std::time::Duration;

use tokio::{sync::broadcast, time::Instant};
use tracing::{trace, warn};

use super::{
    error::{JoinError, ShutdownResult},
    handle::Handle,
};
use crate::{metrics, runtime::shutdown::ShutdownConfig};

/// Unified manager for all runtime components (async tasks and OS threads).
///
/// Components are registered in startup order and shut down in **reverse** order,
/// ensuring producers stop before consumers so channels can drain.
pub struct ComponentManager {
    handles: Vec<Handle>,
    shutdown_tx: broadcast::Sender<()>,
}

impl ComponentManager {
    /// Create a new `ComponentManager`.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for ComponentManager {
    fn default() -> Self {
        // Capacity of 1 is sufficient: exactly one shutdown message is ever sent.
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            handles: Vec::new(),
            shutdown_tx,
        }
    }
}

impl ComponentManager {
    /// Get a shutdown signal receiver. Components should `select!` on this
    /// to know when to begin their graceful shutdown.
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
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
            let timed_out =
                tokio::time::timeout(timeout, tokio::task::spawn_blocking(move || join.join()))
                    .await;
            match timed_out {
                Err(_elapsed) => Err(JoinError::Timeout(timeout)),
                Ok(Err(_spawn_err)) => Err(JoinError::SpawnBlockingFailed),
                Ok(Ok(Err(_panic))) => Err(JoinError::ThreadPanic),
                Ok(Ok(Ok(()))) => Ok(()),
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

    use tokio::time::Duration;

    use super::*;
    use crate::metrics::{opts::MetricsOptions, registry::HistogramBucketConfig};

    fn init_test_metrics() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let metrics_opts = MetricsOptions::default();
            let bucket_config = HistogramBucketConfig::from(&metrics_opts);
            let _ = crate::metrics::registry::init_registry(false, bucket_config);
        });
    }

    #[tokio::test]
    async fn test_async_task_shutdown_with_broadcast() {
        init_test_metrics();
        let mut mgr = ComponentManager::new();
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
        let mut mgr = ComponentManager::new();
        let completed = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        for i in 0..3 {
            let count = Arc::clone(&completed);
            let mut shutdown_rx = mgr.subscribe();
            let join = tokio::spawn(async move {
                let _ = shutdown_rx.recv().await;
                count.fetch_add(1, Ordering::SeqCst);
                let _ = i;
            });
            mgr.register(Handle::async_task(format!("task-{i}"), join));
        }

        let config = ShutdownConfig {
            timeout: Duration::from_secs(5),
            ..Default::default()
        };
        let result = mgr.shutdown(config).await;

        assert!(matches!(
            result,
            ShutdownResult::Graceful {
                components_completed: 3,
                ..
            }
        ));
        assert_eq!(completed.load(Ordering::SeqCst), 3usize);
    }

    /// A component that ignores the shutdown signal should be abandoned when the
    /// timeout expires, producing a `ForcedTermination` result.
    #[tokio::test]
    async fn test_forced_termination_on_component_timeout() {
        init_test_metrics();
        let mut mgr = ComponentManager::new();

        // This task never responds to shutdown — it blocks indefinitely on a
        // channel that will never receive a message.
        let (_never_tx, never_rx) = tokio::sync::oneshot::channel::<()>();
        let join = tokio::spawn(async move {
            let _ = never_rx.await; // never resolves
        });
        mgr.register(Handle::async_task("stubborn-task", join));

        let config = ShutdownConfig {
            timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let result = mgr.shutdown(config).await;

        assert!(
            matches!(
                result,
                ShutdownResult::ForcedTermination {
                    components_failed: 1,
                    components_completed: 0,
                    ..
                }
            ),
            "expected ForcedTermination, got {result:?}"
        );
        if let ShutdownResult::ForcedTermination { failed_names, .. } = result {
            assert_eq!(failed_names, vec!["stubborn-task"]);
        }
    }

    #[tokio::test]
    async fn test_thread_shutdown() {
        init_test_metrics();
        let mut mgr = ComponentManager::new();
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
        let mgr = ComponentManager::new();
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

    /// Verify the "return on exit" pattern: a component sends a resource back via
    /// a oneshot sender as its last action before returning. The receiver is
    /// awaited *after* the handle is joined and reliably gets the value — no race.
    ///
    /// This test exercises the pattern directly using a tokio broadcast channel
    /// (the same primitive `ComponentManager` uses internally) without depending
    /// on global registry state, making it safe to run in parallel with other tests.
    #[tokio::test]
    async fn test_resource_returned_via_oneshot_after_task_joins() {
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
        let (return_tx, return_rx) = tokio::sync::oneshot::channel::<u64>();

        let handle = tokio::spawn(async move {
            let _ = shutdown_rx.recv().await;
            // Last action: send resource back.
            let _ = return_tx.send(42u64);
        });

        let _ = shutdown_tx.send(());
        handle.await.expect("task should not panic");

        // The handle is joined above, so the sender has already fired.
        let resource = return_rx
            .await
            .expect("resource should be returned after task joins");
        assert_eq!(resource, 42);
    }

    /// Verify that the broadcast shutdown pattern correctly wakes multiple tasks.
    ///
    /// All tasks are signaled simultaneously and all complete, confirming that
    /// `broadcast::Sender::send()` reaches every active subscriber.
    #[tokio::test]
    async fn test_broadcast_shutdown_reaches_all_subscribers() {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(16);
        let completed = Arc::new(std::sync::atomic::AtomicU32::new(0));
        const TASK_COUNT: u32 = 5;

        let mut handles = Vec::new();
        for _ in 0..TASK_COUNT {
            let mut rx = shutdown_tx.subscribe();
            let count = Arc::clone(&completed);
            handles.push(tokio::spawn(async move {
                let _ = rx.recv().await;
                count.fetch_add(1, Ordering::SeqCst);
            }));
        }

        let _ = shutdown_tx.send(());
        futures::future::join_all(handles).await;

        assert_eq!(
            completed.load(Ordering::SeqCst),
            TASK_COUNT,
            "all {TASK_COUNT} tasks must receive the shutdown broadcast"
        );
    }
}
