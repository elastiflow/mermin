use std::{sync::Arc, time::Duration};

use tokio::sync::broadcast;
use tracing::{debug, error, info};

use crate::{
    iface::{self, types::ControllerCommand},
    metrics::registry::{FLOWS_LOST_SHUTDOWN, FLOWS_PRESERVED_SHUTDOWN},
    runtime::task_manager::{ShutdownResult, TaskManager},
    span::producer::{FlowSpanComponents, timeout_and_remove_flow},
};

/// Configuration for shutdown behavior
#[derive(Debug, Clone)]
pub struct ShutdownConfig {
    /// Timeout for graceful shutdown before forcing cancellation
    pub timeout: Duration,
    /// Whether to preserve active flows during shutdown
    pub preserve_flows: bool,
    /// Maximum time to wait for flow preservation
    pub flow_preservation_timeout: Duration,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            preserve_flows: true,
            flow_preservation_timeout: Duration::from_secs(10),
        }
    }
}

/// Holds all the necessary handles and channels for a graceful application shutdown.
pub struct ShutdownManager {
    pub shutdown_config: ShutdownConfig,
    pub os_shutdown_tx: broadcast::Sender<()>,
    pub cmd_tx: crossbeam::channel::Sender<ControllerCommand>,
    pub netlink_shutdown_fd: Arc<iface::threads::ShutdownEventFd>,
    pub task_manager: TaskManager,
    pub decorator_join_handle: std::thread::JoinHandle<()>,
    pub os_thread_handles: Vec<(String, std::thread::JoinHandle<()>)>,
    pub controller_handle: std::thread::JoinHandle<()>,
    pub netlink_handle: std::thread::JoinHandle<()>,
    pub flow_span_components: Arc<FlowSpanComponents>,
}

/// Builder for creating ShutdownManager instances with a fluent API
pub struct ShutdownManagerBuilder {
    shutdown_config: Option<ShutdownConfig>,
    os_shutdown_tx: Option<broadcast::Sender<()>>,
    cmd_tx: Option<crossbeam::channel::Sender<ControllerCommand>>,
    netlink_shutdown_fd: Option<Arc<iface::threads::ShutdownEventFd>>,
    task_manager: Option<TaskManager>,
    decorator_join_handle: Option<std::thread::JoinHandle<()>>,
    os_thread_handles: Option<Vec<(String, std::thread::JoinHandle<()>)>>,
    controller_handle: Option<std::thread::JoinHandle<()>>,
    netlink_handle: Option<std::thread::JoinHandle<()>>,
    flow_span_components: Option<Arc<FlowSpanComponents>>,
}

impl ShutdownManagerBuilder {
    /// Creates a new builder instance
    pub fn new() -> Self {
        Self {
            shutdown_config: None,
            os_shutdown_tx: None,
            cmd_tx: None,
            netlink_shutdown_fd: None,
            task_manager: None,
            decorator_join_handle: None,
            os_thread_handles: None,
            controller_handle: None,
            netlink_handle: None,
            flow_span_components: None,
        }
    }

    /// Sets the shutdown configuration
    pub fn with_shutdown_config(mut self, shutdown_config: ShutdownConfig) -> Self {
        self.shutdown_config = Some(shutdown_config);
        self
    }

    /// Sets the OS shutdown channel sender
    pub fn with_os_shutdown_tx(mut self, os_shutdown_tx: broadcast::Sender<()>) -> Self {
        self.os_shutdown_tx = Some(os_shutdown_tx);
        self
    }

    /// Sets the command channel sender
    pub fn with_cmd_tx(mut self, cmd_tx: crossbeam::channel::Sender<ControllerCommand>) -> Self {
        self.cmd_tx = Some(cmd_tx);
        self
    }

    /// Sets the netlink shutdown file descriptor
    pub fn with_netlink_shutdown_fd(
        mut self,
        netlink_shutdown_fd: Arc<iface::threads::ShutdownEventFd>,
    ) -> Self {
        self.netlink_shutdown_fd = Some(netlink_shutdown_fd);
        self
    }

    /// Sets the task manager
    pub fn with_task_manager(mut self, task_manager: TaskManager) -> Self {
        self.task_manager = Some(task_manager);
        self
    }

    /// Sets the decorator join handle
    pub fn with_decorator_join_handle(
        mut self,
        decorator_join_handle: std::thread::JoinHandle<()>,
    ) -> Self {
        self.decorator_join_handle = Some(decorator_join_handle);
        self
    }

    /// Sets the OS thread handles
    pub fn with_os_thread_handles(
        mut self,
        os_thread_handles: Vec<(String, std::thread::JoinHandle<()>)>,
    ) -> Self {
        self.os_thread_handles = Some(os_thread_handles);
        self
    }

    /// Sets the controller handle
    pub fn with_controller_handle(
        mut self,
        controller_handle: std::thread::JoinHandle<()>,
    ) -> Self {
        self.controller_handle = Some(controller_handle);
        self
    }

    /// Sets the netlink handle
    pub fn with_netlink_handle(mut self, netlink_handle: std::thread::JoinHandle<()>) -> Self {
        self.netlink_handle = Some(netlink_handle);
        self
    }

    /// Sets the flow span components
    pub fn with_flow_span_components(
        mut self,
        flow_span_components: Arc<FlowSpanComponents>,
    ) -> Self {
        self.flow_span_components = Some(flow_span_components);
        self
    }

    /// Builds the ShutdownManager instance
    ///
    /// # Panics
    ///
    /// Panics if any required field is missing
    pub fn build(self) -> ShutdownManager {
        ShutdownManager {
            shutdown_config: self.shutdown_config.expect("shutdown_config is required"),
            os_shutdown_tx: self.os_shutdown_tx.expect("os_shutdown_tx is required"),
            cmd_tx: self.cmd_tx.expect("cmd_tx is required"),
            netlink_shutdown_fd: self
                .netlink_shutdown_fd
                .expect("netlink_shutdown_fd is required"),
            task_manager: self.task_manager.expect("task_manager is required"),
            decorator_join_handle: self
                .decorator_join_handle
                .expect("decorator_join_handle is required"),
            os_thread_handles: self
                .os_thread_handles
                .expect("os_thread_handles is required"),
            controller_handle: self
                .controller_handle
                .expect("controller_handle is required"),
            netlink_handle: self.netlink_handle.expect("netlink_handle is required"),
            flow_span_components: self
                .flow_span_components
                .expect("flow_span_components is required"),
        }
    }
}

impl Default for ShutdownManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ShutdownManager {
    /// Creates a new builder for constructing ShutdownManager instances
    pub fn builder() -> ShutdownManagerBuilder {
        ShutdownManagerBuilder::new()
    }

    /// Executes the full graceful shutdown sequence with enhanced flow preservation and timeout handling.
    pub async fn shutdown(self) -> ShutdownResult {
        info!(
            event.name = "application.shutdown.started",
            timeout_seconds = self.shutdown_config.timeout.as_secs(),
            preserve_flows = self.shutdown_config.preserve_flows,
            "starting enhanced shutdown sequence"
        );

        // Phase 1: Preserve active flows if configured
        if self.shutdown_config.preserve_flows {
            info!(
                event.name = "application.shutdown.preserving_flows",
                timeout_seconds = self.shutdown_config.flow_preservation_timeout.as_secs(),
                "attempting to preserve active flows"
            );

            match self
                .preserve_active_flows(self.shutdown_config.flow_preservation_timeout)
                .await
            {
                Ok(preserved_count) => {
                    FLOWS_PRESERVED_SHUTDOWN.inc_by(preserved_count as u64);
                    info!(
                        event.name = "application.shutdown.flows_preserved",
                        count = preserved_count,
                        "successfully preserved active flows"
                    );
                }
                Err(lost_count) => {
                    FLOWS_LOST_SHUTDOWN.inc_by(lost_count as u64);
                    warn!(
                        event.name = "application.shutdown.flows_lost",
                        count = lost_count,
                        "some flows were lost during preservation"
                    );
                }
            }
        }

        // Now destructure after using self methods
        let Self {
            shutdown_config,
            os_shutdown_tx,
            cmd_tx,
            netlink_shutdown_fd,
            task_manager,
            decorator_join_handle,
            os_thread_handles,
            controller_handle,
            netlink_handle,
            flow_span_components: _,
        } = self;

        info!(
            event.name = "application.shutdown.signaling",
            "broadcasting shutdown signal to all tasks and threads"
        );
        task_manager.initiate_shutdown();
        let _ = os_shutdown_tx.send(());
        let _ = cmd_tx.send(ControllerCommand::Shutdown);
        let _ = netlink_shutdown_fd.signal();

        drop(self.flow_span_components);

        debug!(
            event.name = "application.shutdown.waiting_on_tokio_tasks",
            timeout_seconds = shutdown_config.timeout.as_secs(),
            "waiting for main data plane tasks to finish with timeout"
        );
        let task_shutdown_result = task_manager
            .shutdown_with_timeout(shutdown_config.timeout)
            .await;

        debug!(
            event.name = "application.shutdown.waiting_on_decorator",
            "waiting for k8s decorator thread to finish..."
        );
        if let Err(e) = tokio::task::spawn_blocking(move || decorator_join_handle.join()).await {
            error!(event.name = "os_thread.join_error", task.name = "k8s-decorator", error.message = ?e);
        }

        debug!(
            event.name = "application.shutdown.waiting_on_tokio_tasks",
            "waiting for main data plane tasks to finish..."
        );
        task_manager.wait_for_all().await;

        debug!(
            event.name = "application.shutdown.waiting_on_os_threads",
            "waiting for control plane and helper OS threads to finish..."
        );
        if let Err(e) = tokio::task::spawn_blocking(move || {
            for (name, handle) in os_thread_handles {
                if handle.join().is_err() {
                    error!(event.name = "os_thread.panic", task.name = %name, "a dedicated OS thread panicked");
                }
            }
            if controller_handle.join().is_err() {
                error!(event.name = "os_thread.panic", task.name = "controller", "controller thread panicked");
            }
            if netlink_handle.join().is_err() {
                error!(event.name = "os_thread.panic", task.name = "netlink", "netlink thread panicked");
            }
        }).await {
            error!(event.name = "os_thread.join_error", error.message = ?e);
        }

        match &task_shutdown_result {
            ShutdownResult::Graceful {
                duration,
                tasks_completed,
            } => {
                info!(
                    event.name = "application.shutdown.completed_gracefully",
                    duration_ms = duration.as_millis(),
                    tasks_completed = tasks_completed,
                    "all application components shut down gracefully"
                );
            }
            ShutdownResult::ForcedCancellation {
                duration,
                tasks_cancelled,
                tasks_completed,
            } => {
                warn!(
                    event.name = "application.shutdown.completed_with_cancellation",
                    duration_ms = duration.as_millis(),
                    tasks_completed = tasks_completed,
                    tasks_cancelled = tasks_cancelled,
                    "shutdown completed but some tasks were forcefully cancelled"
                );
            }
        }

        task_shutdown_result
    }

    /// Triggers a final flush of all active flows from the producer's flow_store.
    async fn preserve_active_flows(&self, timeout: Duration) -> Result<usize, usize> {
        let flow_store = Arc::clone(&self.flow_span_components.flow_store);
        let flow_stats_map = Arc::clone(&self.flow_span_components.flow_stats_map);
        let flow_span_tx = self.flow_span_components.flow_span_tx.clone();

        let flush_future = async {
            let flow_keys: Vec<String> =
                flow_store.iter().map(|entry| entry.key().clone()).collect();
            let total_flows = flow_keys.len();

            if total_flows == 0 {
                return Ok::<usize, usize>(0);
            }

            info!(
                event.name = "shutdown.flow_preservation.flushing",
                count = total_flows,
                "triggering final export for all active flows."
            );

            let flush_futures = flow_keys
                .into_iter()
                .map(|id| timeout_and_remove_flow(id, &flow_store, &flow_stats_map, &flow_span_tx));

            futures::future::join_all(flush_futures).await;

            Ok(total_flows)
        };

        match tokio::time::timeout(timeout, flush_future).await {
            Ok(Ok(preserved_count)) => Ok(preserved_count),
            Err(_) | Ok(Err(_)) => {
                let lost_count = self.flow_span_components.flow_store.len();
                warn!(
                    event.name = "shutdown.flow_preservation.timeout",
                    "flow preservation timed out. some flows may be lost."
                );
                Err(lost_count)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use aya::maps::HashMap;
    use crossbeam::channel;
    use mermin_common::{FlowKey, FlowStats};
    use tokio::{
        sync::{Mutex, mpsc},
        time::{self, Duration},
    };

    use super::*;
    use crate::{iface, runtime::task_manager::TaskManager};

    #[tokio::test]
    async fn test_full_shutdown_sequence_with_active_tasks() {
        let (flow_span_tx, mut flow_span_rx) = mpsc::channel::<crate::span::flow::FlowSpan>(1);
        let (cmd_tx, cmd_rx) = channel::unbounded();
        let netlink_fd = Arc::new(iface::threads::ShutdownEventFd::new().unwrap());

        let (mut task_manager, _) = TaskManager::new();

        let decorator_handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move { while flow_span_rx.recv().await.is_some() {} });
        });

        let async_task_completed = Arc::new(AtomicBool::new(false));
        let flag_clone = async_task_completed.clone();
        task_manager.spawn_with_shutdown("graceful-task", move |mut shutdown_rx| {
            Box::pin(async move {
                shutdown_rx.recv().await.unwrap();
                flag_clone.store(true, Ordering::SeqCst);
            })
        });

        let os_thread_handles = vec![("mock-os-task".to_string(), std::thread::spawn(|| {}))];
        let controller_handle = std::thread::spawn(|| {});
        let netlink_handle = std::thread::spawn(|| {});
        let flow_stats_map = Arc::new(Mutex::new(unsafe {
            std::mem::zeroed::<HashMap<aya::maps::MapData, FlowKey, FlowStats>>()
        }));

        let mock_components = Arc::new(FlowSpanComponents {
            flow_store: Default::default(),
            flow_stats_map, // Safe because it's never dereferenced.
            flow_span_tx,
        });

        let shutdown_manager = ShutdownManager::builder()
            .with_shutdown_config(ShutdownConfig::default())
            .with_os_shutdown_tx(broadcast::channel(1).0)
            .with_cmd_tx(cmd_tx)
            .with_netlink_shutdown_fd(netlink_fd)
            .with_task_manager(task_manager)
            .with_decorator_join_handle(decorator_handle)
            .with_os_thread_handles(os_thread_handles)
            .with_controller_handle(controller_handle)
            .with_netlink_handle(netlink_handle)
            .with_flow_span_components(mock_components)
            .build();

        let shutdown_result =
            time::timeout(Duration::from_secs(5), shutdown_manager.shutdown()).await;

        assert!(shutdown_result.is_ok(), "Shutdown timed out!");

        assert!(
            async_task_completed.load(Ordering::SeqCst),
            "Graceful async task did not complete!"
        );

        assert!(
            matches!(cmd_rx.try_recv(), Ok(ControllerCommand::Shutdown)),
            "Controller did not receive shutdown command!"
        );

        if let Ok(ShutdownResult::Graceful {
            tasks_completed, ..
        }) = shutdown_result
        {
            assert_eq!(
                tasks_completed, 1,
                "Expected 1 async task to complete gracefully"
            );
        } else {
            panic!(
                "Expected a graceful shutdown result, but got {:?}",
                shutdown_result
            );
        }
    }
}
