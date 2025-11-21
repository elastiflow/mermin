use std::sync::Arc;

use tokio::sync::broadcast;
use tracing::{debug, error, info};

use crate::{
    iface::{self, types::ControllerCommand},
    runtime::task_manager::TaskManager,
};

/// Holds all the necessary handles and channels for a graceful application shutdown.
pub struct ShutdownManager {
    pub shutdown_tx: broadcast::Sender<()>,
    pub cmd_tx: crossbeam::channel::Sender<ControllerCommand>,
    pub netlink_shutdown_fd: Arc<iface::threads::ShutdownEventFd>,
    pub task_manager: TaskManager,
    pub decorator_join_handle: std::thread::JoinHandle<()>,
    pub os_thread_handles: Vec<(String, std::thread::JoinHandle<()>)>,
    pub controller_handle: std::thread::JoinHandle<()>,
    pub netlink_handle: std::thread::JoinHandle<()>,
}

impl ShutdownManager {
    /// Executes the full graceful shutdown sequence in the correct dependency order.
    pub async fn shutdown(self) {
        let Self {
            shutdown_tx,
            cmd_tx,
            netlink_shutdown_fd,
            task_manager,
            decorator_join_handle,
            os_thread_handles,
            controller_handle,
            netlink_handle,
        } = self;

        info!(
            event.name = "application.shutdown.signaling",
            "broadcasting shutdown signal to all tasks and threads"
        );
        let _ = shutdown_tx.send(());
        let _ = cmd_tx.send(ControllerCommand::Shutdown);
        let _ = netlink_shutdown_fd.signal();

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

        info!(
            event.name = "application.shutdown.all_components_finished",
            "all application components shut down successfully."
        );
    }
}
