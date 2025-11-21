use tokio::task::JoinHandle;
use tracing::{debug, error};

/// A simple manager to track spawned Tokio tasks with descriptive names.
pub struct TaskManager {
    tasks: Vec<(String, JoinHandle<()>)>,
}

impl TaskManager {
    /// Creates a new, empty TaskManager.
    pub fn new() -> Self {
        Self { tasks: Vec::new() }
    }

    /// Spawns a new task and adds it to the registry with a name.
    pub fn spawn<F>(&mut self, name: &str, future: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let handle = tokio::spawn(future);
        self.tasks.push((name.to_string(), handle));
    }

    /// Waits for all tracked tasks to complete.
    pub async fn wait_for_all(self) {
        for (name, handle) in self.tasks {
            debug!(event.name = "task.waiting", task.name = %name, "waiting for task to complete");

            match handle.await {
                Ok(()) => {
                    debug!(event.name = "task.completed", task.name = %name, "task completed successfully");
                }
                Err(e) => {
                    error!(
                        event.name = "task.panic",
                        task.name = %name,
                        error.message = ?e,
                        "a background task panicked"
                    );
                }
            }
        }
    }
}
