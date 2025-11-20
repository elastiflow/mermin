use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use futures::{StreamExt, stream::FuturesUnordered};
use tokio::{
    sync::broadcast,
    task::{AbortHandle, JoinHandle},
    time::timeout,
};
use tracing::{error, debug, warn};

use crate::metrics::registry::{
    SHUTDOWN_DURATION, SHUTDOWN_TIMEOUTS, TASKS_ACTIVE, TASKS_CANCELLED, TASKS_COMPLETED,
    TASKS_PANICKED, TASKS_SPAWNED,
};

/// Task state for tracking lifecycle
#[derive(Debug, Clone, PartialEq)]
pub enum TaskState {
    Running,
    Completed,
    Cancelled,
    Panicked,
}

/// Metadata for a tracked task
#[derive(Debug)]
pub struct TaskInfo {
    pub name: String,
    pub handle: JoinHandle<()>,
    pub abort_handle: AbortHandle,
    pub state: TaskState,
    pub completion_time: Option<Instant>,
}

/// Enhanced task manager with comprehensive tracking, cancellation, and metrics
pub struct TaskManager {
    tasks: HashMap<u64, TaskInfo>,
    next_task_id: AtomicU64,
    shutdown_tx: Option<broadcast::Sender<()>>,
}

impl TaskManager {
    /// Creates a new TaskManager with shutdown broadcast capability
    pub fn new() -> (Self, broadcast::Receiver<()>) {
        let (shutdown_tx, shutdown_rx) = broadcast::channel(16);
        (
            Self {
                tasks: HashMap::new(),
                next_task_id: AtomicU64::new(1),
                shutdown_tx: Some(shutdown_tx),
            },
            shutdown_rx,
        )
    }

    /// Spawns a new task and adds it to the registry with comprehensive tracking
    pub fn spawn<F>(&mut self, name: &str, future: F) -> u64
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let task_id = self.next_task_id.fetch_add(1, Ordering::SeqCst);
        let handle = tokio::spawn(future);
        let abort_handle = handle.abort_handle();

        let task_info = TaskInfo {
            name: name.to_string(),
            handle,
            abort_handle,
            state: TaskState::Running,
            completion_time: None,
        };

        self.tasks.insert(task_id, task_info);

        // Update metrics
        TASKS_SPAWNED.with_label_values(&[name]).inc();
        TASKS_ACTIVE.with_label_values(&[name]).inc();

        info!(
            event.name = "task.spawned",
            task.id = task_id,
            task.name = %name,
            "task spawned and registered"
        );

        task_id
    }

    /// Spawns a task that listens for shutdown signals
    pub fn spawn_with_shutdown<F>(&mut self, name: &str, future_fn: F) -> u64
    where
        F: FnOnce(
                broadcast::Receiver<()>,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
            + Send
            + 'static,
    {
        if let Some(shutdown_tx) = &self.shutdown_tx {
            let shutdown_rx = shutdown_tx.subscribe();
            let future = future_fn(shutdown_rx);
            self.spawn(name, future)
        } else {
            panic!("TaskManager shutdown channel not available");
        }
    }

    /// Get current task count by state
    #[allow(dead_code)]
    pub fn task_count(&self) -> (usize, usize, usize, usize) {
        let mut running = 0;
        let mut completed = 0;
        let mut cancelled = 0;
        let mut panicked = 0;

        for task in self.tasks.values() {
            match task.state {
                TaskState::Running => running += 1,
                TaskState::Completed => completed += 1,
                TaskState::Cancelled => cancelled += 1,
                TaskState::Panicked => panicked += 1,
            }
        }

        (running, completed, cancelled, panicked)
    }

    /// Get task information by ID
    #[allow(dead_code)]
    pub fn get_task_info(&self, task_id: u64) -> Option<&TaskInfo> {
        self.tasks.get(&task_id)
    }

    /// List all tasks with their current state
    #[allow(dead_code)]
    pub fn list_tasks(&self) -> Vec<(u64, &TaskInfo)> {
        self.tasks.iter().map(|(id, info)| (*id, info)).collect()
    }

    /// Initiate graceful shutdown by broadcasting shutdown signal
    pub fn initiate_shutdown(&self) {
        if let Some(shutdown_tx) = &self.shutdown_tx {
            info!(
                event.name = "task_manager.shutdown_initiated",
                active_tasks = self.tasks.len(),
                "broadcasting shutdown signal to all tasks"
            );
            let _ = shutdown_tx.send(());
        }
    }

    /// Cancel all running tasks forcefully
    pub fn cancel_all_tasks(&mut self) {
        let running_tasks: Vec<_> = self
            .tasks
            .iter()
            .filter(|(_, task)| task.state == TaskState::Running)
            .map(|(id, task)| (*id, task.name.clone()))
            .collect();

        for (task_id, task_name) in running_tasks {
            if let Some(task) = self.tasks.get_mut(&task_id) {
                task.abort_handle.abort();
                task.state = TaskState::Cancelled;
                task.completion_time = Some(Instant::now());

                // Update metrics
                TASKS_CANCELLED.with_label_values(&[&task_name]).inc();
                TASKS_ACTIVE.with_label_values(&[&task_name]).dec();

                warn!(
                    event.name = "task.cancelled",
                    task.id = task_id,
                    task.name = %task_name,
                    "task cancelled forcefully"
                );
            }
        }
    }

    /// Wait for all tasks to complete with timeout and graceful shutdown
    pub async fn shutdown_with_timeout(mut self, timeout_duration: Duration) -> ShutdownResult {
        let shutdown_start = Instant::now();

        info!(
            event.name = "task_manager.shutdown_started",
            timeout_seconds = timeout_duration.as_secs(),
            active_tasks = self.tasks.len(),
            "starting graceful shutdown sequence"
        );

        self.initiate_shutdown();

        let graceful_result = timeout(timeout_duration, self.wait_for_running_tasks()).await;

        match graceful_result {
            Ok(()) => {
                let shutdown_duration = shutdown_start.elapsed();
                SHUTDOWN_DURATION.observe(shutdown_duration.as_secs_f64());

                info!(
                    event.name = "task_manager.shutdown_completed",
                    duration_ms = shutdown_duration.as_millis(),
                    "all tasks completed gracefully"
                );

                ShutdownResult::Graceful {
                    duration: shutdown_duration,
                    tasks_completed: self.count_completed_tasks(),
                }
            }
            Err(_) => {
                warn!(
                    event.name = "task_manager.shutdown_timeout",
                    timeout_seconds = timeout_duration.as_secs(),
                    "graceful shutdown timed out, cancelling remaining tasks"
                );

                SHUTDOWN_TIMEOUTS.inc();
                self.cancel_all_tasks();

                let _ = timeout(Duration::from_secs(5), self.wait_for_running_tasks()).await;

                let shutdown_duration = shutdown_start.elapsed();
                SHUTDOWN_DURATION.observe(shutdown_duration.as_secs_f64());

                ShutdownResult::ForcedCancellation {
                    duration: shutdown_duration,
                    tasks_cancelled: self.count_cancelled_tasks(),
                    tasks_completed: self.count_completed_tasks(),
                }
            }
        }
    }

    /// Wait for all running tasks to complete (used internally)
    async fn wait_for_running_tasks(&mut self) {
        let mut pending = FuturesUnordered::new();

        for (task_id, task_info) in self
            .tasks
            .iter_mut()
            .filter(|(_, task)| task.state == TaskState::Running)
        {
            let task_id = *task_id;
            let task_name = task_info.name.clone();
            let handle = std::mem::replace(&mut task_info.handle, tokio::spawn(async {}));

            pending.push(async move {
                let result = handle.await;
                (task_id, task_name, result)
            });
        }

        while let Some((task_id, task_name, result)) = pending.next().await {
            match result {
                Ok(()) => {
                    if let Some(task_info) = self.tasks.get_mut(&task_id) {
                        task_info.state = TaskState::Completed;
                        task_info.completion_time = Some(Instant::now());
                        TASKS_COMPLETED.with_label_values(&[&task_name]).inc();
                        TASKS_ACTIVE.with_label_values(&[&task_name]).dec();
                        debug!(event.name = "task.completed", task.id = task_id, task.name = %task_name, "task completed successfully");
                    }
                }
                Err(e) if e.is_cancelled() => {
                    if let Some(task_info) = self.tasks.get_mut(&task_id) {
                        task_info.state = TaskState::Cancelled;
                        task_info.completion_time = Some(Instant::now());
                        TASKS_CANCELLED.with_label_values(&[&task_name]).inc();
                        TASKS_ACTIVE.with_label_values(&[&task_name]).dec();
                        debug!(event.name = "task.cancelled", task.id = task_id, task.name = %task_name, "task was cancelled");
                    }
                }
                Err(e) => {
                    if let Some(task_info) = self.tasks.get_mut(&task_id) {
                        task_info.state = TaskState::Panicked;
                        task_info.completion_time = Some(Instant::now());
                        TASKS_PANICKED.with_label_values(&[&task_name]).inc();
                        TASKS_ACTIVE.with_label_values(&[&task_name]).dec();
                        error!(event.name = "task.panic", task.id = task_id, task.name = %task_name, error.message = ?e, "task panicked");
                    }
                }
            }
        }
    }

    fn count_completed_tasks(&self) -> usize {
        self.tasks
            .values()
            .filter(|t| t.state == TaskState::Completed)
            .count()
    }

    fn count_cancelled_tasks(&self) -> usize {
        self.tasks
            .values()
            .filter(|t| t.state == TaskState::Cancelled)
            .count()
    }
}

/// Result of shutdown operation
#[derive(Clone, Debug)]
pub enum ShutdownResult {
    Graceful {
        duration: Duration,
        tasks_completed: usize,
    },
    ForcedCancellation {
        duration: Duration,
        tasks_cancelled: usize,
        tasks_completed: usize,
    },
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize},
    };

    use tokio::time::{Duration, sleep};

    use super::*;

    #[tokio::test]
    async fn test_task_spawning_and_tracking() {
        let (mut task_manager, _shutdown_rx) = TaskManager::new();

        let task_id = task_manager.spawn("test-task", async {
            sleep(Duration::from_millis(10)).await;
        });

        assert!(task_id > 0);
        assert_eq!(task_manager.task_count().0, 1); // 1 running task

        let task_info = task_manager.get_task_info(task_id).unwrap();
        assert_eq!(task_info.name, "test-task");
        assert_eq!(task_info.state, TaskState::Running);
    }

    #[tokio::test]
    async fn test_graceful_shutdown() {
        let (mut task_manager, _shutdown_rx) = TaskManager::new();

        // Spawn a task that responds to shutdown signals
        let completed = Arc::new(AtomicBool::new(false));
        let completed_clone = completed.clone();

        task_manager.spawn_with_shutdown("graceful-task", move |mut shutdown_rx| {
            let completed = completed_clone.clone();
            Box::pin(async move {
                tokio::select! {
                    _ = sleep(Duration::from_secs(10)) => {
                        // This should not happen in our test
                    }
                    _ = shutdown_rx.recv() => {
                        completed.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                }
            })
        });

        // Shutdown with a reasonable timeout
        let result = task_manager
            .shutdown_with_timeout(Duration::from_secs(1))
            .await;

        match result {
            ShutdownResult::Graceful {
                tasks_completed, ..
            } => {
                assert_eq!(tasks_completed, 1);
                assert!(completed.load(std::sync::atomic::Ordering::SeqCst));
            }
            _ => panic!("Expected graceful shutdown"),
        }
    }

    #[tokio::test]
    async fn test_forced_cancellation() {
        let (mut task_manager, _shutdown_rx) = TaskManager::new();

        // Spawn a task that ignores shutdown signals
        task_manager.spawn("stubborn-task", async {
            sleep(Duration::from_secs(10)).await;
        });

        // Shutdown with a very short timeout to force cancellation
        let result = task_manager
            .shutdown_with_timeout(Duration::from_millis(100))
            .await;

        match result {
            ShutdownResult::ForcedCancellation {
                tasks_cancelled, ..
            } => {
                assert_eq!(tasks_cancelled, 1);
            }
            _ => panic!("Expected forced cancellation"),
        }
    }

    #[tokio::test]
    async fn test_multiple_tasks_shutdown() {
        let (mut task_manager, _shutdown_rx) = TaskManager::new();

        let completed_count = Arc::new(AtomicUsize::new(0));

        // Spawn multiple tasks that respond to shutdown
        for i in 0..5 {
            let completed_count = completed_count.clone();
            task_manager.spawn_with_shutdown(&format!("task-{}", i), move |mut shutdown_rx| {
                Box::pin(async move {
                    tokio::select! {
                        _ = sleep(Duration::from_secs(10)) => {}
                        _ = shutdown_rx.recv() => {
                            completed_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                })
            });
        }

        assert_eq!(task_manager.task_count().0, 5); // 5 running tasks

        let result = task_manager
            .shutdown_with_timeout(Duration::from_secs(1))
            .await;

        match result {
            ShutdownResult::Graceful {
                tasks_completed, ..
            } => {
                assert_eq!(tasks_completed, 5);
                assert_eq!(completed_count.load(std::sync::atomic::Ordering::SeqCst), 5);
            }
            _ => panic!("Expected graceful shutdown"),
        }
    }

    #[tokio::test]
    async fn test_mixed_shutdown_scenarios() {
        let (mut task_manager, _shutdown_rx) = TaskManager::new();

        let graceful_completed = Arc::new(AtomicUsize::new(0));

        // Spawn some tasks that respond to shutdown
        for i in 0..3 {
            let graceful_completed = graceful_completed.clone();
            task_manager.spawn_with_shutdown(&format!("graceful-task-{}", i), move |mut shutdown_rx| {
                Box::pin(async move {
                    tokio::select! {
                        _ = sleep(Duration::from_secs(10)) => {}
                        _ = shutdown_rx.recv() => {
                            graceful_completed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                })
            });
        }

        // Spawn some tasks that ignore shutdown signals
        for i in 0..2 {
            task_manager.spawn(&format!("stubborn-task-{}", i), async {
                sleep(Duration::from_secs(10)).await;
            });
        }

        assert_eq!(task_manager.task_count().0, 5); // 5 running tasks

        let result = task_manager
            .shutdown_with_timeout(Duration::from_millis(200))
            .await;

        match result {
            ShutdownResult::ForcedCancellation {
                tasks_cancelled,
                tasks_completed,
                ..
            } => {
                assert!(tasks_completed > 0);
                assert!(tasks_cancelled > 0);
                assert_eq!(tasks_completed + tasks_cancelled, 5);
            }
            _ => panic!("Expected forced cancellation due to stubborn tasks"),
        }
    }
}
