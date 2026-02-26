use std::time::Duration;

/// Errors that can occur when joining a component handle.
///
/// Used internally by [`super::manager::ComponentManager`]; not part of the public API.
#[derive(Debug)]
pub enum JoinError {
    /// The async task was cancelled.
    Cancelled,
    /// The async task panicked with the given message.
    AsyncPanic(String),
    /// An OS thread panicked.
    ThreadPanic,
    /// `tokio::task::spawn_blocking` failed to spawn.
    SpawnBlockingFailed,
    /// The join operation timed out after the given duration.
    Timeout(Duration),
}

impl std::fmt::Display for JoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JoinError::Cancelled => write!(f, "task was cancelled"),
            JoinError::AsyncPanic(msg) => write!(f, "async task panicked: {msg}"),
            JoinError::ThreadPanic => write!(f, "os thread panicked"),
            JoinError::SpawnBlockingFailed => write!(f, "spawn_blocking failed"),
            JoinError::Timeout(d) => write!(f, "join timed out after {d:?}"),
        }
    }
}

impl std::error::Error for JoinError {}

/// Result of a shutdown operation across all registered components.
#[derive(Clone, Debug)]
pub enum ShutdownResult {
    /// All components shut down within the timeout.
    Graceful {
        duration: Duration,
        components_completed: usize,
    },
    /// Some components did not shut down cleanly and were abandoned.
    ///
    /// `failed_names` includes components that timed out and those that
    /// panicked or otherwise failed to join.
    ForcedTermination {
        duration: Duration,
        components_completed: usize,
        components_failed: usize,
        failed_names: Vec<String>,
    },
}
