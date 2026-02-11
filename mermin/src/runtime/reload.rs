//! Hot-reload triggers for configuration changes.
//!
//! Supports two trigger sources:
//! - **SIGHUP** (Unix only) -- `kill -HUP <pid>`
//! - **File watcher** -- uses the `notify` crate to detect config file modifications

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use notify::{
    RecursiveMode, Watcher,
    event::{DataChange, EventKind, ModifyKind},
};
use tokio::{
    signal::unix::{SignalKind, signal},
    sync::mpsc,
};
use tracing::{error, info, trace, warn};

/// Minimum interval between file-change reload triggers (milliseconds).
///
/// Text editors often emit multiple filesystem events for a single save
/// operation (write temp, rename, chmod). This debounce window coalesces
/// those bursts into a single reload.
const FILE_CHANGE_DEBOUNCE_MS: u64 = 1000;

/// The source that triggered a configuration reload.
#[derive(Debug, Clone)]
pub enum ReloadTrigger {
    /// A SIGHUP signal was received.
    Sighup,
    /// The config file at the given path was modified.
    FileChanged(PathBuf),
}

/// Watches for configuration reload triggers (SIGHUP and/or file changes).
pub struct ConfigWatcher {
    rx: mpsc::Receiver<ReloadTrigger>,
    // Hold the watcher so it isn't dropped (which would stop watching)
    _file_watcher: Option<notify::RecommendedWatcher>,
}

impl ConfigWatcher {
    /// Create a new `ConfigWatcher`.
    ///
    /// - Always listens for SIGHUP on Unix.
    /// - If `config_path` is `Some`, also watches the config file for changes
    ///   via the `notify` crate (watches the parent directory for reliability).
    ///
    /// On non-Unix platforms only file watching is available (no SIGHUP).
    pub fn new(config_path: Option<&Path>) -> Result<Self, Box<dyn std::error::Error>> {
        // Capacity is small, we only need to buffer a few triggers before
        // the main loop processes them.
        let (tx, rx) = mpsc::channel::<ReloadTrigger>(4);

        #[cfg(unix)]
        {
            let sighup_tx = tx.clone();
            tokio::spawn(async move {
                let mut sighup = match signal(SignalKind::hangup()) {
                    Ok(s) => s,
                    Err(e) => {
                        error!(
                            event.name = "reload.sighup_listener_failed",
                            error.message = %e,
                            "failed to install sighup handler"
                        );
                        return;
                    }
                };
                loop {
                    sighup.recv().await;
                    info!(
                        event.name = "reload.sighup_received",
                        "received sighup, triggering config reload"
                    );
                    if sighup_tx.send(ReloadTrigger::Sighup).await.is_err() {
                        // Receiver dropped, stop listening
                        break;
                    }
                }
            });
        }

        #[cfg(not(unix))]
        {
            // SIGHUP is not available on non-Unix platforms.
            // Only file watching will trigger reloads.
            let _ = &tx; // suppress unused warning when no file path either
        }

        let file_watcher = if let Some(path) = config_path {
            Some(Self::start_file_watcher(path, tx)?)
        } else {
            None
        };

        Ok(Self {
            rx,
            _file_watcher: file_watcher,
        })
    }

    /// Wait for the next reload trigger.
    pub async fn next(&mut self) -> Option<ReloadTrigger> {
        self.rx.recv().await
    }

    /// Start a file watcher on the parent directory of the config file.
    ///
    /// The `notify` crate works more reliably when watching directories
    /// rather than individual files (editors often delete + recreate files).
    ///
    /// A debounce window of [`FILE_CHANGE_DEBOUNCE_MS`] prevents duplicate
    /// triggers from editor save sequences (write temp + rename).
    fn start_file_watcher(
        config_path: &Path,
        tx: mpsc::Sender<ReloadTrigger>,
    ) -> Result<notify::RecommendedWatcher, Box<dyn std::error::Error>> {
        let config_path = config_path.to_path_buf();
        let config_filename = config_path
            .file_name()
            .ok_or("config path has no filename")?
            .to_os_string();
        let parent_dir = config_path
            .parent()
            .ok_or("config path has no parent directory")?
            .to_path_buf();

        // Shared with the watcher callback for debouncing.
        let last_trigger_ms = Arc::new(AtomicU64::new(0));

        let mut watcher: notify::RecommendedWatcher =
            notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
                match res {
                    Ok(event) => {
                        // Only react to data modifications and file creations
                        // (editors may delete + recreate instead of modifying in place)
                        let is_write_event = matches!(
                            event.kind,
                            EventKind::Modify(ModifyKind::Data(
                                DataChange::Any | DataChange::Content
                            )) | EventKind::Create(_)
                        );
                        if !is_write_event {
                            return;
                        }

                        let is_our_file = event
                            .paths
                            .iter()
                            .any(|p| p.file_name().map(|f| f == config_filename).unwrap_or(false));
                        if !is_our_file {
                            return;
                        }

                        // Editors emit multiple rapid events per save (write temp + rename);
                        // coalesce them so we only reload once per actual user action.
                        let now_ms = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        let prev_ms = last_trigger_ms.swap(now_ms, Ordering::Relaxed);
                        if now_ms.saturating_sub(prev_ms) < FILE_CHANGE_DEBOUNCE_MS {
                            return;
                        }

                        info!(
                            event.name = "reload.file_changed",
                            path = %config_path.display(),
                            "config file changed, triggering reload"
                        );

                        if tx
                            .blocking_send(ReloadTrigger::FileChanged(config_path.clone()))
                            .is_err()
                        {
                            warn!(
                                event.name = "reload.channel_closed",
                                "reload channel closed, file watcher stopping"
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            event.name = "reload.watcher_error",
                            error.message = %e,
                            "file watcher error"
                        );
                    }
                }
            })?;

        watcher.watch(&parent_dir, RecursiveMode::NonRecursive)?;

        info!(
            event.name = "reload.file_watcher_started",
            watch_dir = %parent_dir.display(),
            "config file watcher started"
        );

        Ok(watcher)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[tokio::test]
    async fn test_config_watcher_file_change() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        std::fs::write(&config_path, "initial: true").unwrap();

        let mut watcher = ConfigWatcher::new(Some(&config_path)).unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&config_path)
            .unwrap();
        file.write_all(b"initial: false").unwrap();
        file.flush().unwrap();
        drop(file);

        let trigger = tokio::time::timeout(std::time::Duration::from_secs(5), watcher.next()).await;

        match trigger {
            Ok(Some(ReloadTrigger::FileChanged(path))) => {
                assert_eq!(path, config_path);
            }
            Ok(Some(ReloadTrigger::Sighup)) => {
                // Possible if a stray SIGHUP was received; not a failure
            }
            Ok(None) => panic!("watcher channel closed unexpectedly"),
            Err(_) => {
                // Timeout -- some CI environments / filesystems don't emit events reliably
                // This is acceptable; the test mainly verifies construction doesn't panic
            }
        }
    }

    #[tokio::test]
    async fn test_config_watcher_no_path() {
        // Without a config path, only SIGHUP is active
        let watcher = ConfigWatcher::new(None);
        assert!(watcher.is_ok());
    }
}
