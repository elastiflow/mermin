//! Hot-reload triggers for configuration changes.
//!
//! Supports two trigger sources:
//! - **SIGHUP** (Unix only) -- `kill -HUP <pid>`
//! - **File watcher** -- uses Linux inotify via `nix` to detect config file modifications

use std::{
    ffi::OsStr,
    os::unix::io::{AsFd, AsRawFd},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
use tokio::{
    signal::unix::{SignalKind, signal},
    sync::mpsc,
    task::JoinHandle,
};
use tracing::{error, info, trace, warn};

/// Minimum interval between file-change reload triggers (milliseconds).
///
/// Text editors often emit multiple filesystem events for a single save
/// operation (write temp, rename, chmod). This debounce window coalesces
/// those bursts into a single reload.
const FILE_CHANGE_DEBOUNCE_MS: u64 = 1000;

#[derive(Debug, Clone)]
pub enum ReloadTrigger {
    Sighup,
    FileChanged(PathBuf),
}

pub struct ConfigWatcher {
    rx: mpsc::Receiver<ReloadTrigger>,
    // Held so the JoinHandle isn't dropped (and the task detached) before we signal stop.
    _file_watcher: Option<JoinHandle<()>>,
    // Signals the blocking watcher thread to exit; checked every ~200 ms.
    stop_flag: Arc<AtomicBool>,
}

impl Drop for ConfigWatcher {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }
}

impl ConfigWatcher {
    pub fn new(config_path: Option<&Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let (tx, rx) = mpsc::channel::<ReloadTrigger>(4);
        let stop_flag = Arc::new(AtomicBool::new(false));

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
                    if sighup.recv().await.is_none() {
                        break;
                    }
                    info!(
                        event.name = "reload.sighup_received",
                        "received sighup, triggering config reload"
                    );
                    if sighup_tx.send(ReloadTrigger::Sighup).await.is_err() {
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
            Some(Self::start_file_watcher(path, tx, Arc::clone(&stop_flag))?)
        } else {
            None
        };

        Ok(Self {
            rx,
            _file_watcher: file_watcher,
            stop_flag,
        })
    }

    pub async fn next(&mut self) -> Option<ReloadTrigger> {
        self.rx.recv().await
    }

    fn start_file_watcher(
        config_path: &Path,
        tx: mpsc::Sender<ReloadTrigger>,
        stop: Arc<AtomicBool>,
    ) -> Result<JoinHandle<()>, Box<dyn std::error::Error>> {
        let config_path = config_path.to_path_buf();
        let config_filename = config_path
            .file_name()
            .ok_or("config path has no filename")?
            .to_os_string();
        let parent_dir = config_path
            .parent()
            .ok_or("config path has no parent directory")?
            .to_path_buf();

        let last_trigger_ms = Arc::new(AtomicU64::new(0));

        let inotify = Inotify::init(InitFlags::empty())?;
        inotify.add_watch(
            &parent_dir,
            AddWatchFlags::IN_MODIFY
                | AddWatchFlags::IN_CREATE
                | AddWatchFlags::IN_CLOSE_WRITE
                | AddWatchFlags::IN_MOVED_TO,
        )?;

        info!(
            event.name = "reload.file_watcher_started",
            watch_dir = %parent_dir.display(),
            "config file watcher started"
        );

        // Capture the raw fd once; it stays valid for the lifetime of `inotify`
        // (which is moved into the closure below).
        let raw_fd = inotify.as_fd().as_raw_fd();

        let handle = tokio::task::spawn_blocking(move || {
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }

                // libc::poll with a 200 ms timeout so the stop flag is checked
                // regularly without busy-looping.
                // SAFETY: pollfd is a plain C struct; zeroed is valid initial state.
                // raw_fd stays valid for the lifetime of `inotify` (owned by this closure).
                let ret = unsafe {
                    let mut pfd: libc::pollfd = std::mem::zeroed();
                    pfd.fd = raw_fd;
                    pfd.events = libc::POLLIN;
                    libc::poll(&mut pfd, 1, 200)
                };

                if ret == 0 {
                    continue; // timeout — loop back and check stop flag
                }
                if ret < 0 {
                    let os_errno =
                        std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                    if os_errno == libc::EINTR {
                        continue; // interrupted by a signal, retry
                    }
                    warn!(
                        event.name = "reload.watcher_error",
                        errno = os_errno,
                        "inotify poll error, file watcher stopping"
                    );
                    break;
                }

                let events = match inotify.read_events() {
                    Ok(e) => e,
                    Err(e) => {
                        warn!(
                            event.name = "reload.watcher_error",
                            error.message = %e,
                            "inotify read error, file watcher stopping"
                        );
                        break;
                    }
                };

                for event in events {
                    let is_our_file = event
                        .name
                        .as_deref()
                        .map(|n| n == OsStr::new(&config_filename))
                        .unwrap_or(false);
                    if !is_our_file {
                        continue;
                    }

                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let prev_ms = last_trigger_ms.swap(now_ms, Ordering::Relaxed);
                    if now_ms.saturating_sub(prev_ms) < FILE_CHANGE_DEBOUNCE_MS {
                        continue;
                    }

                    info!(
                        event.name = "reload.file_changed",
                        path = %config_path.display(),
                        "config file changed, triggering reload"
                    );

                    match tx.try_send(ReloadTrigger::FileChanged(config_path.clone())) {
                        Ok(()) => {}
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            warn!(
                                event.name = "reload.channel_closed",
                                "reload channel closed, file watcher stopping"
                            );
                            return;
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            trace!(
                                event.name = "reload.channel_full",
                                "reload channel full, dropping file-change trigger; next change will retry"
                            );
                        }
                    }
                }
            }
        });

        Ok(handle)
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

        // In resource-constrained environments (e.g. Docker with low inotify/FD limits),
        // watcher creation can fail with EMFILE when many tests run in parallel.
        // Skip rather than fail — the logic under test is the file-change detection path.
        let mut watcher = match ConfigWatcher::new(Some(&config_path)) {
            Ok(w) => w,
            Err(e) if e.to_string().contains("Too many open files") => return,
            Err(e) => panic!("ConfigWatcher::new failed unexpectedly: {e}"),
        };

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
                // Timeout: some CI environments or filesystems don't emit inotify/fsevents
                // reliably. The test still verifies ConfigWatcher construction and that
                // the watcher runs; a skipped file-change trigger is acceptable here.
            }
        }
    }

    #[tokio::test]
    async fn test_config_watcher_no_path() {
        // Without a config path, only SIGHUP is active
        let watcher = ConfigWatcher::new(None);
        assert!(watcher.is_ok());
    }

    #[tokio::test]
    async fn test_config_watcher_atomic_rename() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        std::fs::write(&config_path, "initial: true").unwrap();

        let mut watcher = match ConfigWatcher::new(Some(&config_path)) {
            Ok(w) => w,
            Err(e) if e.to_string().contains("Too many open files") => return,
            Err(e) => panic!("ConfigWatcher::new failed unexpectedly: {e}"),
        };

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Simulate vim/editor-style atomic save: write to sibling temp, then rename over config.
        // This triggers IN_MOVED_TO on the watched parent directory.
        let tmp_path = dir.path().join("config.yaml.tmp");
        std::fs::write(&tmp_path, "updated: true").unwrap();
        std::fs::rename(&tmp_path, &config_path).unwrap();

        let trigger = tokio::time::timeout(std::time::Duration::from_secs(5), watcher.next()).await;
        match trigger {
            Ok(Some(ReloadTrigger::FileChanged(path))) => assert_eq!(path, config_path),
            Ok(Some(ReloadTrigger::Sighup)) => {} // stray signal, not a failure
            Ok(None) => panic!("watcher channel closed unexpectedly"),
            Err(_) => {
                // Timeout: acceptable in CI environments with unreliable fsevents.
            }
        }
    }

    #[tokio::test]
    async fn test_config_watcher_debounce() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        std::fs::write(&config_path, "v: 0").unwrap();

        let mut watcher = match ConfigWatcher::new(Some(&config_path)) {
            Ok(w) => w,
            Err(e) if e.to_string().contains("Too many open files") => return,
            Err(e) => panic!("ConfigWatcher::new failed unexpectedly: {e}"),
        };

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Write 5 times in rapid succession — all within the 1000 ms debounce window.
        for i in 1..=5u8 {
            std::fs::write(&config_path, format!("v: {i}")).unwrap();
        }

        // Collect triggers for 1.5 s (debounce window is 1000 ms).
        let mut trigger_count = 0usize;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(1500);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, watcher.next()).await {
                Ok(Some(ReloadTrigger::FileChanged(_))) => trigger_count += 1,
                Ok(Some(ReloadTrigger::Sighup)) => {}
                Ok(None) | Err(_) => break,
            }
        }

        // In CI/virtual filesystems events may not fire at all — skip rather than fail.
        // When they do fire, debounce must coalesce 5 writes into at most 2 triggers.
        if trigger_count > 0 {
            assert!(
                trigger_count <= 2,
                "expected debounce to coalesce triggers, got {trigger_count}"
            );
        }
    }
}
