use std::{mem, os::fd::RawFd, sync::Arc, thread};

use libc::{EFD_CLOEXEC, EFD_NONBLOCK, c_void, eventfd};
use tokio::task::JoinHandle;
use tracing::{error, trace};

/// RAII wrapper for eventfd used to signal shutdown to OS threads.
/// Automatically closes the eventfd when dropped.
pub struct ShutdownEventFd(RawFd);

impl ShutdownEventFd {
    pub fn new() -> Result<Self, std::io::Error> {
        // SAFETY: eventfd() is safe to call, we check for errors
        let fd = unsafe { eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self(fd))
    }

    /// Returns the raw file descriptor for use in syscalls (e.g. `poll()`).
    pub fn as_raw_fd(&self) -> RawFd {
        self.0
    }

    /// Signal shutdown by writing to the eventfd.
    pub fn signal(&self) -> Result<(), std::io::Error> {
        let val: u64 = 1;
        // SAFETY: self.0 is valid, val is properly initialized
        let ret = unsafe {
            libc::write(
                self.0,
                &val as *const u64 as *const c_void,
                mem::size_of::<u64>(),
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for ShutdownEventFd {
    fn drop(&mut self) {
        // SAFETY: self.0 is a valid file descriptor that we own
        unsafe {
            libc::close(self.0);
        }
    }
}

// SAFETY: The underlying eventfd is a kernel object accessible via its file descriptor.
// It is safe to send across threads and share between them (reads/writes are atomic).
unsafe impl Send for ShutdownEventFd {}
unsafe impl Sync for ShutdownEventFd {}

/// A handle to a registered runtime component -- either an async tokio task or an OS thread.
pub enum Handle {
    /// An async task running on the tokio runtime.
    Async { name: String, join: JoinHandle<()> },
    /// A dedicated OS thread, optionally with an eventfd for signaling shutdown.
    Thread {
        name: String,
        join: thread::JoinHandle<()>,
        shutdown: Option<Arc<ShutdownEventFd>>,
    },
}

impl Handle {
    /// Create a handle for an async tokio task.
    pub fn async_task(name: impl Into<String>, join: JoinHandle<()>) -> Self {
        Handle::Async {
            name: name.into(),
            join,
        }
    }

    /// Create a handle for an OS thread without a dedicated shutdown signal.
    pub fn thread(name: impl Into<String>, join: thread::JoinHandle<()>) -> Self {
        Handle::Thread {
            name: name.into(),
            join,
            shutdown: None,
        }
    }

    /// Create a handle for an OS thread with an eventfd-based shutdown signal.
    pub fn thread_with_shutdown(
        name: impl Into<String>,
        join: thread::JoinHandle<()>,
        shutdown: Arc<ShutdownEventFd>,
    ) -> Self {
        Handle::Thread {
            name: name.into(),
            join,
            shutdown: Some(shutdown),
        }
    }

    /// Returns the name of this component.
    pub fn name(&self) -> &str {
        match self {
            Handle::Async { name, .. } => name,
            Handle::Thread { name, .. } => name,
        }
    }

    /// Signal shutdown to this component's dedicated eventfd, if it has one.
    /// No-op for async tasks and threads without an eventfd.
    pub fn signal_shutdown(&self) {
        if let Handle::Thread {
            shutdown: Some(fd),
            name,
            ..
        } = self
            && let Err(e) = fd.signal()
        {
            error!(
                event.name = "component.shutdown_signal_failed",
                component.name = %name,
                error.message = %e,
                "failed to signal shutdown eventfd"
            );
        }
    }
}
