// Network namespace switching support for interface operations
//
// This module provides utilities for switching between network namespaces,
// which is required for interface discovery and eBPF program attachment in
// containerized environments.

use std::os::fd::{AsRawFd, OwnedFd};
use std::fs::File;
use nix::sched::{setns, CloneFlags};
use tracing::{debug, trace};

use crate::error::MerminError;

/// Network namespace switcher for executing operations in host namespace
pub struct NetnsSwitch {
    /// File descriptor for host network namespace
    pub host_netns: OwnedFd,
    /// File descriptor for original (pod) network namespace
    _pod_netns: OwnedFd,
}

impl NetnsSwitch {
    /// Create new namespace switcher
    ///
    /// Requires:
    /// - hostPID: true in pod spec
    /// - CAP_SYS_PTRACE capability
    /// - CAP_SYS_ADMIN capability
    pub fn new() -> Result<Self, MerminError> {
        // Open host namespace (PID 1 in host namespace)
        let host_netns = File::open("/proc/1/ns/net")
            .map_err(|e| MerminError::internal(format!("failed to open host netns: {e}")))?
            .into();

        // Open current (pod) namespace for reference
        let pod_netns = File::open("/proc/self/ns/net")
            .map_err(|e| MerminError::internal(format!("failed to open pod netns: {e}")))?
            .into();

        debug!(
            event.name = "netns_switch.initialized",
            "network namespace switcher initialized"
        );

        Ok(Self {
            host_netns,
            _pod_netns: pod_netns,
        })
    }

    /// Execute closure in host network namespace
    ///
    /// Switches to host namespace, executes the closure, then switches back to pod namespace.
    /// This is safe because it only affects the current thread.
    pub fn in_host_namespace<F, R>(&self, context: Option<&str>, f: F) -> Result<R, MerminError>
    where
        F: FnOnce() -> Result<R, MerminError>,
    {
        // Save current namespace
        let current_netns = File::open("/proc/self/ns/net")
            .map_err(|e| MerminError::internal(format!("failed to open current netns: {e}")))?;

        // Switch to host namespace
        setns(&self.host_netns, CloneFlags::CLONE_NEWNET).map_err(|e| {
            MerminError::internal(format!("failed to switch to host netns: {e}"))
        })?;

        if let Some(ctx) = context {
            trace!(
                event.name = "netns_switch.entered_host",
                context = %ctx,
                "entered host network namespace"
            );
        }

        // Execute operation
        let result = f();

        // Switch back to original namespace
        if let Err(e) = setns(&current_netns, CloneFlags::CLONE_NEWNET) {
            // This is critical - we can't leave the thread in wrong namespace
            panic!("CRITICAL: failed to restore network namespace: {e}");
        }

        if let Some(ctx) = context {
            trace!(
                event.name = "netns_switch.restored",
                context = %ctx,
                "restored original network namespace"
            );
        }

        result
    }
}
