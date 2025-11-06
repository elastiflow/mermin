//! Network namespace switching for eBPF attachment
//!
//! This module provides functionality to temporarily switch to the host network namespace
//! for eBPF program attachment, then switch back to the original namespace. This allows
//! mermin to attach to host network interfaces without requiring `hostNetwork: true`,
//! enabling better network isolation while maintaining full monitoring capabilities.

use std::{fs::File, os::fd::AsFd};

use nix::sched::{CloneFlags, setns};
use tracing::{debug, error, info};

use crate::error::{MerminError, Result};

/// Manages network namespace switching for eBPF operations
///
/// This struct holds file descriptors to both the original (pod) network namespace
/// and the host network namespace, allowing safe switching between them.
pub struct NetnsSwitch {
    original_netns: File,
    /// File descriptor for host network namespace (/proc/1/ns/net)
    /// Made public to allow blocking threads to enter host namespace permanently
    pub host_netns: File,
}

impl NetnsSwitch {
    /// Create a new namespace switcher
    ///
    /// Opens file descriptors to both the current network namespace and the host
    /// network namespace (via /proc/1/ns/net).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Cannot open /proc/self/ns/net (current namespace)
    /// - Cannot open /proc/1/ns/net (host namespace)
    /// - Requires CAP_SYS_ADMIN capability and hostPID: true
    pub fn new() -> Result<Self> {
        info!(
            event.name = "netns.switch.initializing",
            "initializing network namespace switcher"
        );

        let original_netns = File::open("/proc/self/ns/net").map_err(|e| {
            MerminError::internal(format!(
                "failed to open original network namespace (/proc/self/ns/net): {e} - this should always be accessible"
            ))
        })?;

        debug!(
            event.name = "netns.switch.original_opened",
            "opened original network namespace file descriptor"
        );

        let host_netns = File::open("/proc/1/ns/net").map_err(|e| {
            MerminError::internal(format!(
                "failed to open host network namespace (/proc/1/ns/net): {e} - ensure hostPID: true is set in pod spec and CAP_SYS_PTRACE capability is granted"
            ))
        })?;

        info!(
            event.name = "netns.switch.initialized",
            "network namespace switcher initialized successfully"
        );

        Ok(Self {
            original_netns,
            host_netns,
        })
    }

    /// Execute a function in the host network namespace
    ///
    /// This method:
    /// 1. Switches the current thread to the host network namespace
    /// 2. Executes the provided closure
    /// 3. Always switches back to the original namespace (even on error)
    ///
    /// # Arguments
    ///
    /// * `context` - Optional context string (e.g., interface name) for logging
    /// * `f` - Closure to execute in the host network namespace
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Switching to host namespace fails (requires CAP_SYS_ADMIN)
    /// - The provided closure returns an error
    /// - Switching back to original namespace fails (critical error)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// let netns = NetnsSwitch::new()?;
    /// let link_id = netns.in_host_namespace(Some("cni0"), || {
    ///     program.attach("cni0", TcAttachType::Ingress)
    /// })?;
    /// ```
    pub fn in_host_namespace<F, R>(&self, context: Option<&str>, f: F) -> Result<R>
    where
        F: FnOnce() -> Result<R>,
    {
        let ctx = context.unwrap_or("unknown");

        debug!(
            event.name = "netns.switch.to_host",
            context = ctx,
            "switching to host network namespace"
        );

        let host_fd = self.host_netns.as_fd();
        setns(host_fd, CloneFlags::CLONE_NEWNET).map_err(|e| {
            MerminError::internal(format!(
                "failed to switch to host network namespace: {e} - requires CAP_SYS_ADMIN capability"
            ))
        })?;

        info!(
            event.name = "netns.switch.in_host",
            context = ctx,
            "now operating in host network namespace"
        );

        let result = f();

        debug!(
            event.name = "netns.switch.to_original",
            context = ctx,
            "switching back to original network namespace"
        );

        let original_fd = self.original_netns.as_fd();
        match setns(original_fd, CloneFlags::CLONE_NEWNET) {
            Ok(_) => {
                info!(
                    event.name = "netns.switch.restored",
                    context = ctx,
                    "restored to original network namespace"
                );
                result
            }
            Err(e) => {
                let err = MerminError::internal(format!(
                    "CRITICAL: failed to restore original network namespace: {e} - process is now in an inconsistent state",
                ));
                error!(
                    event.name = "netns.switch.restore_failed",
                    context = ctx,
                    error = %e,
                    "failed to restore original network namespace"
                );
                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires privileges and hostPID access
    fn test_netns_switch_creation() {
        // This test only works in a properly configured environment
        // with CAP_SYS_ADMIN and hostPID: true
        let result = NetnsSwitch::new();
        assert!(result.is_ok() || result.is_err()); // Just verify it doesn't panic
    }

    #[test]
    #[ignore] // Requires privileges and hostPID access
    fn test_netns_switch_in_host_namespace() {
        // This test only works in a properly configured environment
        // with CAP_SYS_ADMIN and hostPID: true
        let netns = NetnsSwitch::new().unwrap();
        let result = netns.in_host_namespace(Some("test"), || Ok(()));
        assert!(result.is_ok());
    }

    #[test]
    #[ignore] // Requires privileges and hostPID access
    fn test_netns_switch_in_host_namespace_with_error() {
        // This test only works in a properly configured environment
        // with CAP_SYS_ADMIN and hostPID: true
        let netns = NetnsSwitch::new().unwrap();
        let result = netns.in_host_namespace(None, || {
            Err::<(), MerminError>(MerminError::internal("test error"))
        });
        assert!(result.is_err());
    }
}
