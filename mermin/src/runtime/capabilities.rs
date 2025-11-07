//! Capability checking for required Linux capabilities.
//!
//! Mermin requires several capabilities to function properly:
//! - CAP_BPF: Load and manage eBPF programs
//! - CAP_NET_ADMIN: Attach TC programs to network interfaces
//! - CAP_SYS_ADMIN: Network namespace switching and various kernel operations
//! - CAP_SYS_PTRACE: Access to /proc/1/ns/net for host namespace
//! - CAP_PERFMON: Performance monitoring capabilities (kernel >= 5.8)
//! - CAP_SYS_RESOURCE: Modify resource limits (e.g., memlock rlimit)

use std::fs;

use tracing::{debug, warn};

use crate::error::{MerminError, Result};

/// Linux capability constants from <linux/capability.h>
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum Capability {
    NetAdmin = 12,
    SysAdmin = 21,
    SysPtrace = 19,
    SysResource = 24,
    Perfmon = 38,
    Bpf = 39,
}

impl Capability {
    fn name(&self) -> &'static str {
        match self {
            Capability::NetAdmin => "CAP_NET_ADMIN",
            Capability::SysAdmin => "CAP_SYS_ADMIN",
            Capability::SysPtrace => "CAP_SYS_PTRACE",
            Capability::SysResource => "CAP_SYS_RESOURCE",
            Capability::Perfmon => "CAP_PERFMON",
            Capability::Bpf => "CAP_BPF",
        }
    }

    fn description(&self) -> &'static str {
        match self {
            Capability::NetAdmin => "attach TC programs to network interfaces",
            Capability::SysAdmin => "network namespace switching and kernel operations",
            Capability::SysPtrace => "access host network namespace via /proc/1/ns/net",
            Capability::SysResource => "modify resource limits (e.g., memlock rlimit)",
            Capability::Perfmon => "performance monitoring (eBPF program loading on kernel >= 5.8)",
            Capability::Bpf => "load and manage eBPF programs",
        }
    }
}

/// Check if the process has a specific capability.
/// Reads from /proc/self/status CapEff (effective capabilities).
fn has_capability(cap: Capability) -> Result<bool> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|e| MerminError::internal(format!("failed to read /proc/self/status: {e}")))?;

    for line in status.lines() {
        if let Some(caps_hex) = line.strip_prefix("CapEff:").map(str::trim) {
            // Parse the hex string as u64 (capabilities bitmask)
            let caps = u64::from_str_radix(caps_hex, 16).map_err(|e| {
                MerminError::internal(format!("failed to parse capability mask '{caps_hex}': {e}"))
            })?;

            let cap_bit = 1u64 << (cap as u32);
            return Ok((caps & cap_bit) != 0);
        }
    }

    Err(MerminError::internal(
        "CapEff line not found in /proc/self/status",
    ))
}

/// Check all required capabilities at startup.
/// Returns a detailed error if any required capabilities are missing.
pub fn check_required_capabilities() -> Result<()> {
    let required_caps = [
        Capability::SysAdmin,
        Capability::NetAdmin,
        Capability::Bpf,
        Capability::SysPtrace,
        Capability::Perfmon,
        Capability::SysResource,
    ];

    let mut missing_caps = Vec::new();

    for cap in &required_caps {
        debug!(
            event.name = "capabilities.checking",
            capability = cap.name(),
            "checking for required capability"
        );

        match has_capability(*cap) {
            Ok(true) => {
                debug!(
                    event.name = "capabilities.present",
                    capability = cap.name(),
                    "capability is present"
                );
            }
            Ok(false) => {
                // CAP_PERFMON and CAP_BPF were added in kernel 5.8
                // On older kernels, CAP_SYS_ADMIN provides similar functionality
                if matches!(cap, Capability::Perfmon | Capability::Bpf) {
                    warn!(
                        event.name = "capabilities.missing_fallback",
                        capability = cap.name(),
                        description = cap.description(),
                        "capability not found, but may work on older kernels with CAP_SYS_ADMIN"
                    );
                } else {
                    missing_caps.push(*cap);
                }
            }
            Err(e) => {
                // If we can't read capabilities, assume we're running as root
                // and continue - the actual operations will fail with clear errors if needed
                warn!(
                    event.name = "capabilities.check_failed",
                    capability = cap.name(),
                    error = %e,
                    "failed to check capability, assuming present"
                );
            }
        }
    }

    if !missing_caps.is_empty() {
        let mut error_msg = String::from("Missing required capabilities:\n\n");
        for cap in missing_caps {
            error_msg.push_str(&format!(
                "  ❌ {} - required to {}\n",
                cap.name(),
                cap.description()
            ));
        }
        error_msg.push_str("\n💡 Solutions:\n");
        error_msg.push_str("  1. Run as root: sudo mermin\n");
        error_msg.push_str("  2. In Docker: use --privileged flag\n");
        error_msg.push_str(
            "  3. In Kubernetes: set securityContext with these capabilities in the pod spec\n",
        );
        return Err(MerminError::internal(error_msg));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Only works when running with appropriate capabilities
    fn test_check_capabilities() {
        // This test will fail if not running with required capabilities
        let result = check_required_capabilities();
        // Just verify it doesn't panic - actual result depends on execution environment
        let _ = result;
    }

    #[test]
    fn test_capability_names() {
        assert_eq!(Capability::NetAdmin.name(), "CAP_NET_ADMIN");
        assert_eq!(Capability::SysAdmin.name(), "CAP_SYS_ADMIN");
        assert_eq!(Capability::Bpf.name(), "CAP_BPF");
    }
}
