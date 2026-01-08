//! Process name scanner for initializing PROCESS_NAMES eBPF map.
//!
//! This module scans `/proc/*/comm` at startup to populate the eBPF PROCESS_NAMES
//! map with existing processes. After startup, eBPF tracepoints maintain the map in real-time.

use std::{fs, path::Path, sync::Arc};

use aya::maps::HashMap as EbpfHashMap;
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// Scanner for process names at startup
pub struct ProcessNameScanner {
    process_names_map: Arc<Mutex<EbpfHashMap<aya::maps::MapData, u32, [u8; 16]>>>,
    proc_base: String,
}

impl ProcessNameScanner {
    pub fn new(
        process_names_map: Arc<Mutex<EbpfHashMap<aya::maps::MapData, u32, [u8; 16]>>>,
    ) -> Self {
        // Determine correct /proc path (same logic as ProcessNameResolver)
        let proc_base = Self::determine_proc_base();

        Self {
            process_names_map,
            proc_base,
        }
    }

    /// Determine the correct /proc base path based on namespace configuration.
    ///
    /// Returns:
    /// - `/proc` if we're already in the host PID namespace (hostPID: true) or on bare metal
    /// - `/proc/1` if we're in a container but can access host namespace via /proc/1
    /// - `/proc` as fallback
    fn determine_proc_base() -> String {
        // Check if we're in a container
        let in_container =
            Path::new("/.dockerenv").exists() || Path::new("/proc/1/cgroup").exists();

        if !in_container {
            // Not in container, use /proc directly
            return "/proc".to_string();
        }

        // In container - check if we're already in the host PID namespace
        // If /proc/self/ns/pid == /proc/1/ns/pid, we're in host namespace (hostPID: true)
        let self_pid_ns = fs::read_link("/proc/self/ns/pid").ok();
        let host_pid_ns = fs::read_link("/proc/1/ns/pid").ok();

        if self_pid_ns == host_pid_ns {
            // We're already in host PID namespace (hostPID: true)
            // Use /proc directly, not /proc/1
            "/proc".to_string()
        } else if Path::new("/proc/1/comm").exists() && Path::new("/proc/self/ns/pid").exists() {
            // We're in a container but can access host via /proc/1
            "/proc/1".to_string()
        } else {
            // Fallback to current namespace
            "/proc".to_string()
        }
    }

    /// Scan /proc/*/comm and populate the eBPF map with existing processes.
    ///
    /// This is called once at startup after eBPF programs are attached.
    ///
    /// When running in a container with `hostPID: true`, uses `/proc/*/comm` directly
    /// since we're already in the host PID namespace. Without `hostPID: true`, uses
    /// `/proc/1/*/comm` to access the host's processes.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] if scanning encounters I/O errors.
    pub async fn scan_and_populate(&self) -> Result<usize, std::io::Error> {
        debug!(
            event.name = "process_name.scan_mode",
            proc_path = %self.proc_base,
            "scanning for existing processes"
        );

        let mut count = 0;
        let entries = fs::read_dir(&self.proc_base)?;

        let mut pids_to_insert = Vec::new();

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            // Check if directory name is numeric (PID)
            if let Some(pid_str) = path.file_name().and_then(|n| n.to_str())
                && let Ok(pid) = pid_str.parse::<u32>()
            {
                let comm_path = path.join("comm");
                if let Ok(comm_bytes) = fs::read(&comm_path) {
                    // Parse comm: read up to 15 bytes (TASK_COMM_LEN - 1)
                    // comm file contains name with newline, we want just the name
                    let mut comm_array = [0u8; 16];
                    let name_len = comm_bytes.len().min(15);
                    // Copy name without newline if present
                    let end = if name_len > 0 && comm_bytes[name_len - 1] == b'\n' {
                        name_len - 1
                    } else {
                        name_len
                    };
                    comm_array[..end].copy_from_slice(&comm_bytes[..end]);
                    pids_to_insert.push((pid, comm_array));
                }
            }
        }

        // Insert into eBPF map
        let mut map = self.process_names_map.lock().await;
        for (pid, comm) in pids_to_insert {
            if map.insert(pid, comm, 0).is_err() {
                warn!(
                    event.name = "process_name.insert_failed",
                    pid = pid,
                    "failed to insert process name into eBPF map"
                );
            } else {
                count += 1;
            }
        }

        debug!(
            event.name = "process_name.scan_complete",
            total_processes = count,
            "populated eBPF map with existing process names"
        );

        Ok(count)
    }
}
