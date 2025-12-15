//! Process name resolver for correlating PIDs with executable names.
//!
//! This module provides process name resolution by reading `/proc/[pid]/comm` and
//! caching results to minimize I/O overhead. Handles container namespace isolation
//! by detecting host PID mode and using appropriate `/proc` paths.

use std::{
    fs,
    path::Path,
    sync::Arc,
    time::Duration,
};

use moka::future::Cache;
use tracing::{debug, trace, warn};

/// Default cache capacity (10,000 entries)
const DEFAULT_CACHE_CAPACITY: u64 = 10000;

/// Default TTL for cached process names (60 seconds)
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(60);

/// Resolver for process names from PIDs.
///
/// Uses an LRU cache with TTL to minimize `/proc` file reads while handling
/// process termination gracefully (expired entries indicate process likely terminated).
pub struct ProcessNameResolver {
    cache: Cache<u32, String>,
    proc_base: String,
}

impl ProcessNameResolver {
    /// Create a new ProcessNameResolver with default cache settings.
    pub fn new() -> Self {
        Self::with_capacity_and_ttl(DEFAULT_CACHE_CAPACITY, DEFAULT_CACHE_TTL)
    }

    /// Create a new ProcessNameResolver with custom cache capacity and TTL.
    pub fn with_capacity_and_ttl(capacity: u64, ttl: Duration) -> Self {
        let cache = Cache::builder()
            .max_capacity(capacity)
            .time_to_live(ttl)
            .build();

        // Determine correct /proc path based on deployment mode:
        // - Container with hostPID: true -> use /proc/1/[pid]/comm (host namespace)
        // - Bare metal or hostNetwork: true -> use /proc/[pid]/comm (same namespace)
        let proc_base = if Path::new("/proc/1/ns/net").exists() {
            "/proc/1".to_string()
        } else {
            "/proc".to_string()
        };

        debug!(
            event.name = "process_name.resolver.initialized",
            proc_base = %proc_base,
            cache_capacity = capacity,
            cache_ttl_secs = ttl.as_secs(),
            "process name resolver initialized"
        );

        Self { cache, proc_base }
    }

    /// Resolve a PID to its process executable name.
    ///
    /// Returns the process name if found, or `None` if:
    /// - PID is 0 (invalid/unavailable)
    /// - Process has terminated
    /// - Permission denied (restricted container)
    /// - Other I/O errors
    ///
    /// Results are cached to minimize `/proc` file reads.
    pub async fn resolve(&self, pid: u32) -> Option<String> {
        // PID 0 is invalid/unavailable (e.g., forwarded traffic, kernel-generated packets)
        if pid == 0 {
            trace!(
                event.name = "process_name.resolve_skipped",
                pid = pid,
                reason = "pid_zero",
                "skipping process name resolution for PID 0"
            );
            return None;
        }

        // Check cache first (fast path)
        if let Some(cached) = self.cache.get(&pid).await {
            trace!(
                event.name = "process_name.cache_hit",
                pid = pid,
                process_name = %cached,
                "process name found in cache"
            );
            return Some(cached);
        }

        // Cache miss - read from /proc
        let process_name = self.read_proc_comm(pid);

        if let Some(ref name) = process_name {
            // Cache successful lookups
            self.cache.insert(pid, name.clone()).await;
            trace!(
                event.name = "process_name.resolved",
                pid = pid,
                process_name = %name,
                "resolved process name from /proc"
            );
        } else {
            trace!(
                event.name = "process_name.resolve_failed",
                pid = pid,
                "failed to resolve process name (process may have terminated)"
            );
        }

        process_name
    }

    /// Read process name from `/proc/[pid]/comm`.
    ///
    /// Handles errors gracefully:
    /// - Process terminated: returns None
    /// - Permission denied: returns None, logs at debug level
    /// - Other errors: returns None, logs at warn level
    fn read_proc_comm(&self, pid: u32) -> Option<String> {
        let comm_path = format!("{}/proc/{}/comm", self.proc_base, pid);

        match fs::read_to_string(&comm_path) {
            Ok(content) => {
                // /proc/[pid]/comm includes trailing newline, trim it
                let name = content.trim_end().to_string();
                if name.is_empty() {
                    None
                } else {
                    Some(name)
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Process terminated
                debug!(
                    event.name = "process_name.not_found",
                    pid = pid,
                    path = %comm_path,
                    "process not found (likely terminated)"
                );
                None
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                // Permission denied (restricted container)
                debug!(
                    event.name = "process_name.permission_denied",
                    pid = pid,
                    path = %comm_path,
                    "permission denied reading process name"
                );
                None
            }
            Err(e) => {
                // Other I/O errors
                warn!(
                    event.name = "process_name.read_error",
                    pid = pid,
                    path = %comm_path,
                    error.message = %e,
                    "failed to read process name from /proc"
                );
                None
            }
        }
    }
}

impl Default for ProcessNameResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_resolve_pid_zero() {
        let resolver = ProcessNameResolver::new();
        assert_eq!(resolver.resolve(0).await, None);
    }

    #[tokio::test]
    async fn test_resolve_nonexistent_pid() {
        let resolver = ProcessNameResolver::new();
        // Use a very high PID that's unlikely to exist
        assert_eq!(resolver.resolve(999999).await, None);
    }

    #[tokio::test]
    async fn test_resolve_current_process() {
        let resolver = ProcessNameResolver::new();
        let current_pid = std::process::id();
        let result = resolver.resolve(current_pid).await;
        // Should succeed for current process
        assert!(result.is_some());
        // Process name should not be empty
        assert!(!result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_cache_behavior() {
        let resolver = ProcessNameResolver::with_capacity_and_ttl(100, Duration::from_secs(1));
        let current_pid = std::process::id();

        // First call should read from /proc
        let result1 = resolver.resolve(current_pid).await;
        assert!(result1.is_some());

        // Second call should hit cache
        let result2 = resolver.resolve(current_pid).await;
        assert_eq!(result1, result2);
    }

    #[tokio::test]
    async fn test_read_proc_comm_trim_newline() {
        let temp_dir = TempDir::new().unwrap();
        let proc_dir = temp_dir.path().join("proc").join("12345");
        std::fs::create_dir_all(&proc_dir).unwrap();

        let comm_file = proc_dir.join("comm");
        let mut file = std::fs::File::create(&comm_file).unwrap();
        writeln!(file, "test-process").unwrap();
        drop(file);

        // Create resolver with custom proc base
        let resolver = ProcessNameResolver {
            cache: Cache::builder().max_capacity(100).build(),
            proc_base: temp_dir.path().to_string_lossy().to_string(),
        };

        let result = resolver.read_proc_comm(12345);
        assert_eq!(result, Some("test-process".to_string()));
    }
}

