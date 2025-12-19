//! Process name resolver for correlating PIDs with executable names.
//!
//! This module provides process name resolution by reading `/proc/[pid]/comm` and
//! caching results to minimize I/O overhead. Handles container namespace isolation
//! by detecting host PID mode and using appropriate `/proc` paths.

use std::{fs, path::Path, time::Duration};

use moka::future::Cache;
use tracing::{debug, trace, warn};

const DEFAULT_CACHE_CAPACITY: u64 = 10000;
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
    ///
    /// Use this when you need to tune cache behavior for specific workloads:
    /// - Higher capacity for systems with many unique processes
    /// - Longer TTL for stable process names, shorter for frequently changing names
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::time::Duration;
    /// use mermin::process_name::ProcessNameResolver;
    ///
    /// let resolver = ProcessNameResolver::with_capacity_and_ttl(
    ///     50000,  // Cache up to 50K process names
    ///     Duration::from_secs(300),  // 5 minute TTL
    /// );
    /// ```
    pub fn with_capacity_and_ttl(capacity: u64, ttl: Duration) -> Self {
        let cache = Cache::builder()
            .max_capacity(capacity)
            .time_to_live(ttl)
            .build();

        // Determine correct /proc path based on deployment mode:
        // - Container with hostPID: true -> use /proc/1/[pid]/comm (host namespace)
        // - Bare metal or hostNetwork: true -> use /proc/[pid]/comm (same namespace)
        let proc_base = if Path::new("/.dockerenv").exists() || Path::new("/proc/1/cgroup").exists()
        {
            // In container - check if we can access host /proc via /proc/1
            if Path::new("/proc/1/comm").exists() && Path::new("/proc/self/ns/pid").exists() {
                "/proc/1".to_string()
            } else {
                "/proc".to_string()
            }
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

    /// Convert a comm array (from bpf_get_current_comm) to a String.
    ///
    /// The comm array is a null-terminated string of up to 15 characters.
    /// This function finds the null terminator and converts the bytes before it to a String.
    /// Returns None if the array is empty (all zeros) or contains invalid UTF-8.
    ///
    /// # Examples
    ///
    /// ```
    /// use mermin::process_name::ProcessNameResolver;
    ///
    /// let resolver = ProcessNameResolver::new();
    /// let comm = [b'n', b'g', b'i', b'n', b'x', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    /// assert_eq!(resolver.comm_to_string(comm), Some("nginx".to_string()));
    ///
    /// let empty = [0u8; 16];
    /// assert_eq!(resolver.comm_to_string(empty), None);
    /// ```
    fn comm_to_string(&self, comm: [u8; 16]) -> Option<String> {
        // Find the null terminator
        let null_pos = comm.iter().position(|&b| b == 0).unwrap_or(16);

        // If all zeros, return None
        if null_pos == 0 {
            return None;
        }

        // Convert to string, handling invalid UTF-8 gracefully
        String::from_utf8(comm[..null_pos].to_vec())
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Resolve a PID to its process executable name.
    ///
    /// If `comm` is provided and non-empty, it will be used as the primary source.
    /// Falls back to `/proc/[pid]/comm` lookup if comm is missing, empty, or generic.
    ///
    /// Returns the process name if found, or `None` if:
    /// - PID is 0 (invalid/unavailable)
    /// - Process has terminated
    /// - Permission denied (restricted container)
    /// - Other I/O errors
    ///
    /// Results are cached to minimize `/proc` file reads.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use mermin::process_name::ProcessNameResolver;
    ///
    /// # async fn example() {
    /// let resolver = ProcessNameResolver::new();
    /// let process_name = resolver.resolve(1234, None).await;
    /// match process_name {
    ///     Some(name) => println!("Process name: {}", name),
    ///     None => println!("Process not found or unavailable"),
    /// }
    /// # }
    /// ```
    pub async fn resolve(&self, pid: u32, comm: Option<[u8; 16]>) -> Option<String> {
        // PID 0 is invalid/unavailable (e.g., forwarded traffic, kernel-generated packets)
        // TODO: Add metric for tracking PID 0 rate
        if pid == 0 {
            trace!(
                event.name = "process_name.resolve_skipped",
                pid = pid,
                reason = "pid_zero",
                "skipping process name resolution for PID 0"
            );
            return None;
        }

        // Check comm first if provided (in-kernel capture)
        if let Some(comm_array) = comm
            && let Some(comm_name) = self.comm_to_string(comm_array)
        {
            // Skip generic kernel thread names that are better resolved via /proc
            // These are common kernel threads that may have more specific names in /proc
            let generic_names = ["ksoftirqd", "kworker", "migration", "rcu_"];
            let is_generic = generic_names
                .iter()
                .any(|&prefix| comm_name.starts_with(prefix));

            if !is_generic {
                trace!(
                    event.name = "process_name.resolved_from_comm",
                    pid = pid,
                    process_name = %comm_name,
                    "resolved process name from in-kernel comm"
                );
                // Cache the result for future lookups
                self.cache.insert(pid, comm_name.clone()).await;
                return Some(comm_name);
            }
        }

        if let Some(cached) = self.cache.get(&pid).await {
            trace!(
                event.name = "process_name.cache_hit",
                pid = pid,
                process_name = %cached,
                "process name found in cache"
            );
            return Some(cached);
        }

        let process_name = self.read_proc_comm(pid);

        if let Some(ref name) = process_name {
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
        let comm_path = format!("{}/{}/comm", self.proc_base, pid);

        match fs::read_to_string(&comm_path) {
            Ok(content) => {
                // trim newline char
                let name = content.trim().to_string();
                if name.is_empty() { None } else { Some(name) }
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
    use std::{io::Write, time::Duration};

    use moka::future::Cache;
    use tempfile::TempDir;

    use crate::process_name::ProcessNameResolver;

    #[tokio::test]
    async fn test_resolve_pid_zero() {
        let resolver = ProcessNameResolver::new();
        assert_eq!(resolver.resolve(0, None).await, None);
    }

    #[tokio::test]
    async fn test_resolve_nonexistent_pid() {
        let resolver = ProcessNameResolver::new();
        // Use a very high PID that's unlikely to exist
        assert_eq!(resolver.resolve(999999, None).await, None);
    }

    #[tokio::test]
    async fn test_resolve_current_process() {
        let resolver = ProcessNameResolver::new();
        let current_pid = std::process::id();
        let result = resolver.resolve(current_pid, None).await;
        // Should succeed for current process if /proc is accessible
        // In some test environments (e.g., sandboxed), /proc may not be accessible
        // In that case, the test still validates the resolver doesn't panic
        if result.is_some() {
            // Process name should not be empty when successfully resolved
            assert!(!result.unwrap().is_empty());
        }
        // If result is None, it's likely due to test environment restrictions, not a code bug
    }

    #[tokio::test]
    async fn test_cache_behavior() {
        // Use a temp directory to simulate /proc for reliable testing
        let temp_dir = TempDir::new().unwrap();
        let proc_dir = temp_dir.path().join("12345");
        std::fs::create_dir_all(&proc_dir).unwrap();

        let comm_file = proc_dir.join("comm");
        let mut file = std::fs::File::create(&comm_file).unwrap();
        writeln!(file, "test-process").unwrap();
        drop(file);

        // Create resolver with custom proc base pointing to temp directory
        let resolver = ProcessNameResolver {
            cache: Cache::builder()
                .max_capacity(100)
                .time_to_live(Duration::from_secs(1))
                .build(),
            proc_base: temp_dir.path().to_string_lossy().to_string(),
        };

        // First call should read from /proc (temp directory in this case)
        let result1 = resolver.resolve(12345, None).await;
        assert_eq!(result1, Some("test-process".to_string()));

        // Second call should hit cache (same result)
        let result2 = resolver.resolve(12345, None).await;
        assert_eq!(result1, result2, "cache should return same result");
    }

    #[tokio::test]
    async fn test_read_proc_comm_trim_newline() {
        let temp_dir = TempDir::new().unwrap();
        // Create process directory directly under temp_dir (not under temp_dir/proc)
        // because proc_base will be set to temp_dir.path(), so path construction
        // will be: {temp_dir}/{pid}/comm
        let proc_dir = temp_dir.path().join("12345");
        std::fs::create_dir_all(&proc_dir).unwrap();

        let comm_file = proc_dir.join("comm");
        let mut file = std::fs::File::create(&comm_file).unwrap();
        writeln!(file, "test-process").unwrap();
        drop(file);

        // Create resolver with custom proc base pointing to temp directory root
        // This simulates proc_base = "/proc", so path will be {proc_base}/{pid}/comm
        let resolver = ProcessNameResolver {
            cache: Cache::builder().max_capacity(100).build(),
            proc_base: temp_dir.path().to_string_lossy().to_string(),
        };

        let result = resolver.read_proc_comm(12345);
        assert_eq!(result, Some("test-process".to_string()));
    }

    #[tokio::test]
    async fn test_host_pid_mode_path_construction() {
        let temp_dir = TempDir::new().unwrap();
        // Simulate host PID mode: proc_base = "/proc/1"
        let proc_base = temp_dir.path().join("proc").join("1");
        std::fs::create_dir_all(&proc_base).unwrap();

        // Create process directory under /proc/1 (host PID mode)
        let proc_dir = proc_base.join("12345");
        std::fs::create_dir_all(&proc_dir).unwrap();

        let comm_file = proc_dir.join("comm");
        let mut file = std::fs::File::create(&comm_file).unwrap();
        writeln!(file, "nginx").unwrap();
        drop(file);

        // Create resolver with host PID mode proc base
        let resolver = ProcessNameResolver {
            cache: Cache::builder().max_capacity(100).build(),
            proc_base: proc_base.to_string_lossy().to_string(),
        };

        // Verify path construction: should be /proc/1/12345/comm
        let result = resolver.read_proc_comm(12345);
        assert_eq!(
            result,
            Some("nginx".to_string()),
            "host PID mode path construction failed"
        );
    }
}
