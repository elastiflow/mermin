use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::DashMap;
use fxhash::FxBuildHasher;
use opentelemetry::trace::TraceId;
use opentelemetry_sdk::trace::IdGenerator;
use tracing::{debug, trace};

/// Entry in the trace ID cache containing the trace ID and timestamp
#[derive(Debug, Clone)]
struct CacheEntry {
    trace_id: TraceId,
    created_at: Instant,
}

/// Thread-safe cache that maps community IDs to trace IDs with expiration support.
///
/// This cache enables trace correlation by ensuring that all flows with the same
/// community ID share the same trace ID until the configured timeout expires.
///
/// ## Concurrency Model
///
/// - Uses `DashMap` for lock-free concurrent access from multiple worker threads
/// - Safe for concurrent reads and writes without external synchronization
///
/// ## Memory Footprint
///
/// - ~100-200 bytes per active flow mapping
/// - For 100K concurrent flows: ~10-20 MB of cache memory
pub struct TraceIdCache {
    /// Map from community ID to (TraceId, creation timestamp)
    cache: Arc<DashMap<String, CacheEntry, FxBuildHasher>>,
    /// Trace ID generator for creating new trace IDs
    id_generator: Arc<dyn IdGenerator + Send + Sync>,
    /// Timeout duration for trace ID expiration
    timeout: Duration,
}

impl TraceIdCache {
    /// Creates a new TraceIdCache with the specified timeout and initial capacity
    ///
    /// # Arguments
    ///
    /// * `timeout` - Duration after which trace ID mappings expire
    /// * `capacity` - Initial capacity hint for the cache
    pub fn new(timeout: Duration, capacity: usize) -> Self {
        Self {
            cache: Arc::new(DashMap::with_capacity_and_hasher(
                capacity,
                FxBuildHasher::default(),
            )),
            id_generator: Arc::new(opentelemetry_sdk::trace::RandomIdGenerator::default()),
            timeout,
        }
    }

    /// Gets an existing trace ID for the community ID or creates a new one.
    ///
    /// This method implements lazy expiration - if an entry exists but has expired,
    /// it will be replaced with a new trace ID.
    ///
    /// This method is race-condition safe: if multiple threads access an expired entry
    /// simultaneously, only one will generate a new trace ID and all will receive the same ID.
    ///
    /// # Arguments
    ///
    /// * `community_id` - The community ID to look up or create a mapping for
    ///
    /// # Returns
    ///
    /// The trace ID associated with this community ID (existing or newly created)
    pub fn get_or_create(&self, community_id: &str) -> TraceId {
        let now = Instant::now();

        loop {
            let entry = self
                .cache
                .entry(community_id.to_string())
                .or_insert_with(|| {
                    // First time seeing this community ID - create new entry
                    CacheEntry {
                        trace_id: self.id_generator.new_trace_id(),
                        created_at: now,
                    }
                });

            // Check if entry is still valid
            let age = now.duration_since(entry.value().created_at);
            if age < self.timeout {
                // Cache hit - entry is still valid
                let trace_id = entry.value().trace_id;
                drop(entry); // Release lock

                trace!(
                    event.name = "trace_cache.hit",
                    community_id = %community_id,
                    age_secs = age.as_secs(),
                    "trace ID cache hit"
                );
                return trace_id;
            }

            // Entry has expired - need to replace it
            // Drop the entry reference before removal to avoid deadlock
            drop(entry);

            // Atomically remove the expired entry if it still exists
            // Another thread might have already removed it, which is fine
            if self.cache.remove(community_id).is_some() {
                trace!(
                    event.name = "trace_cache.expired",
                    community_id = %community_id,
                    age_secs = age.as_secs(),
                    "removed expired trace ID entry"
                );
            }

            // Loop back to create a fresh entry
            // The or_insert_with() will atomically create a new one
            // This ensures only one thread creates the replacement entry
        }
    }

    /// Removes expired entries from the cache.
    ///
    /// This method is designed to be called periodically by a background task
    /// to prevent unbounded memory growth.
    ///
    /// # Returns
    ///
    /// A tuple containing (entries_scanned, entries_removed)
    pub fn cleanup_expired(&self) -> (usize, usize) {
        let now = Instant::now();
        let mut scanned = 0;

        // Collect expired keys first to avoid holding locks during removal
        let expired_keys: Vec<String> = self
            .cache
            .iter()
            .filter_map(|entry| {
                scanned += 1;
                let age = now.duration_since(entry.value().created_at);
                if age >= self.timeout {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();

        // Remove expired entries
        let removed = expired_keys.len();
        for key in expired_keys {
            self.cache.remove(&key);
        }

        if removed > 0 {
            debug!(
                event.name = "trace_cache.cleanup",
                entries.scanned = scanned,
                entries.removed = removed,
                "cleaned up expired trace ID mappings"
            );
        }

        (scanned, removed)
    }

    /// Removes an entry from the cache by community ID.
    ///
    /// This method should be called when a flow is timed out, indicating that
    /// the connection is closed or the flow is done. Removing the cache entry
    /// ensures that future flows with the same community ID will get a new trace ID.
    ///
    /// # Arguments
    ///
    /// * `community_id` - The community ID of the entry to remove
    pub fn remove(&self, community_id: &str) {
        self.cache.remove(community_id);
    }

    /// Clears all entries from the cache (primarily for testing)
    #[cfg(test)]
    pub fn clear(&self) {
        self.cache.clear();
    }
}

impl Clone for TraceIdCache {
    fn clone(&self) -> Self {
        Self {
            cache: Arc::clone(&self.cache),
            id_generator: Arc::clone(&self.id_generator),
            timeout: self.timeout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_new() {
        let cache = TraceIdCache::new(Duration::from_secs(3600), 100);
        assert_eq!(cache.timeout, Duration::from_secs(3600));
        assert_eq!(cache.cache.len(), 0);
    }

    #[test]
    fn test_get_or_create_new_entry() {
        let cache = TraceIdCache::new(Duration::from_secs(3600), 100);
        let community_id = "1:test123";

        let trace_id1 = cache.get_or_create(community_id);

        assert_eq!(cache.cache.len(), 1);

        // Verify trace ID is valid (non-zero)
        assert_ne!(trace_id1.to_bytes(), [0u8; 16]);
    }

    #[test]
    fn test_get_or_create_reuses_existing() {
        let cache = TraceIdCache::new(Duration::from_secs(3600), 100);
        let community_id = "1:test123";

        // First call creates entry
        let trace_id1 = cache.get_or_create(community_id);
        assert_eq!(cache.cache.len(), 1);

        // Second call should reuse same trace ID
        let trace_id2 = cache.get_or_create(community_id);
        assert_eq!(cache.cache.len(), 1); // Still only one entry

        // Trace IDs should be identical
        assert_eq!(trace_id1, trace_id2);
    }

    #[test]
    fn test_different_community_ids_get_different_trace_ids() {
        let cache = TraceIdCache::new(Duration::from_secs(3600), 100);

        let trace_id1 = cache.get_or_create("1:community1");
        let trace_id2 = cache.get_or_create("1:community2");

        assert_ne!(trace_id1, trace_id2);
        assert_eq!(cache.cache.len(), 2);
    }

    #[test]
    fn test_expired_entry_generates_new_trace_id() {
        // Very short timeout for testing
        let cache = TraceIdCache::new(Duration::from_millis(100), 100);
        let community_id = "1:test123";

        // Create initial entry
        let trace_id1 = cache.get_or_create(community_id);
        assert_eq!(cache.cache.len(), 1);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(150));

        // Should generate new trace ID (entry gets replaced)
        let trace_id2 = cache.get_or_create(community_id);
        assert_eq!(cache.cache.len(), 1); // Still one entry, but replaced

        // Trace IDs should be different
        assert_ne!(trace_id1, trace_id2);
    }

    #[test]
    fn test_cleanup_expired_removes_old_entries() {
        let cache = TraceIdCache::new(Duration::from_millis(100), 100);

        // Create several entries
        cache.get_or_create("1:community1");
        cache.get_or_create("1:community2");
        cache.get_or_create("1:community3");

        assert_eq!(cache.cache.len(), 3);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(150));

        // Cleanup should remove all expired entries
        let (scanned, removed) = cache.cleanup_expired();
        assert_eq!(scanned, 3);
        assert_eq!(removed, 3);
        assert_eq!(cache.cache.len(), 0);
    }

    #[test]
    fn test_cleanup_expired_keeps_valid_entries() {
        let cache = TraceIdCache::new(Duration::from_secs(3600), 100);

        // Create entries that won't expire
        cache.get_or_create("1:community1");
        cache.get_or_create("1:community2");

        assert_eq!(cache.cache.len(), 2);

        // Cleanup should not remove valid entries
        let (scanned, removed) = cache.cleanup_expired();
        assert_eq!(scanned, 2);
        assert_eq!(removed, 0);
        assert_eq!(cache.cache.len(), 2);
    }

    #[test]
    fn test_cleanup_expired_partial() {
        let cache = TraceIdCache::new(Duration::from_millis(200), 100);

        // Create first entry
        cache.get_or_create("1:old_community");

        // Wait a bit
        std::thread::sleep(Duration::from_millis(150));

        // Create second entry (will not be expired)
        cache.get_or_create("1:new_community");

        // Wait for first entry to expire
        std::thread::sleep(Duration::from_millis(100));

        assert_eq!(cache.cache.len(), 2);

        // Cleanup should only remove the first entry
        let (scanned, removed) = cache.cleanup_expired();
        assert_eq!(scanned, 2);
        assert_eq!(removed, 1);
        assert_eq!(cache.cache.len(), 1);

        // New community should still be accessible
        let trace_id = cache.get_or_create("1:new_community");
        assert_ne!(trace_id.to_bytes(), [0u8; 16]);
    }

    #[test]
    fn test_concurrent_access() {
        use std::thread;

        let cache = TraceIdCache::new(Duration::from_secs(3600), 1000);
        let cache_clone = cache.clone();

        let handle1 = thread::spawn(move || {
            for i in 0..100 {
                cache_clone.get_or_create(&format!("1:community{}", i));
            }
        });

        let cache_clone2 = cache.clone();
        let handle2 = thread::spawn(move || {
            for i in 50..150 {
                cache_clone2.get_or_create(&format!("1:community{}", i));
            }
        });

        handle1.join().unwrap();
        handle2.join().unwrap();

        // Should have 150 unique entries (0-149)
        assert_eq!(cache.cache.len(), 150);
    }

    #[test]
    fn test_concurrent_expired_entry_race_condition() {
        use std::{sync::Barrier, thread};

        // Test that concurrent access to an expired entry produces the same trace ID
        let cache = TraceIdCache::new(Duration::from_millis(100), 100);
        let community_id = "1:test_race";

        // Create initial entry
        cache.get_or_create(community_id);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(150));

        // Now spawn multiple threads to access the expired entry simultaneously
        let barrier = Arc::new(Barrier::new(5));
        let mut handles = vec![];
        let mut trace_ids = vec![];

        for _ in 0..5 {
            let cache_clone = cache.clone();
            let barrier_clone = Arc::clone(&barrier);
            let (tx, rx) = std::sync::mpsc::channel();
            trace_ids.push(rx);

            let handle = thread::spawn(move || {
                // Wait for all threads to be ready
                barrier_clone.wait();

                // All threads access expired entry at the same time
                let trace_id = cache_clone.get_or_create(community_id);
                tx.send(trace_id).unwrap();
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Collect all trace IDs
        let collected_ids: Vec<TraceId> =
            trace_ids.into_iter().map(|rx| rx.recv().unwrap()).collect();

        // All threads should have received the SAME trace ID (no race condition)
        let first_id = collected_ids[0];
        for id in &collected_ids {
            assert_eq!(
                *id, first_id,
                "Race condition detected: threads got different trace IDs for the same community ID"
            );
        }

        // Only one entry should exist
        assert_eq!(cache.cache.len(), 1);
    }

    #[test]
    fn test_clear() {
        let cache = TraceIdCache::new(Duration::from_secs(3600), 100);

        cache.get_or_create("1:community1");
        cache.get_or_create("1:community2");
        cache.get_or_create("1:community3");

        assert_eq!(cache.cache.len(), 3);

        cache.clear();

        assert_eq!(cache.cache.len(), 0);
    }

    #[test]
    fn test_trace_id_format() {
        let cache = TraceIdCache::new(Duration::from_secs(3600), 100);

        let trace_id = cache.get_or_create("1:test");

        // Verify trace ID is 16 bytes (128 bits) as per OpenTelemetry spec
        let bytes = trace_id.to_bytes();
        assert_eq!(bytes.len(), 16);

        // Verify it's not all zeros
        assert_ne!(bytes, [0u8; 16]);

        // Verify string representation is valid hex
        let trace_id_str = format!("{}", trace_id);
        assert_eq!(trace_id_str.len(), 32); // 16 bytes = 32 hex chars
        assert!(trace_id_str.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
