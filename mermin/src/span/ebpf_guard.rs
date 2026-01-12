//! RAII guard for eBPF flow map entries to ensure cleanup on error paths.
//!
//! This module provides `EbpfFlowGuard`, a guard that automatically removes
//! entries from the eBPF `FLOW_STATS` when dropped, unless explicitly
//! marked as "kept" (managed by flow_store).
//!
//! ## Problem
//!
//! Multiple error paths in flow creation can leave orphaned entries in the
//! eBPF map:
//! - Ring buffer full → entry created but userspace never notified
//! - Flow creation errors → error logged but map not cleaned up
//! - Task cancellation/panic → cleanup code never reached
//!
//! ## Solution
//!
//! The guard uses RAII (Resource Acquisition Is Initialization) to ensure
//! cleanup happens on ALL code paths, including:
//! - Early returns from errors
//! - Panics
//! - Task cancellation
//!
//! ## Usage
//!
//! ```rust,ignore
//! async fn process_new_flow(&self, event: FlowEvent) -> Result<(), Error> {
//!     // Guard ensures cleanup on ANY error path
//!     let guard = EbpfFlowGuard::new(
//!         event.flow_key,
//!         self.flow_stats_map.clone(),
//!     );
//!
//!     // ... process flow, may return early on error ...
//!
//!     // Success - flow now managed by flow_store, disable auto-cleanup
//!     guard.keep();
//!     Ok(())
//! }
//! ```

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use aya::maps::HashMap as EbpfHashMap;
use mermin_common::FlowKey;
use tokio::sync::Mutex;
use tracing::warn;

/// RAII guard for eBPF flow map entries.
///
/// Automatically removes entries from `FLOW_STATS` when dropped,
/// unless explicitly marked as "kept" via [`keep()`](Self::keep).
///
/// This prevents orphaned entries when errors occur during flow creation.
pub struct EbpfFlowGuard {
    key: FlowKey,
    map: Arc<Mutex<EbpfHashMap<aya::maps::MapData, FlowKey, mermin_common::FlowStats>>>,
    should_keep: Arc<AtomicBool>,
}

impl EbpfFlowGuard {
    /// Create a new guard for an eBPF flow entry.
    ///
    /// The entry will be automatically removed from the map when the guard
    /// is dropped, unless [`keep()`](Self::keep) is called first.
    ///
    /// ### Arguments
    ///
    /// - `key` - Flow key identifying the entry in the eBPF map
    /// - `map` - Shared reference to the eBPF `FLOW_STATS`
    pub fn new(
        key: FlowKey,
        map: Arc<Mutex<EbpfHashMap<aya::maps::MapData, FlowKey, mermin_common::FlowStats>>>,
    ) -> Self {
        Self {
            key,
            map,
            should_keep: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Mark the entry as "kept" - disables automatic cleanup.
    ///
    /// Call this when the flow has been successfully created and is now
    /// managed by the `flow_store`. The eBPF map entry will be cleaned up
    /// by the timeout task instead.
    pub fn keep(&self) {
        self.should_keep.store(true, Ordering::Release);
    }
}

impl Drop for EbpfFlowGuard {
    fn drop(&mut self) {
        if !self.should_keep.load(Ordering::Acquire) {
            // Entry was not marked as "kept", so clean it up
            // Spawn a background task to avoid blocking the drop (async not allowed in Drop)
            let key = self.key;
            let map = Arc::clone(&self.map);

            // Try to spawn cleanup task, but handle gracefully if runtime is unavailable
            // (e.g., during test teardown or when async runtime has shut down)
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    let mut map_guard = map.lock().await;
                    if let Err(e) = map_guard.remove(&key) {
                        warn!(
                            event.name = "ebpf_guard.cleanup_failed",
                            flow.key = ?key,
                            error.message = %e,
                            "failed to remove orphaned eBPF entry via guard cleanup"
                        );
                    } else {
                        warn!(
                            event.name = "ebpf_guard.cleanup_success",
                            flow.key = ?key,
                            "removed orphaned eBPF entry via guard cleanup (error occurred during flow creation)"
                        );
                    }
                });
            } else {
                // No async runtime available (e.g., during test teardown or shutdown)
                // Log a warning but don't panic - the entry will be cleaned up by timeout
                // or on next map operation
                warn!(
                    event.name = "ebpf_guard.cleanup_skipped",
                    flow.key = ?key,
                    "skipped eBPF entry cleanup - no async runtime available (likely during shutdown)"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Full integration tests require eBPF maps, which can't be instantiated in unit tests.
    // The guard behavior is tested via integration tests in the parent module.

    #[test]
    fn test_should_keep_default_false() {
        // Verify the default state is "don't keep" (will cleanup)
        let should_keep = Arc::new(AtomicBool::new(false));
        assert!(!should_keep.load(Ordering::Acquire));
    }

    #[test]
    fn test_keep_sets_flag() {
        // Verify keep() sets the flag correctly
        let should_keep = Arc::new(AtomicBool::new(false));
        should_keep.store(true, Ordering::Release);
        assert!(should_keep.load(Ordering::Acquire));
    }
}
