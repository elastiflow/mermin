//! Memory management utilities for Mermin
//!
//! This module provides utilities for managing memory usage, particularly
//! for handling DashMap capacity retention issues where maps allocate
//! capacity but never shrink it when entries are removed.

/// Configuration for DashMap capacity shrinking behavior.
///
/// DashMap allocates capacity that is never automatically released, even when
/// entries are removed. This can cause unbounded memory growth. The shrinking
/// policy determines when to call `shrink_to_fit()` to release excess capacity.
///
/// Capacity waste ratio threshold (as a numerator over denominator).
/// Shrink when: capacity > entries * (numerator / denominator)
///
/// Examples:
/// - (23, 8) = 2.875x threshold (after ~20% entry removal post-resize)
/// - (5, 2) = 2.5x threshold (shrink when capacity is 150% larger)
/// - (2, 1) = 2.0x threshold (shrink when capacity is 100% larger) - TOO TIGHT!
/// - (3, 2) = 1.5x threshold (shrink when capacity is 50% larger) - CAUSES THRASHING!
#[derive(Debug, Clone, Copy)]
pub struct ShrinkPolicy {
    /// Minimum capacity threshold - don't shrink maps smaller than this.
    /// Small maps aren't worth the overhead of shrinking.
    pub min_capacity: usize,

    /// Numerator of the waste ratio threshold.
    ///
    /// Used with `waste_ratio_denominator` to define when to shrink.
    /// Shrink occurs when: `capacity > entries * (numerator / denominator)`.
    pub waste_ratio_numerator: usize,

    /// Denominator of the waste ratio threshold.
    ///
    /// Used with `waste_ratio_numerator` to define when to shrink.
    /// Shrink occurs when: `capacity > entries * (numerator / denominator)`.
    pub waste_ratio_denominator: usize,
}

impl ShrinkPolicy {
    /// Default shrinking policy for userspace flow tracking maps.
    ///
    /// - Threshold: 2.875x (23/8 - shrink after ~20% entry removal post-resize)
    /// - Minimum: 10,000 entries (don't shrink small maps)
    ///
    /// Why 2.875x specifically?
    /// - DashMap resizes at 0.875 load factor (7/8 full)
    /// - After resize: capacity = 2x entries (since it was 0.875 full)
    /// - 2.875x = 23/8 keeps the 0.875 semantic consistency
    /// - Shrinks after ~20% of entries removed post-resize (meaningful decline signal)
    /// - Safe margin above 2x prevents thrashing from natural growth
    pub const fn userspace_flows() -> Self {
        Self {
            min_capacity: 10_000,
            waste_ratio_numerator: 23,
            waste_ratio_denominator: 8,
        }
    }

    /// Default shrinking policy for Kubernetes resource caches.
    ///
    /// - Threshold: 2.875x (23/8 - same as userspace flows)
    /// - Minimum: 100 entries (lower than flows since K8s caches are smaller)
    ///
    /// K8s caches use the same 2.875x threshold for consistency.
    /// This prevents thrashing after natural DashMap resizes while still
    /// recovering memory after ~20% of entries are removed post-growth.
    pub const fn k8s_cache() -> Self {
        Self {
            min_capacity: 100,
            waste_ratio_numerator: 23,
            waste_ratio_denominator: 8,
        }
    }

    /// Check if a DashMap should be shrunk based on this policy.
    ///
    /// # Examples
    ///
    /// ```
    /// use mermin::runtime::memory::ShrinkPolicy;
    ///
    /// let policy = ShrinkPolicy::userspace_flows();
    ///
    /// assert_eq!(policy.should_shrink(5_000, 1_000), false);
    ///
    /// assert_eq!(policy.should_shrink(100_000, 50_000), true);
    ///
    /// assert_eq!(policy.should_shrink(100_000, 90_000), false);
    /// ```
    pub const fn should_shrink(&self, capacity: usize, entries: usize) -> bool {
        // Check minimum capacity threshold
        if capacity <= self.min_capacity {
            return false;
        }

        // Check waste ratio: capacity > entries * (numerator / denominator)
        // Use integer math to avoid float: capacity * denominator > entries * numerator
        capacity * self.waste_ratio_denominator >= entries * self.waste_ratio_numerator
    }
}

impl Default for ShrinkPolicy {
    fn default() -> Self {
        Self::userspace_flows()
    }
}

/// Recommended initial capacities for DashMap instances.
///
/// These values balance memory efficiency with performance, assuming:
/// - Most deployments see 1K-10K flows/sec (not 100K)
/// - With shrink_to_fit() preventing bloat, we can start smaller
/// - Maps will resize if needed (amortized O(1) cost)
/// - Better to start small and grow than over-allocate 600 MB
pub mod initial_capacity {
    /// Interface map (iface_map).
    ///
    /// Typical deployments have 1-50 network interfaces.
    /// 16 entries avoids initial resizes for most systems.
    pub const INTERFACE_MAP: usize = 16;

    /// Kubernetes IP index (ip_index).
    ///
    /// Sized for medium K8s cluster (~500 pods):
    /// - 500 pods * 2 IPs avg = 1,000 IPs
    /// - Headroom: 1,024 entries (~100 KB)
    ///
    /// Large clusters (10K+ pods) will resize during initial sync.
    pub const K8S_IP_INDEX: usize = 1_024;

    /// Kubernetes watcher IP cache (ip_cache).
    ///
    /// Per-watcher cache for change detection:
    /// - Pod watcher: ~100-1000 pods typical
    /// - Service watcher: ~50-500 services typical
    /// - 256 entries covers small-to-medium clusters
    pub const K8S_WATCHER_CACHE: usize = 256;

    /// Calculate flow tracking capacity (FlowStore, TraceIdCache) based on pipeline base capacity.
    ///
    /// Uses a 4x multiplier (vs legacy 128x) to balance memory efficiency with performance.
    ///
    /// Calculation rationale:
    /// - Default base_capacity: 8,192 entries
    /// - 4x multiplier → 32,768 capacity (~13 MB)
    /// - Covers 10K flows/sec without resize
    /// - For extreme traffic (100K flows/sec), will resize to 1M naturally
    /// - With shrink_to_fit(), memory recovered after traffic drops
    ///
    /// # Examples
    ///
    /// ```
    /// use mermin::runtime::memory::initial_capacity;
    ///
    /// let capacity = initial_capacity::from_base_capacity(8_192);
    /// assert_eq!(capacity, 32_768);
    /// ```
    pub const fn from_base_capacity(base_capacity: usize) -> usize {
        // Use 4x multiplier instead of 128x
        // Provides reasonable headroom without massive over-allocation
        base_capacity * 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_shrink_below_min_capacity() {
        let policy = ShrinkPolicy::userspace_flows();

        // Even with 10x waste, don't shrink if below minimum
        assert!(!policy.should_shrink(5_000, 500));
        assert!(!policy.should_shrink(1_000, 100));
    }

    #[test]
    fn test_should_shrink_at_threshold() {
        let policy = ShrinkPolicy::userspace_flows();

        // Exactly at 2.875x threshold (23/8)
        // 10,000 * 23 / 8 = 28,750
        assert!(policy.should_shrink(28_750, 10_000));

        // Just over threshold
        assert!(policy.should_shrink(28_750, 9_999));

        // Just under threshold - don't shrink
        assert!(!policy.should_shrink(28_750, 10_001));
    }

    #[test]
    fn test_should_shrink_reasonable_capacity() {
        let policy = ShrinkPolicy::userspace_flows();

        // 1.1x - very efficient, don't shrink
        assert!(!policy.should_shrink(110_000, 100_000));

        // 2.0x - after DashMap resize, don't shrink (avoids thrashing)
        assert!(!policy.should_shrink(200_000, 100_000));

        // 2.5x - under 2.875x threshold, don't shrink
        assert!(!policy.should_shrink(250_000, 100_000));

        // 2.875x - at threshold (100K * 23/8 = 287,500), shrink
        assert!(policy.should_shrink(287_500, 100_000));

        // 3.0x - definitely shrink
        assert!(policy.should_shrink(300_000, 100_000));

        // 10x - wasteful, shrink
        assert!(policy.should_shrink(1_000_000, 100_000));
    }

    #[test]
    fn test_k8s_cache_policy_lower_minimum() {
        let policy = ShrinkPolicy::k8s_cache();

        // K8s cache has lower minimum (100 vs 10,000)
        // At 2.875x threshold: 100 * 23/8 = 287.5, so 288 capacity would shrink
        assert!(policy.should_shrink(288, 100)); // Would shrink K8s cache

        let flow_policy = ShrinkPolicy::userspace_flows();
        assert!(!flow_policy.should_shrink(288, 100)); // Wouldn't shrink flow map (below min)
    }

    #[test]
    fn test_shrink_after_20_percent_removal() {
        let policy = ShrinkPolicy::userspace_flows();

        // Simulate DashMap resize scenario
        // Map at 8_750/10_000 (87.5% full) → resizes to 20_000
        let capacity_after_resize = 20_000;
        let entries_after_resize = 8_750;

        // Immediately after resize: 2.29x ratio, don't shrink
        assert!(!policy.should_shrink(capacity_after_resize, entries_after_resize));

        // After 20% removal: 8_750 → 7_000 entries
        // Threshold: 20_000 > 7_000 * 2.875 = 20_000 > 20_125 → NO (just barely)
        let entries_20_percent_removed = 7_000;
        assert!(!policy.should_shrink(capacity_after_resize, entries_20_percent_removed));

        // After 21% removal: 8_750 → 6_910 entries
        // Threshold: 20_000 > 6_910 * 2.875 = 20_000 > 19_866.25 → YES
        let entries_21_percent_removed = 6_910;
        assert!(policy.should_shrink(capacity_after_resize, entries_21_percent_removed));

        // This confirms: shrinking triggers after ~20% entry removal post-resize
    }

    #[test]
    fn test_edge_cases() {
        let policy = ShrinkPolicy::userspace_flows();

        // Zero entries
        assert!(policy.should_shrink(100_000, 0));

        // Zero capacity (shouldn't happen in practice)
        assert!(!policy.should_shrink(0, 100_000));

        // Equal capacity and entries
        assert!(!policy.should_shrink(100_000, 100_000));
    }
}
