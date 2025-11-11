//! Helper functions for export-related metrics.

use std::time::Duration;

use crate::metrics::registry;

/// Increment the spans exported counter.
///
/// ### Arguments
///
/// - `count` - Number of spans successfully exported
pub fn inc_spans_exported(count: u64) {
    registry::SPANS_EXPORTED.inc_by(count);
}

/// Record export operation latency.
///
/// ### Arguments
///
/// - `duration` - Time taken for the export operation
pub fn observe_export_latency(duration: Duration) {
    registry::EXPORT_LATENCY.observe(duration.as_secs_f64());
}
