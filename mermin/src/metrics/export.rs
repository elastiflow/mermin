//! Helper functions for export-related metrics.

use std::time::Duration;

use crate::metrics::registry;

/// Increment the export flow spans counter.
///
/// ### Arguments
///
/// - `status` - Export status: "queued", "dropped", "ok", or "error"
pub fn inc_export_flow_spans(status: &str) {
    registry::EXPORT_FLOW_SPANS_TOTAL
        .with_label_values(&[status])
        .inc();
}

/// Record export operation latency.
///
/// ### Arguments
///
/// - `duration` - Time taken for the export operation
pub fn observe_export_latency(duration: Duration) {
    registry::EXPORT_LATENCY.observe(duration.as_secs_f64());
}
