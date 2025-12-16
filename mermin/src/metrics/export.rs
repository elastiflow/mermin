//! Helper functions for export-related metrics.

use std::time::Duration;

use crate::metrics::registry;

/// Export status for flow spans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportStatus {
    Ok,
    Error,
    NoOp,
}

impl AsRef<str> for ExportStatus {
    fn as_ref(&self) -> &str {
        match self {
            ExportStatus::Ok => "ok",
            ExportStatus::Error => "error",
            ExportStatus::NoOp => "noop",
        }
    }
}

/// Increment the export flow spans counter.
///
/// `exporter_type` - The type of exporter: "otlp" or "stdout"
/// `status` - The export status: "ok", "error", or "noop"
pub fn inc_export_flow_spans(exporter_type: &str, status: ExportStatus) {
    registry::EXPORT_FLOW_SPANS_TOTAL
        .with_label_values(&[exporter_type, status.as_ref()])
        .inc();
}

/// Record export batch span count.
pub fn observe_export_batch_spans(count: usize) {
    registry::EXPORT_BATCH_SIZE.observe(count as f64);
}

/// Increment the export timeouts counter.
///
/// Called when an export operation times out.
pub fn inc_export_timeouts() {
    registry::EXPORT_TIMEOUTS_TOTAL.inc();
}

/// Record time spent blocked waiting for export operations.
///
/// Called to track how long the pipeline is blocked waiting for export to complete.
pub fn observe_export_blocking_time(duration: Duration) {
    registry::EXPORT_BLOCKING_TIME_SECONDS.observe(duration.as_secs_f64());
}
