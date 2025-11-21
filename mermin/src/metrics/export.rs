//! Helper functions for export-related metrics.

use std::time::Duration;

use crate::metrics::registry;

/// Export status for flow spans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportStatus {
    Queued,
    Dropped,
    Ok,
    Error,
}

impl AsRef<str> for ExportStatus {
    fn as_ref(&self) -> &str {
        match self {
            ExportStatus::Queued => "queued",
            ExportStatus::Dropped => "dropped",
            ExportStatus::Ok => "ok",
            ExportStatus::Error => "error",
        }
    }
}

/// Increment the export flow spans counter.
pub fn inc_export_flow_spans(status: ExportStatus) {
    registry::EXPORT_FLOW_SPANS_TOTAL
        .with_label_values(&[status.as_ref()])
        .inc();
}

/// Record export operation latency.
pub fn observe_export_latency(duration: Duration) {
    registry::EXPORT_LATENCY.observe(duration.as_secs_f64());
}
