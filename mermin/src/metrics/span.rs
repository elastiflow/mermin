//! Helper functions for flow span pipeline metrics.
//!
//! This module provides convenience functions for tracking flow spans through
//! the processing pipeline: ring buffer → worker → decoration → export.

use crate::metrics::registry;

/// Increment the flow spans processed counter.
///
/// Called when FlowWorker successfully creates a flow span from a flow event.
pub fn inc_flow_spans_processed() {
    registry::FLOW_SPANS_PROCESSED_TOTAL.inc();
}

/// Increment the flow spans sent to exporter counter.
///
/// Called when a flow span is successfully sent to the export channel.
/// This is distinct from exported (which happens when the exporter actually sends to backend).
pub fn inc_flow_spans_sent_to_exporter() {
    registry::FLOW_SPANS_SENT_TO_EXPORTER_TOTAL.inc();
}

/// Set the flow store size gauge.
///
/// ### Arguments
///
/// - `poller_id` - ID of the poller (for sharded tracking)
/// - `size` - Current number of flows in the flow_store
pub fn set_flow_store_size(poller_id: usize, size: usize) {
    registry::FLOW_STORE_SIZE
        .with_label_values(&[&poller_id.to_string()])
        .set(size as i64);
}

/// Set the flow poller queue size gauge.
///
/// ### Arguments
///
/// - `poller_id` - ID of the poller
/// - `size` - Current number of flows queued for processing
pub fn set_flow_poller_queue_size(poller_id: usize, size: usize) {
    registry::FLOW_POLLER_QUEUE_SIZE
        .with_label_values(&[&poller_id.to_string()])
        .set(size as i64);
}
