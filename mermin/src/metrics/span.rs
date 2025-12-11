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

/// Set the current size of a flow store for a specific poller.
///
/// Called periodically by flow pollers to track the number of active flows.
pub fn set_flow_store_size(poller_id: &str, size: usize) {
    registry::FLOW_SPAN_STORE_SIZE
        .with_label_values(&[poller_id])
        .set(size as i64);
}

/// Set the current queue size for a specific flow poller.
///
/// Called periodically by flow pollers to track the number of flows queued for processing.
/// Combined with flow_store_size, this can be used to calculate utilization.
pub fn set_poller_queue_size(poller_id: &str, size: usize) {
    registry::PRODUCER_QUEUE_SIZE
        .with_label_values(&[poller_id])
        .set(size as i64);
}
