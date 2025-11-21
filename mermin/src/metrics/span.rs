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
