//! Helper functions for Kubernetes decorator metrics.

use crate::metrics::registry;

/// Increment the K8s decorator flow spans counter.
///
/// ### Arguments
///
/// - `status` - Decoration status: "dropped", "ok", "error", or "undecorated"
pub fn inc_k8s_decorator_flow_spans(status: &str) {
    registry::K8S_DECORATOR_FLOW_SPANS_TOTAL
        .with_label_values(&[status])
        .inc();
}
