//! Helper functions for Kubernetes decorator metrics.

use crate::metrics::registry;

/// K8s decorator flow span status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum K8sDecoratorStatus {
    Dropped,
    Ok,
    Error,
    Undecorated,
}

impl AsRef<str> for K8sDecoratorStatus {
    fn as_ref(&self) -> &str {
        match self {
            K8sDecoratorStatus::Dropped => "dropped",
            K8sDecoratorStatus::Ok => "ok",
            K8sDecoratorStatus::Error => "error",
            K8sDecoratorStatus::Undecorated => "undecorated",
        }
    }
}

/// K8s watcher event types for metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum K8sWatcherEventType {
    Apply,
    Delete,
    Init,
    InitDone,
    Error,
}

impl AsRef<str> for K8sWatcherEventType {
    fn as_ref(&self) -> &str {
        match self {
            K8sWatcherEventType::Apply => "apply",
            K8sWatcherEventType::Delete => "delete",
            K8sWatcherEventType::Init => "init",
            K8sWatcherEventType::InitDone => "init_done",
            K8sWatcherEventType::Error => "error",
        }
    }
}

/// Increment the K8s decorator flow spans counter.
pub fn inc_k8s_decorator_flow_spans(status: K8sDecoratorStatus) {
    registry::K8S_DECORATOR_FLOW_SPANS_TOTAL
        .with_label_values(&[status.as_ref()])
        .inc();
}
