//! Type-safe label value enums for all Prometheus metric dimensions.

use crate::metrics;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportStatus {
    Ok,
    Error,
    NoOp,
}

impl ExportStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            ExportStatus::Ok => "ok",
            ExportStatus::Error => "error",
            ExportStatus::NoOp => "noop",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExporterName {
    Otlp,
    Stdout,
    Noop,
}

impl ExporterName {
    pub const fn as_str(self) -> &'static str {
        match self {
            ExporterName::Otlp => "otlp",
            ExporterName::Stdout => "stdout",
            ExporterName::Noop => "noop",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowEventResult {
    Received,
    Filtered,
    DroppedBackpressure,
    DroppedError,
}

impl FlowEventResult {
    pub const fn as_str(self) -> &'static str {
        match self {
            FlowEventResult::Received => "received",
            FlowEventResult::Filtered => "filtered",
            FlowEventResult::DroppedBackpressure => "dropped_backpressure",
            FlowEventResult::DroppedError => "dropped_error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowSpanProducerStatus {
    Created,
    Recorded,
    Idled,
    Dropped,
}

impl FlowSpanProducerStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            FlowSpanProducerStatus::Created => "created",
            FlowSpanProducerStatus::Recorded => "recorded",
            FlowSpanProducerStatus::Idled => "idled",
            FlowSpanProducerStatus::Dropped => "dropped",
        }
    }
}

/// Processing stage for latency metrics.
///
/// Stages follow the data flow through the system:
/// 1. **FlowProducerOut**: Flow producer processing from ringbuffer (microseconds to milliseconds)
/// 2. **K8sDecoratorOut**: Kubernetes decoration and enrichment (milliseconds)
/// 3. **ExportOut**: Export to OTLP/stdout (can be seconds)
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessingStage {
    FlowProducerOut,
    K8sDecoratorOut,
    ExportOut,
}

impl ProcessingStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            ProcessingStage::FlowProducerOut => "flow_producer_out",
            ProcessingStage::K8sDecoratorOut => "k8s_decorator_out",
            ProcessingStage::ExportOut => "export_out",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum K8sDecoratorStatus {
    Dropped,
    Ok,
    Error,
    Undecorated,
}

impl K8sDecoratorStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            K8sDecoratorStatus::Dropped => "dropped",
            K8sDecoratorStatus::Ok => "ok",
            K8sDecoratorStatus::Error => "error",
            K8sDecoratorStatus::Undecorated => "undecorated",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum K8sWatcherEventType {
    Apply,
    Delete,
    Init,
    InitDone,
    Error,
}

impl K8sWatcherEventType {
    pub const fn as_str(self) -> &'static str {
        match self {
            K8sWatcherEventType::Apply => "apply",
            K8sWatcherEventType::Delete => "delete",
            K8sWatcherEventType::Init => "init",
            K8sWatcherEventType::InitDone => "init_done",
            K8sWatcherEventType::Error => "error",
        }
    }
}

pub fn inc_k8s_decorator_flow_spans(status: K8sDecoratorStatus) {
    metrics::registry::K8S_DECORATOR_FLOW_SPANS_TOTAL
        .with_label_values(&[status.as_str()])
        .inc();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelName {
    PacketWorker,
    ProducerOutput,
    DecoratorOutput,
}

impl ChannelName {
    pub const fn as_str(self) -> &'static str {
        match self {
            ChannelName::PacketWorker => "packet_worker",
            ChannelName::ProducerOutput => "producer_output",
            ChannelName::DecoratorOutput => "decorator_output",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelSendStatus {
    Success,
    Error,
    Backpressure,
}

impl ChannelSendStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            ChannelSendStatus::Success => "success",
            ChannelSendStatus::Error => "error",
            ChannelSendStatus::Backpressure => "backpressure",
        }
    }
}
