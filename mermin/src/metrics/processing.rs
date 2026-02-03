//! Enums for processing latency metrics labels.
//!
//! This module provides type-safe enums for metric label values used in
//! processing latency measurements across the Mermin pipeline. These enums
//! prevent typos and ensure consistency when labeling metrics.

/// Processing stage for latency metrics.
///
/// Represents different points in the flow processing pipeline where latency
/// is measured. Each stage corresponds to a specific operation in the data
/// flow from eBPF ring buffer to export.
///
/// These stages are used as labels for the processing latency histogram metric,
/// allowing you to track latency at each stage of the pipeline independently.
///
/// # Pipeline Flow
///
/// The stages follow the data flow through the system:
///
/// 1. **FlowProducerOut**: Flow producer processing from ringbuffer (fast, typically microseconds to milliseconds)
/// 2. **K8sDecoratorOut**: Kubernetes decoration and enrichment (medium, typically milliseconds)
/// 3. **ExportOut**: Export to OTLP/stdout (slow, can be seconds)
///
/// # Examples
///
/// Using the enum to label a latency metric:
///
/// ```no_run
/// use mermin::metrics::processing::ProcessingStage;
/// use mermin::metrics::registry;
///
/// // Start a timer for the flow producer output stage
/// let _timer = registry::processing_duration_seconds()
///     .with_label_values(&[ProcessingStage::FlowProducerOut.as_str()])
///     .start_timer();
///
/// // ... perform flow producer processing ...
///
/// // Timer automatically records the duration when dropped
/// ```
///
/// Converting to string for metric labels:
///
/// ```
/// use mermin::metrics::processing::ProcessingStage;
///
/// let stage = ProcessingStage::FlowProducerOut;
/// let label = stage.as_str(); // "flow_producer_out"
/// assert_eq!(label, "flow_producer_out");
/// ```
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessingStage {
    /// Time spent by the flow producer reading and processing flow events from the ringbuffer.
    ///
    /// This stage measures the latency of the flow producer processing flow events
    /// from the eBPF ring buffer. This includes reading, parsing, and initial
    /// processing of flow events in userspace.
    FlowProducerOut,

    /// Time spent enriching flow spans with Kubernetes metadata.
    ///
    /// This stage measures the latency of the Kubernetes decorator, which
    /// enriches flow spans with pod, service, and namespace information.
    /// This includes the time spent looking up Kubernetes resources and
    /// attaching metadata to spans.
    K8sDecoratorOut,

    /// Time spent exporting spans to configured exporters (OTLP or stdout).
    ///
    /// This stage measures the latency of exporting completed flow spans
    /// to configured exporters (OTLP or stdout). This includes serialization,
    /// network I/O (for OTLP), and any batching operations.
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
