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
/// 1. **EbpfRingbufOutput**: eBPF ring buffer → userspace (fast, typically microseconds)
/// 2. **ProducerOutput**: Kubernetes decoration and enrichment (medium, typically milliseconds)
/// 3. **DecoratorOutput**: Export to OTLP/stdout (slow, can be seconds)
///
/// # Examples
///
/// Using the enum to label a latency metric:
///
/// ```no_run
/// use mermin::metrics::processing::ProcessingStage;
/// use mermin::metrics::registry::PROCESSING_LATENCY_SECONDS;
///
/// // Start a timer for the eBPF ring buffer output stage
/// let _timer = PROCESSING_LATENCY_SECONDS
///     .with_label_values(&[ProcessingStage::EbpfRingbufOutput.as_str()])
///     .start_timer();
///
/// // ... perform eBPF ring buffer processing ...
///
/// // Timer automatically records the duration when dropped
/// ```
///
/// Converting to string for metric labels:
///
/// ```
/// use mermin::metrics::processing::ProcessingStage;
///
/// let stage = ProcessingStage::ProducerOutput;
/// let label = stage.as_str(); // "producer_output"
/// assert_eq!(label, "producer_output");
/// ```
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessingStage {
    /// Time spent reading and processing flow events from the eBPF ring buffer.
    ///
    /// This stage measures the latency from when data is available in the eBPF
    /// ring buffer until it's been read and parsed into flow events in userspace.
    EbpfRingbufOutput,

    /// Time spent enriching flow spans with Kubernetes metadata.
    ///
    /// This stage measures the latency of the Kubernetes decorator, which
    /// enriches flow spans with pod, service, and namespace information.
    /// This includes the time spent looking up Kubernetes resources and
    /// attaching metadata to spans.
    ProducerOutput,

    /// Time spent exporting spans to the OTLP backend.
    ///
    /// This stage measures the latency of exporting completed flow spans
    /// to configured exporters (OTLP or stdout). This includes serialization,
    /// network I/O (for OTLP), and any batching operations.
    DecoratorOutput,
}

impl ProcessingStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            ProcessingStage::EbpfRingbufOutput => "ebpf_ringbuf_output",
            ProcessingStage::ProducerOutput => "producer_output",
            ProcessingStage::DecoratorOutput => "decorator_output",
        }
    }
}
