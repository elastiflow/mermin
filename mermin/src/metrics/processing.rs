//! Enums for processing latency metrics labels.

/// Processing stage for latency metrics.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessingStage {
    EbpfRingbufOutput,
    ProducerOutput,
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
