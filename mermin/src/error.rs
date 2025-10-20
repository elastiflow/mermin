use thiserror::Error;

use crate::{
    health::HealthError, k8s::K8sError, otlp::OtlpError, runtime::context::ContextError,
    span::producer::BootTimeError,
};

/// Main application error type for Mermin
#[derive(Debug, Error)]
pub enum MerminError {
    /// Kubernetes-related errors
    #[error("kubernetes error: {0}")]
    K8s(#[from] K8sError),

    /// OTLP/tracing-related errors
    #[error("OTLP error: {0}")]
    Otlp(#[from] OtlpError),

    /// Health check/API server errors
    #[error("health check error: {0}")]
    Health(#[from] HealthError),

    /// Runtime context initialization errors
    #[error("context error: {0}")]
    Context(#[from] ContextError),

    /// Boot time calculation errors
    #[error("boot time error: {0}")]
    BootTime(#[from] BootTimeError),

    /// eBPF loading errors
    #[error("failed to load eBPF program: {0}")]
    EbpfLoad(#[from] aya::EbpfError),

    /// eBPF program errors
    #[error("eBPF program error: {0}")]
    EbpfProgram(#[from] aya::programs::ProgramError),

    /// eBPF map errors
    #[error("eBPF map error: {0}")]
    EbpfMap(String),

    /// eBPF map conversion errors
    #[error("eBPF map conversion error: {0}")]
    EbpfMapConversion(#[from] aya::maps::MapError),

    /// eBPF logger initialization errors
    #[error("failed to initialize eBPF logger: {0}")]
    #[allow(dead_code)]
    EbpfLogger(String),

    /// Network interface errors
    #[error("network interface error: {0}")]
    #[allow(dead_code)]
    NetworkInterface(String),

    /// TC (traffic control) errors
    #[error("TC (traffic control) error: {0}")]
    #[allow(dead_code)]
    TrafficControl(String),

    /// Channel send/receive errors
    #[error("channel error: {0}")]
    #[allow(dead_code)]
    Channel(String),

    /// Signal handling errors
    #[error("signal handling error: {0}")]
    Signal(#[from] std::io::Error),

    /// Flow span producer initialization errors
    #[error("failed to initialize flow span producer: {0}")]
    #[allow(dead_code)]
    FlowSpanProducer(String),

    /// Configuration errors (delegated to ContextError, but can be caught separately)
    #[error("configuration error: {0}")]
    #[allow(dead_code)]
    Configuration(String),

    /// Generic internal error
    #[error("internal error: {0}")]
    #[allow(dead_code)]
    Internal(String),
}

impl MerminError {
    /// Create an eBPF map error
    pub fn ebpf_map(msg: impl Into<String>) -> Self {
        Self::EbpfMap(msg.into())
    }

    /// Create an eBPF logger error
    #[allow(dead_code)]
    pub fn ebpf_logger(msg: impl Into<String>) -> Self {
        Self::EbpfLogger(msg.into())
    }

    /// Create a network interface error
    #[allow(dead_code)]
    pub fn network_interface(msg: impl Into<String>) -> Self {
        Self::NetworkInterface(msg.into())
    }

    /// Create a traffic control error
    #[allow(dead_code)]
    pub fn traffic_control(msg: impl Into<String>) -> Self {
        Self::TrafficControl(msg.into())
    }

    /// Create a channel error
    #[allow(dead_code)]
    pub fn channel(msg: impl Into<String>) -> Self {
        Self::Channel(msg.into())
    }

    /// Create a flow span producer error
    #[allow(dead_code)]
    pub fn flow_span_producer(msg: impl Into<String>) -> Self {
        Self::FlowSpanProducer(msg.into())
    }

    /// Create a configuration error
    #[allow(dead_code)]
    pub fn configuration(msg: impl Into<String>) -> Self {
        Self::Configuration(msg.into())
    }

    /// Create an internal error
    #[allow(dead_code)]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

/// Type alias for Result with MerminError
pub type Result<T> = std::result::Result<T, MerminError>;
