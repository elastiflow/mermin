use thiserror::Error;

use crate::{
    health::HealthError, k8s::K8sError, otlp::OtlpError, runtime::conf::ConfError,
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

    /// Runtime initialization errors
    #[error("configuration error: {0}")]
    Conf(#[from] ConfError),

    /// Boot time calculation errors
    #[error("boot time error: {0}")]
    BootTime(#[from] BootTimeError),

    /// eBPF loading errors
    #[error("failed to load eBPF program: {0}")]
    EbpfLoad(#[from] aya::EbpfError),

    /// eBPF program errors
    #[error("eBPF program error: {0}")]
    EbpfProgram(#[from] aya::programs::ProgramError),

    /// eBPF map conversion errors
    #[error("eBPF map conversion error: {0}")]
    EbpfMapConversion(#[from] aya::maps::MapError),

    /// Signal handling errors
    #[error("signal handling error: {0}")]
    Signal(#[from] std::io::Error),

    /// Generic internal error
    #[error("internal error: {0}")]
    #[allow(dead_code)]
    Internal(String),
}

impl MerminError {
    /// Create an internal error
    #[allow(dead_code)]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

/// Type alias for Result with MerminError
pub type Result<T> = std::result::Result<T, MerminError>;
