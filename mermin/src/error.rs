use thiserror::Error;

use crate::{
    health::error::HealthError, k8s::K8sError, otlp::error::OtlpError, runtime::conf::ConfError,
    span::producer::BootTimeError,
};

#[derive(Debug, Error)]
pub enum MerminError {
    #[error("kubernetes error: {0}")]
    K8s(#[from] K8sError),

    #[error("OTLP error: {0}")]
    Otlp(#[from] OtlpError),

    #[error("health check error: {0}")]
    Health(#[from] HealthError),

    #[error("configuration error: {0}")]
    Conf(#[from] ConfError),

    #[error("boot time error: {0}")]
    BootTime(#[from] BootTimeError),

    #[error("failed to load eBPF program: {0}")]
    EbpfLoad(#[from] aya::EbpfError),

    #[error("eBPF program error: {0}")]
    EbpfProgram(#[from] aya::programs::ProgramError),

    #[error("eBPF map conversion error: {0}")]
    EbpfMapConversion(#[from] aya::maps::MapError),

    #[error("signal handling error: {0}")]
    Signal(#[from] std::io::Error),

    #[error("internal error: {0}")]
    Internal(String),
}

impl MerminError {
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

pub type Result<T> = std::result::Result<T, MerminError>;
