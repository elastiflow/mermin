use std::{error::Error, fmt};

use crate::{
    health::error::HealthError, k8s::K8sError, otlp::error::OtlpError, runtime::conf::ConfError,
    span::producer::BootTimeError,
};

#[derive(Debug)]
pub enum MerminError {
    K8s(K8sError),
    Otlp(OtlpError),
    Health(HealthError),
    Conf(ConfError),
    BootTime(BootTimeError),
    EbpfLoad(aya::EbpfError),
    EbpfProgram(aya::programs::ProgramError),
    EbpfMapConversion(aya::maps::MapError),
    Signal(std::io::Error),
    Internal(String),
}

impl fmt::Display for MerminError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::K8s(e) => write!(f, "kubernetes error: {e}"),
            Self::Otlp(e) => write!(f, "OTLP error: {e}"),
            Self::Health(e) => write!(f, "health check error: {e}"),
            Self::Conf(e) => write!(f, "configuration error: {e}"),
            Self::BootTime(e) => write!(f, "boot time error: {e}"),
            Self::EbpfLoad(e) => write!(f, "failed to load eBPF program: {e}"),
            Self::EbpfProgram(e) => write!(f, "eBPF program error: {e}"),
            Self::EbpfMapConversion(e) => write!(f, "eBPF map conversion error: {e}"),
            Self::Signal(e) => write!(f, "signal handling error: {e}"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl Error for MerminError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::K8s(e) => Some(e),
            Self::Otlp(e) => Some(e),
            Self::Health(e) => Some(e),
            Self::Conf(e) => Some(e),
            Self::BootTime(e) => Some(e),
            Self::EbpfLoad(e) => Some(e),
            Self::EbpfProgram(e) => Some(e),
            Self::EbpfMapConversion(e) => Some(e),
            Self::Signal(e) => Some(e),
            Self::Internal(_) => None,
        }
    }
}

impl From<K8sError> for MerminError {
    fn from(e: K8sError) -> Self {
        Self::K8s(e)
    }
}

impl From<OtlpError> for MerminError {
    fn from(e: OtlpError) -> Self {
        Self::Otlp(e)
    }
}

impl From<HealthError> for MerminError {
    fn from(e: HealthError) -> Self {
        Self::Health(e)
    }
}

impl From<ConfError> for MerminError {
    fn from(e: ConfError) -> Self {
        Self::Conf(e)
    }
}

impl From<BootTimeError> for MerminError {
    fn from(e: BootTimeError) -> Self {
        Self::BootTime(e)
    }
}

impl From<aya::EbpfError> for MerminError {
    fn from(e: aya::EbpfError) -> Self {
        Self::EbpfLoad(e)
    }
}

impl From<aya::programs::ProgramError> for MerminError {
    fn from(e: aya::programs::ProgramError) -> Self {
        Self::EbpfProgram(e)
    }
}

impl From<aya::maps::MapError> for MerminError {
    fn from(e: aya::maps::MapError) -> Self {
        Self::EbpfMapConversion(e)
    }
}

impl From<std::io::Error> for MerminError {
    fn from(e: std::io::Error) -> Self {
        Self::Signal(e)
    }
}

impl MerminError {
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

pub type Result<T> = std::result::Result<T, MerminError>;
