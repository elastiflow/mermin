use std::{error::Error, fmt};

#[derive(Debug)]
pub enum OtlpError {
    ExporterConfiguration(String),
    InvalidEndpoint { endpoint: String, details: String },
    TlsConfiguration(String),
    TonicTransport(tonic::transport::Error),
}

impl fmt::Display for OtlpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExporterConfiguration(msg) => {
                write!(f, "failed to create OTLP exporter: {msg}")
            }
            Self::InvalidEndpoint { endpoint, details } => {
                write!(f, "invalid exporter endpoint '{endpoint}': {details}")
            }
            Self::TlsConfiguration(msg) => write!(f, "TLS configuration error: {msg}"),
            Self::TonicTransport(e) => write!(f, "tonic transport error: {e}"),
        }
    }
}

impl Error for OtlpError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::TonicTransport(e) => Some(e),
            Self::ExporterConfiguration(_)
            | Self::InvalidEndpoint { .. }
            | Self::TlsConfiguration(_) => None,
        }
    }
}

impl From<tonic::transport::Error> for OtlpError {
    fn from(e: tonic::transport::Error) -> Self {
        Self::TonicTransport(e)
    }
}

impl OtlpError {
    pub fn invalid_endpoint(endpoint: impl Into<String>, details: impl Into<String>) -> Self {
        Self::InvalidEndpoint {
            endpoint: endpoint.into(),
            details: details.into(),
        }
    }
}
