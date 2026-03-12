use thiserror::Error;

#[derive(Debug, Error)]
pub enum OtlpError {
    #[error("failed to create OTLP exporter: {0}")]
    ExporterConfiguration(String),

    #[error("invalid exporter endpoint '{endpoint}': {details}")]
    InvalidEndpoint { endpoint: String, details: String },

    #[error("TLS configuration error: {0}")]
    TlsConfiguration(String),

    #[error("tonic transport error: {0}")]
    TonicTransport(#[from] tonic::transport::Error),
}

impl OtlpError {
    pub fn invalid_endpoint(endpoint: impl Into<String>, details: impl Into<String>) -> Self {
        Self::InvalidEndpoint {
            endpoint: endpoint.into(),
            details: details.into(),
        }
    }
}
