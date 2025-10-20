use thiserror::Error;

/// Errors that can occur during OTLP operations
#[derive(Debug, Error)]
pub enum OtlpError {
    /// Failed to initialize OTLP provider
    #[error("failed to initialize OTLP provider: {0}")]
    #[allow(dead_code)]
    ProviderInitialization(String),

    /// Failed to create OTLP exporter
    #[error("failed to create OTLP exporter: {0}")]
    #[allow(dead_code)]
    ExporterCreation(String),

    /// Failed to configure OTLP exporter
    #[error("failed to configure OTLP exporter: {0}")]
    #[allow(dead_code)]
    ExporterConfiguration(String),

    /// Failed to export trace data
    #[error("failed to export trace data: {0}")]
    #[allow(dead_code)]
    TraceExport(String),

    /// Failed to initialize internal tracing
    #[error("failed to initialize internal tracing: {0}")]
    #[allow(dead_code)]
    InternalTracingInitialization(String),

    /// Failed to set global tracer provider
    #[error("failed to set global tracer provider: {0}")]
    #[allow(dead_code)]
    GlobalTracerProvider(String),

    /// Invalid exporter options
    #[error("invalid exporter options: {0}")]
    #[allow(dead_code)]
    InvalidOptions(String),

    /// Exporter endpoint error
    #[error("invalid exporter endpoint '{endpoint}': {details}")]
    #[allow(dead_code)]
    InvalidEndpoint { endpoint: String, details: String },

    /// TLS configuration error
    #[error("TLS configuration error: {0}")]
    #[allow(dead_code)]
    TlsConfiguration(String),

    /// Batch processor configuration error
    #[error("batch processor configuration error: {0}")]
    #[allow(dead_code)]
    BatchProcessorConfiguration(String),

    /// Tonic transport error
    #[error("tonic transport error: {0}")]
    TonicTransport(#[from] tonic::transport::Error),
}

impl OtlpError {
    /// Create an invalid endpoint error
    #[allow(dead_code)]
    pub fn invalid_endpoint(endpoint: impl Into<String>, details: impl Into<String>) -> Self {
        Self::InvalidEndpoint {
            endpoint: endpoint.into(),
            details: details.into(),
        }
    }
}
