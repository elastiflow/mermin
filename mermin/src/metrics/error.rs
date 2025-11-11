//! Error types for the metrics module.

use std::io;

use thiserror::Error;

/// Errors that can occur in the metrics system.
#[derive(Debug, Error)]
pub enum MetricsError {
    /// Failed to bind to the configured address and port.
    #[error("failed to bind metrics server to {address}: {source}")]
    BindAddress {
        /// The address that failed to bind.
        address: String,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// Failed to serve HTTP requests.
    #[error("metrics server error: {0}")]
    ServeError(#[from] io::Error),

    /// Prometheus registry error.
    #[error("prometheus registry error: {0}")]
    PrometheusError(#[from] prometheus::Error),
}

impl MetricsError {
    /// Create a bind address error.
    pub fn bind_address(address: impl Into<String>, source: io::Error) -> Self {
        Self::BindAddress {
            address: address.into(),
            source,
        }
    }
}
