use thiserror::Error;

/// Errors that can occur during health check operations
#[derive(Debug, Error)]
pub enum HealthError {
    /// Failed to bind API server to address
    #[error("failed to bind API server to {address}: {source}")]
    BindAddress {
        address: String,
        #[source]
        source: std::io::Error,
    },

    /// Failed to start API server
    #[error("failed to start API server: {0}")]
    #[allow(dead_code)]
    ServerStart(#[source] std::io::Error),

    /// Failed to serve requests
    #[error("failed to serve requests: {0}")]
    ServeError(#[source] std::io::Error),

    /// Health check state inconsistent
    #[error("health check state is inconsistent: {0}")]
    #[allow(dead_code)]
    InconsistentState(String),

    /// Router configuration error
    #[error("failed to configure health router: {0}")]
    #[allow(dead_code)]
    RouterConfiguration(String),
}

impl HealthError {
    /// Create a bind address error
    pub fn bind_address(address: impl Into<String>, source: std::io::Error) -> Self {
        Self::BindAddress {
            address: address.into(),
            source,
        }
    }
}
