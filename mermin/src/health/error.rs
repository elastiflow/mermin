use std::{error::Error, fmt};

#[derive(Debug)]
pub enum HealthError {
    BindAddress {
        address: String,
        source: std::io::Error,
    },
    #[allow(dead_code)]
    ServerStart(std::io::Error),
    ServeError(std::io::Error),
    #[allow(dead_code)]
    InconsistentState(String),
    #[allow(dead_code)]
    RouterConfiguration(String),
}

impl fmt::Display for HealthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BindAddress { address, source } => {
                write!(f, "failed to bind API server to {address}: {source}")
            }
            Self::ServerStart(e) => write!(f, "failed to start API server: {e}"),
            Self::ServeError(e) => write!(f, "failed to serve requests: {e}"),
            Self::InconsistentState(msg) => {
                write!(f, "health check state is inconsistent: {msg}")
            }
            Self::RouterConfiguration(msg) => {
                write!(f, "failed to configure health router: {msg}")
            }
        }
    }
}

impl Error for HealthError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::BindAddress { source, .. } => Some(source),
            Self::ServerStart(e) => Some(e),
            Self::ServeError(e) => Some(e),
            Self::InconsistentState(_) | Self::RouterConfiguration(_) => None,
        }
    }
}

impl HealthError {
    pub fn bind_address(address: impl Into<String>, source: std::io::Error) -> Self {
        Self::BindAddress {
            address: address.into(),
            source,
        }
    }
}
