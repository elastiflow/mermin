use std::time::Duration;

/// Configuration for shutdown behavior.
#[derive(Debug, Clone)]
pub struct ShutdownConfig {
    /// Timeout for graceful shutdown before forcing cancellation.
    pub timeout: Duration,
    /// Whether to preserve active flows during shutdown.
    pub preserve_flows: bool,
    /// Maximum time to wait for flow preservation.
    pub flow_preservation_timeout: Duration,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            preserve_flows: true,
            flow_preservation_timeout: Duration::from_secs(10),
        }
    }
}
