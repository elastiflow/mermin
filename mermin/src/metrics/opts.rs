use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MetricsOptions {
    /// Enable the metrics server.
    pub enabled: bool,
    /// The network address the metrics server will listen on.
    pub listen_address: String,
    /// The port the metrics server will listen on.
    pub port: u16,
}

impl Default for MetricsOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_address: Ipv4Addr::UNSPECIFIED.to_string(),
            port: 10250,
        }
    }
}
