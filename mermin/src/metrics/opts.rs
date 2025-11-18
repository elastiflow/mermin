use std::{
    net::Ipv4Addr,
    sync::atomic::{AtomicBool, Ordering},
};

use serde::{Deserialize, Serialize};

/// Global flag indicating whether debug metrics are enabled.
/// This is set during initialization and checked before executing debug metric operations.
static DEBUG_METRICS_ENABLED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MetricsOptions {
    /// Enable the metrics server.
    pub enabled: bool,
    /// The network address the metrics server will listen on.
    pub listen_address: String,
    /// The port the metrics server will listen on.
    pub port: u16,
    /// Enable the debug metrics endpoint at /metrics/debug.
    pub debug_enabled: bool,
}

impl Default for MetricsOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_address: Ipv4Addr::UNSPECIFIED.to_string(),
            port: 10250,
            debug_enabled: false,
        }
    }
}

impl MetricsOptions {
    /// Initialize the global debug metrics flag based on the configuration.
    ///
    /// This should be called once during application startup after loading configuration.
    /// The flag is used by `with_debug_metrics` to avoid executing debug metric operations
    /// when debug metrics are disabled, saving resources.
    pub fn init_debug_flag(&self) {
        DEBUG_METRICS_ENABLED.store(self.debug_enabled, Ordering::Relaxed);
    }
}

/// Execute a closure only if debug metrics are enabled.
///
/// This function checks the global debug metrics flag before executing the provided closure.
/// When debug metrics are disabled, the closure is not executed, avoiding unnecessary
/// work and resource usage.
pub fn with_debug_metrics<F>(f: F)
where
    F: FnOnce(),
{
    if DEBUG_METRICS_ENABLED.load(Ordering::Relaxed) {
        f();
    }
}
