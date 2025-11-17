//! Prometheus metrics collection and HTTP server.
//!
//! This module provides comprehensive observability for Mermin through Prometheus-compatible
//! metrics exposed via HTTP at `/metrics`.
//!
//! ## Metric Categories
//!
//! - **eBPF Resource Metrics**: Map utilization, ring buffer drops, orphan cleanup
//! - **Flow Lifecycle**: Creation, expiry, duration, active counts
//! - **Export Performance**: Success/error rates, batch sizes, latency
//! - **Interface Statistics**: Packet/byte counters per interface
//!
//! ## Usage
//!
//! ```rust,ignore
//! use mermin::metrics::{self, registry};
//!
//! // Initialize registry once at startup
//! registry::init_registry()?;
//!
//! // Start metrics HTTP server
//! let metrics_handle = tokio::spawn(metrics::start_metrics_server(config.metrics));
//!
//! // Instrument code
//! registry::FLOWS_CREATED.with_label_values(&["eth0"]).inc();
//! ```

use axum::{Router, http::StatusCode, response::IntoResponse, routing::get};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::metrics::{error::MetricsError, opts::MetricsOptions, registry};

/// Handler for the `/metrics` endpoint.
///
/// Returns Prometheus text format metrics for all registered collectors.
async fn metrics_handler() -> impl IntoResponse {
    match tokio::task::spawn_blocking(|| {
        let encoder = prometheus::TextEncoder::new();
        let metric_families = registry::REGISTRY.gather();
        encoder.encode_to_string(&metric_families)
    })
    .await
    {
        Ok(Ok(body)) => (StatusCode::OK, body),
        Ok(Err(e)) => {
            tracing::error!(
                event.name = "metrics.encode_failed",
                error.message = %e,
                "failed to encode metrics"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to encode metrics: {e}"),
            )
        }
        Err(e) => {
            tracing::error!(
                event.name = "metrics.gather_failed",
                error.message = %e,
                "metrics gathering task panicked"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to gather metrics".to_string(),
            )
        }
    }
}

/// Handler for the `/metrics_debug` endpoint.
///
/// Returns Prometheus text format metrics for debug-specific collectors.
async fn debug_handler() -> impl IntoResponse {
    match tokio::task::spawn_blocking(|| {
        let encoder = prometheus::TextEncoder::new();
        let metric_families = registry::DEBUG_REGISTRY.gather();
        encoder.encode_to_string(&metric_families)
    })
    .await
    {
        Ok(Ok(body)) => (StatusCode::OK, body),
        Ok(Err(e)) => {
            tracing::error!(
                event.name = "debug.encode_failed",
                error.message = %e,
                "failed to encode debug metrics"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to encode debug metrics: {e}"),
            )
        }
        Err(e) => {
            tracing::error!(
                event.name = "debug.gather_failed",
                error.message = %e,
                "debug metrics gathering task panicked"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to gather debug metrics".to_string(),
            )
        }
    }
}

/// Create the metrics HTTP router.
fn create_metrics_router(config: &MetricsOptions) -> Router {
    let mut router = Router::new().route("/metrics", get(metrics_handler));

    if config.debug_enabled {
        router = router.route("/metrics_debug", get(debug_handler));
    }

    router.layer(TraceLayer::new_for_http())
}

/// Start the Prometheus metrics HTTP server.
///
/// Serves metrics at `<listen_address>:<port>/metrics` in Prometheus text format.
///
/// ### Arguments
///
/// - `config` - Metrics server configuration (address, port, enabled flag)
///
/// ### Returns
///
/// Returns `Ok(())` on successful shutdown, or `MetricsError` if startup fails.
///
/// ### Example
///
/// ```rust,ignore
/// let config = MetricsConf {
///     enabled: true,
///     listen_address: "0.0.0.0".to_string(),
///     port: 10250,
/// };
///
/// tokio::spawn(start_metrics_server(config));
/// ```
pub async fn start_metrics_server(config: MetricsOptions) -> Result<(), MetricsError> {
    if !config.enabled {
        info!(
            event.name = "metrics.disabled",
            "metrics server is disabled in configuration"
        );
        return Ok(());
    }

    let app = create_metrics_router(&config);

    let bind_address = format!("{}:{}", config.listen_address, config.port);
    let listener = TcpListener::bind(&bind_address)
        .await
        .map_err(|e| MetricsError::bind_address(&bind_address, e))?;

    info!(
        event.name = "metrics.started",
        net.listen.address = %bind_address,
        "metrics server started"
    );

    axum::serve(listener, app)
        .await
        .map_err(MetricsError::ServeError)?;

    Ok(())
}
