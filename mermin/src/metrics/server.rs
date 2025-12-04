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

/// Handler for the `/metrics/standard` endpoint.
///
/// Returns Prometheus text format metrics for standard collectors only (no high-cardinality labels).
/// Always returns 200 OK because standard metrics are always enabled.
async fn standard_metrics_handler() -> impl IntoResponse {
    match tokio::task::spawn_blocking(|| {
        let encoder = prometheus::TextEncoder::new();
        let metric_families = registry::STANDARD_REGISTRY.gather();
        encoder.encode_to_string(&metric_families)
    })
    .await
    {
        Ok(Ok(body)) => (StatusCode::OK, body),
        Ok(Err(e)) => {
            tracing::error!(
                event.name = "metrics.standard.encode_failed",
                error.message = %e,
                "failed to encode standard metrics"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to encode standard metrics: {e}"),
            )
        }
        Err(e) => {
            tracing::error!(
                event.name = "metrics.standard.gather_failed",
                error.message = %e,
                "standard metrics gathering task panicked"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to gather standard metrics".to_string(),
            )
        }
    }
}

/// Handler for the `/metrics/debug` endpoint.
///
/// Returns Prometheus text format metrics for debug collectors only (high-cardinality labels).
/// Returns 200 OK if debug metrics are enabled, 404 Not Found if disabled.
async fn debug_metrics_handler(debug_enabled: bool) -> impl IntoResponse {
    if !debug_enabled {
        return (
            StatusCode::NOT_FOUND,
            "Debug metrics are not enabled. Set metrics.debug_metrics_enabled = true to enable."
                .to_string(),
        );
    }

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
                event.name = "metrics.debug.encode_failed",
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
                event.name = "metrics.debug.gather_failed",
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
fn create_metrics_router(debug_enabled: bool) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/metrics/standard", get(standard_metrics_handler))
        .route(
            "/metrics/debug",
            get(move || debug_metrics_handler(debug_enabled)),
        )
        .layer(TraceLayer::new_for_http())
}

/// Start the Prometheus metrics HTTP server.
///
/// Serves metrics at:
/// - `<listen_address>:<port>/metrics` - All metrics (standard + debug if enabled)
/// - `<listen_address>:<port>/metrics/standard` - Standard metrics only (always available)
/// - `<listen_address>:<port>/metrics/debug` - Debug metrics only (404 if debug not enabled)
///
/// ### Example
///
/// ```rust,ignore
/// let opts = MetricsOptions {
///     enabled: true,
///     listen_address: "0.0.0.0".to_string(),
///     port: 10250,
///     debug_metrics_enabled: false,
///     stale_metric_ttl: Duration::from_secs(300),
/// };
///
/// tokio::spawn(start_metrics_server(opts));
/// ```
pub async fn start_metrics_server(opts: MetricsOptions) -> Result<(), MetricsError> {
    if !opts.enabled {
        info!(
            event.name = "metrics.disabled",
            "metrics server is disabled in configuration"
        );
        return Ok(());
    }

    let app = create_metrics_router(opts.debug_metrics_enabled);

    let bind_address = format!("{}:{}", opts.listen_address, opts.port);
    let listener = TcpListener::bind(&bind_address)
        .await
        .map_err(|e| MetricsError::bind_address(&bind_address, e))?;

    info!(
        event.name = "metrics.started",
        net.listen.address = %bind_address,
        debug_metrics_enabled = opts.debug_metrics_enabled,
        "metrics server started"
    );

    axum::serve(listener, app)
        .await
        .map_err(MetricsError::ServeError)?;

    Ok(())
}
