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

use axum::{
    Router,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::get,
};
use serde::{Deserialize, Serialize};
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

#[derive(Serialize, Deserialize)]
struct MetricSummary {
    name: String,
    #[serde(rename = "type")]
    r#type: String,
    description: String,
    labels: Vec<String>,
    category: String,
}

#[derive(Serialize, Deserialize)]
struct MetricsSummaryResponse {
    debug_metrics_enabled: bool,
    total_metrics: usize,
    standard_metrics: usize,
    debug_metrics: usize,
    metrics: Vec<MetricSummary>,
}

/// Handler for the `/metrics/summary` endpoint.
///
/// Returns a JSON summary of all available metrics with their metadata.
async fn metrics_summary_handler(debug_enabled: bool) -> impl IntoResponse {
    match tokio::task::spawn_blocking(move || {
        let mut standard_metrics = Vec::new();
        let mut debug_metrics = Vec::new();

        // Gather standard metrics
        let standard_families = registry::STANDARD_REGISTRY.gather();
        for family in standard_families {
            let metric_type = match family.get_field_type() {
                prometheus::proto::MetricType::COUNTER => "counter",
                prometheus::proto::MetricType::GAUGE => "gauge",
                prometheus::proto::MetricType::HISTOGRAM => "histogram",
                prometheus::proto::MetricType::SUMMARY => "summary",
                prometheus::proto::MetricType::UNTYPED => "untyped",
            };

            let labels: Vec<String> = family
                .get_metric()
                .first()
                .and_then(|m| {
                    if m.get_label().is_empty() {
                        None
                    } else {
                        Some(
                            m.get_label()
                                .iter()
                                .map(|l| l.get_name().to_string())
                                .collect(),
                        )
                    }
                })
                .unwrap_or_default();

            standard_metrics.push(MetricSummary {
                name: family.get_name().to_string(),
                r#type: metric_type.to_string(),
                description: family.get_help().to_string(),
                labels,
                category: "standard".to_string(),
            });
        }

        // Gather debug metrics if enabled
        if debug_enabled {
            let debug_families = registry::DEBUG_REGISTRY.gather();
            for family in debug_families {
                let metric_type = match family.get_field_type() {
                    prometheus::proto::MetricType::COUNTER => "counter",
                    prometheus::proto::MetricType::GAUGE => "gauge",
                    prometheus::proto::MetricType::HISTOGRAM => "histogram",
                    prometheus::proto::MetricType::SUMMARY => "summary",
                    prometheus::proto::MetricType::UNTYPED => "untyped",
                };

                let labels: Vec<String> = family
                    .get_metric()
                    .first()
                    .and_then(|m| {
                        if m.get_label().is_empty() {
                            None
                        } else {
                            Some(
                                m.get_label()
                                    .iter()
                                    .map(|l| l.get_name().to_string())
                                    .collect(),
                            )
                        }
                    })
                    .unwrap_or_default();

                debug_metrics.push(MetricSummary {
                    name: family.get_name().to_string(),
                    r#type: metric_type.to_string(),
                    description: family.get_help().to_string(),
                    labels,
                    category: "debug".to_string(),
                });
            }
        }

        let all_metrics: Vec<MetricSummary> = standard_metrics
            .into_iter()
            .chain(debug_metrics.into_iter())
            .collect();

        MetricsSummaryResponse {
            debug_metrics_enabled: debug_enabled,
            total_metrics: all_metrics.len(),
            standard_metrics: all_metrics
                .iter()
                .filter(|m| m.category == "standard")
                .count(),
            debug_metrics: all_metrics.iter().filter(|m| m.category == "debug").count(),
            metrics: all_metrics,
        }
    })
    .await
    {
        Ok(summary) => match serde_json::to_string_pretty(&summary) {
            Ok(json) => {
                let mut headers = HeaderMap::new();
                headers.insert(
                    axum::http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                (StatusCode::OK, headers, json)
            }
            Err(e) => {
                tracing::error!(
                    event.name = "metrics.summary.serialize_failed",
                    error.message = %e,
                    "failed to serialize metrics summary"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    HeaderMap::new(),
                    format!(r#"{{"error": "Failed to serialize metrics summary: {e}"}}"#),
                )
            }
        },
        Err(e) => {
            tracing::error!(
                event.name = "metrics.summary.gather_failed",
                error.message = %e,
                "metrics summary gathering task panicked"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                HeaderMap::new(),
                r#"{"error": "Failed to gather metrics summary"}"#.to_string(),
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
        .route(
            "/metrics/summary",
            get(move || metrics_summary_handler(debug_enabled)),
        )
        .layer(TraceLayer::new_for_http())
}

/// Start the Prometheus metrics HTTP server.
///
/// Serves metrics at:
/// - `<listen_address>:<port>/metrics` - All metrics (standard + debug if enabled)
/// - `<listen_address>:<port>/metrics/standard` - Standard metrics only (always available)
/// - `<listen_address>:<port>/metrics/debug` - Debug metrics only (404 if debug not enabled)
/// - `<listen_address>:<port>/metrics/summary` - JSON summary of all available metrics
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
