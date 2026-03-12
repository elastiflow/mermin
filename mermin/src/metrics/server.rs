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
//! metrics::registry::init_registry()?;
//!
//! // Start metrics HTTP server
//! let metrics_handle = tokio::spawn(metrics::start_metrics_server(config.metrics));
//!
//! // Instrument code
//! metrics::registry::FLOWS_CREATED.with_label_values(&["eth0"]).inc();
//! ```

use std::io;

use axum::{
    Router,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::get,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

use crate::metrics::{self, ebpf::update_ringbuf_size_metric, opts::MetricsOptions};

#[derive(Debug, Error)]
pub enum MetricsError {
    #[error("failed to bind metrics server to {address}: {source}")]
    BindAddress {
        address: String,
        #[source]
        source: io::Error,
    },

    #[error("metrics server error: {0}")]
    ServeError(#[from] io::Error),

    #[error("prometheus registry error: {0}")]
    PrometheusError(#[from] prometheus::Error),
}

impl MetricsError {
    pub fn bind_address(address: impl Into<String>, source: io::Error) -> Self {
        Self::BindAddress {
            address: address.into(),
            source,
        }
    }
}

async fn metrics_handler() -> impl IntoResponse {
    match tokio::task::spawn_blocking(|| {
        update_ringbuf_size_metric();

        let encoder = prometheus::TextEncoder::new();
        let metric_families = metrics::registry::REGISTRY.gather();
        encoder.encode_to_string(&metric_families)
    })
    .await
    {
        Ok(Ok(body)) => (StatusCode::OK, body),
        Ok(Err(e)) => {
            error!(
                event.name = "metrics.server.encode_failed",
                error.message = %e,
                "failed to encode metrics"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to encode metrics: {e}"),
            )
        }
        Err(e) => {
            error!(
                event.name = "metrics.server.gather_failed",
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

async fn standard_metrics_handler() -> impl IntoResponse {
    match tokio::task::spawn_blocking(|| {
        update_ringbuf_size_metric();

        let encoder = prometheus::TextEncoder::new();
        let metric_families = metrics::registry::STANDARD_REGISTRY.gather();
        encoder.encode_to_string(&metric_families)
    })
    .await
    {
        Ok(Ok(body)) => (StatusCode::OK, body),
        Ok(Err(e)) => {
            error!(
                event.name = "metrics.server.standard.encode_failed",
                error.message = %e,
                "failed to encode standard metrics"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to encode standard metrics: {e}"),
            )
        }
        Err(e) => {
            error!(
                event.name = "metrics.server.standard.gather_failed",
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
        let metric_families = metrics::registry::DEBUG_REGISTRY.gather();
        encoder.encode_to_string(&metric_families)
    })
    .await
    {
        Ok(Ok(body)) => (StatusCode::OK, body),
        Ok(Err(e)) => {
            error!(
                event.name = "metrics.server.debug.encode_failed",
                error.message = %e,
                "failed to encode debug metrics"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to encode debug metrics: {e}"),
            )
        }
        Err(e) => {
            error!(
                event.name = "metrics.server.debug.gather_failed",
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

async fn metrics_summary_handler(debug_enabled: bool) -> impl IntoResponse {
    match tokio::task::spawn_blocking(move || {
        let mut standard_metrics = Vec::new();
        let mut debug_metrics = Vec::new();

        let standard_families = metrics::registry::STANDARD_REGISTRY.gather();
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
                        return None;
                    }
                    Some(
                        m.get_label()
                            .iter()
                            .map(|l| l.get_name().to_string())
                            .collect(),
                    )
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

        if debug_enabled {
            let debug_families = metrics::registry::DEBUG_REGISTRY.gather();
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
                error!(
                    event.name = "metrics.server.summary.serialize_failed",
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
            error!(
                event.name = "metrics.server.summary.gather_failed",
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

fn create_metrics_router(debug_enabled: bool) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/metrics/standard", get(standard_metrics_handler))
        .route(
            "/metrics/debug",
            get(move || debug_metrics_handler(debug_enabled)),
        )
        .route(
            "/metrics:summary",
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
/// - `<listen_address>:<port>/metrics:summary` - JSON summary of all available metrics
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
            event.name = "metrics.server.disabled",
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
        event.name = "metrics.server.started",
        net.listen.address = %bind_address,
        debug_metrics_enabled = opts.debug_metrics_enabled,
        "metrics server started"
    );

    axum::serve(listener, app)
        .await
        .map_err(MetricsError::ServeError)?;

    Ok(())
}
