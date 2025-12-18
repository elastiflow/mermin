use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use axum::{
    Router,
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::get,
};
use serde_json::json;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, warn};

use crate::{
    health::HealthError,
    metrics::{export::ExportStatus, registry},
    runtime::conf::ApiConf,
};

#[derive(Clone)]
pub struct HealthState {
    pub ebpf_loaded: Arc<AtomicBool>,
    pub k8s_caches_synced: Arc<AtomicBool>,
    pub ready_to_process: Arc<AtomicBool>,
    pub startup_complete: Arc<AtomicBool>,
}

impl Default for HealthState {
    fn default() -> Self {
        Self {
            ebpf_loaded: Arc::new(AtomicBool::new(false)),
            k8s_caches_synced: Arc::new(AtomicBool::new(false)),
            ready_to_process: Arc::new(AtomicBool::new(false)),
            startup_complete: Arc::new(AtomicBool::new(false)),
        }
    }
}

pub async fn liveness_handler(State(state): State<HealthState>) -> impl IntoResponse {
    let start = std::time::Instant::now();

    let ebpf_loaded = state.ebpf_loaded.load(Ordering::Relaxed);
    let startup_complete = state.startup_complete.load(Ordering::Relaxed);
    let ready_to_process = state.ready_to_process.load(Ordering::Relaxed);

    // Liveness is OK if eBPF is loaded OR if we haven't completed startup yet
    // This prevents killing the pod during initialization
    let is_alive = ebpf_loaded || !startup_complete;

    let status_code = if is_alive {
        StatusCode::OK
    } else {
        warn!(
            event.name = "health.liveness.failed",
            ebpf_loaded = %ebpf_loaded,
            startup_complete = %startup_complete,
            "liveness check failed"
        );
        StatusCode::SERVICE_UNAVAILABLE
    };

    let duration = start.elapsed();
    debug!(
        event.name = "health.liveness.checked",
        http.response.status_code = status_code.as_u16(),
        duration_us = duration.as_micros(),
        ebpf_loaded = ebpf_loaded,
        startup_complete = startup_complete,
        "liveness check completed"
    );

    // Sum export errors across all exporter types for health monitoring
    let export_errors_otlp = registry::EXPORT_FLOW_SPANS_TOTAL
        .with_label_values(&["otlp", ExportStatus::Error.as_ref()])
        .get();
    let export_errors_stdout = registry::EXPORT_FLOW_SPANS_TOTAL
        .with_label_values(&["stdout", ExportStatus::Error.as_ref()])
        .get();
    let total_export_errors = export_errors_otlp + export_errors_stdout;
    let pipeline_healthy = ebpf_loaded && ready_to_process;

    let body = Json(json!({
        "status": if is_alive { "ok" } else { "unavailable" },
        "checks": {
            "ebpf_loaded": ebpf_loaded,
            "startup_complete": startup_complete,
            "pipeline_healthy": pipeline_healthy
        },
        "metrics": {
            "export_errors_total": total_export_errors
        }
    }));

    (status_code, body)
}

pub async fn readiness_handler(State(state): State<HealthState>) -> impl IntoResponse {
    let ebpf_loaded = state.ebpf_loaded.load(Ordering::Relaxed);
    let k8s_caches_synced = state.k8s_caches_synced.load(Ordering::Relaxed);
    let ready_to_process = state.ready_to_process.load(Ordering::Relaxed);

    let is_ready = ebpf_loaded && k8s_caches_synced && ready_to_process;

    // Sum export errors across all exporter types for health monitoring
    let export_errors_otlp = registry::EXPORT_FLOW_SPANS_TOTAL
        .with_label_values(&["otlp", ExportStatus::Error.as_ref()])
        .get();
    let export_errors_stdout = registry::EXPORT_FLOW_SPANS_TOTAL
        .with_label_values(&["stdout", ExportStatus::Error.as_ref()])
        .get();
    let total_export_errors = export_errors_otlp + export_errors_stdout;
    let pipeline_healthy = ebpf_loaded && ready_to_process;

    let status_code = if is_ready {
        StatusCode::OK
    } else {
        warn!(
            event.name = "health.readiness.failed",
            ebpf_loaded = %ebpf_loaded,
            k8s_caches_synced = %k8s_caches_synced,
            ready_to_process = %ready_to_process,
            pipeline_healthy = %pipeline_healthy,
            export_errors_total = %total_export_errors,
            "readiness check failed"
        );
        StatusCode::SERVICE_UNAVAILABLE
    };

    let body = Json(json!({
        "status": if is_ready { "ok" } else { "unavailable" },
        "checks": {
            "ebpf_loaded": ebpf_loaded,
            "k8s_caches_synced": k8s_caches_synced,
            "ready_to_process": ready_to_process,
            "pipeline_healthy": pipeline_healthy
        },
        "metrics": {
            "export_errors_total": total_export_errors
        }
    }));

    (status_code, body)
}

pub async fn startup_handler(State(state): State<HealthState>) -> impl IntoResponse {
    let startup_complete = state.startup_complete.load(Ordering::Relaxed);
    let status_code = if startup_complete {
        StatusCode::OK
    } else {
        warn!(
            event.name = "health.startup.failed",
            startup_complete = %startup_complete,
            "startup check failed"
        );
        StatusCode::SERVICE_UNAVAILABLE
    };

    let body = Json(json!({
        "status": if startup_complete { "ok" } else { "unavailable" },
        "checks": {
            "startup_complete": startup_complete
        }
    }));

    (status_code, body)
}

async fn log_errors_middleware(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();

    let response = next.run(req).await;
    let status = response.status();

    // Log unexpected errors (not 503 SERVICE_UNAVAILABLE which is expected for health checks)
    if !status.is_success() && status != StatusCode::SERVICE_UNAVAILABLE {
        if status.is_client_error() {
            warn!(
                event.name = "health.request.client_error",
                http.request.method = %method,
                url.path = %uri.path(),
                http.response.status_code = %status.as_u16(),
                "health check request returned unexpected client error"
            );
        } else if status.is_server_error() {
            error!(
                event.name = "health.request.server_error",
                http.request.method = %method,
                url.path = %uri.path(),
                http.response.status_code = %status.as_u16(),
                "health check request returned unexpected server error"
            );
        }
    }

    response
}

pub fn create_health_router(state: HealthState) -> Router {
    Router::new()
        .route("/livez", get(liveness_handler))
        .route("/readyz", get(readiness_handler))
        .route("/startup", get(startup_handler))
        .layer(middleware::from_fn(log_errors_middleware))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

pub async fn start_api_server(state: HealthState, config: &ApiConf) -> Result<(), HealthError> {
    let app = create_health_router(state);

    let bind_address = format!("{}:{}", config.listen_address, config.port);
    let listener = TcpListener::bind(&bind_address)
        .await
        .map_err(|e| HealthError::bind_address(&bind_address, e))?;

    info!(
        event.name = "api.started",
        net.listen.address = %bind_address,
        "api server has started"
    );
    axum::serve(listener, app)
        .await
        .map_err(HealthError::ServeError)?;
    Ok(())
}
