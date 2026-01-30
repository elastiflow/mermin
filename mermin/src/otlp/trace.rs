use std::{any::Any, sync::Arc, time::SystemTime};

use async_trait::async_trait;
use opentelemetry::trace::{
    SpanContext, SpanId, SpanKind, TraceContextExt, TraceFlags, TraceId, TraceState, Tracer,
    TracerProvider,
};
use opentelemetry_sdk::{
    error::OTelSdkResult,
    trace::{IdGenerator, SdkTracerProvider},
};
use tracing::trace;

use crate::metrics::{
    self,
    export::{ExportStatus, ExporterName},
};

pub struct TraceExporterAdapter {
    provider: SdkTracerProvider,
}

impl TraceExporterAdapter {
    pub fn new(provider: SdkTracerProvider) -> Self {
        Self { provider }
    }

    /// Explicitly shutdown the OpenTelemetry provider with a timeout
    pub fn shutdown(&self) -> OTelSdkResult {
        // The OpenTelemetry SDK provider has a shutdown method that should be called
        // to gracefully flush remaining spans and close connections
        self.provider.shutdown()
    }
}

pub type TraceableRecord = Arc<dyn Traceable + Send + Sync + 'static>;

/// Defines a common interface for data structures that can be represented as an
/// OpenTelemetry trace span.
pub trait Traceable {
    /// Returns the logical start time of the event represented by this record.
    ///
    /// This timestamp will be used as the `start_time_unix_nano` for the
    /// resulting OpenTelemetry `Span`.
    fn start_time(&self) -> SystemTime;

    /// Returns the logical end time of the event represented by this record.
    ///
    /// This timestamp will be used as the `end_time_unix_nano` for the
    /// resulting OpenTelemetry `Span`.
    fn end_time(&self) -> SystemTime;

    /// Returns a specific name for the span, if applicable.
    ///
    /// If `Some(String)` is returned, it will be used as the `Span` name. If `None` is
    /// returned, the exporter is expected to use a default or generic name.
    fn name(&self) -> Option<String>;

    /// Returns a custom trace ID for this span, if available.
    ///
    /// If `Some(TraceId)` is returned, it will be used as the trace ID for this span,
    /// enabling correlation of multiple spans under the same trace. If `None` is returned,
    /// OpenTelemetry will generate a new random trace ID.
    fn trace_id(&self) -> Option<TraceId>;

    /// Returns the OpenTelemetry span kind for this record.
    ///
    /// The span kind indicates the role of the span in the trace (e.g., Client, Server, Internal).
    /// For network flows, this is determined by direction inference based on listening ports,
    /// TCP handshake patterns, and port number heuristics.
    fn span_kind(&self) -> SpanKind;

    /// Populates a pre-configured `Span` with the record's specific attributes.
    ///
    /// This is the core method where the implementing type is responsible for mapping
    /// its internal fields to the key-value attributes of an OpenTelemetry `Span`.
    ///
    /// ### Arguments
    /// - `span` - An `opentelemetry_sdk::trace::Span` instance that has already been
    ///   configured with its start time, end time, and name based on the other
    ///   methods in this trait.
    ///
    /// ### Returns
    /// The same `Span` instance, now enriched with the record's specific attributes.
    ///
    /// ### Important
    /// For performance reasons within the export pipeline, this method is designed to
    /// be called **only once** per record. The implementation should be efficient and
    /// perform all necessary attribute-setting within this single call.
    fn record(&self, span: opentelemetry_sdk::trace::Span) -> opentelemetry_sdk::trace::Span;
}

#[async_trait]
pub trait TraceableExporter: Send + Sync {
    async fn export(&self, traceable_record: TraceableRecord);

    /// Allow downcasting to concrete types for shutdown operations
    fn as_any(&self) -> &dyn Any;
}

#[async_trait]
impl TraceableExporter for TraceExporterAdapter {
    async fn export(&self, traceable: TraceableRecord) {
        let tracer = self.provider.tracer("mermin");
        let name = if let Some(name) = traceable.name() {
            name
        } else {
            "flow".to_string()
        };

        let mut span = if let Some(custom_trace_id) = traceable.trace_id() {
            let span_id_bytes: [u8; 8] = opentelemetry_sdk::trace::RandomIdGenerator::default()
                .new_span_id()
                .to_bytes();
            let span_id = SpanId::from_bytes(span_id_bytes);

            let parent_span_context = SpanContext::new(
                custom_trace_id,
                span_id,
                TraceFlags::SAMPLED,
                true,
                TraceState::default(),
            );

            let parent_cx =
                opentelemetry::Context::current().with_remote_span_context(parent_span_context);

            tracer
                .span_builder(name.clone())
                .with_kind(traceable.span_kind())
                .with_start_time(traceable.start_time())
                .start_with_context(&tracer, &parent_cx)
        } else {
            tracer
                .span_builder(name.clone())
                .with_kind(traceable.span_kind())
                .with_start_time(traceable.start_time())
                .start(&tracer)
        };
        span = traceable.record(span);
        opentelemetry::trace::Span::end_with_timestamp(&mut span, traceable.end_time());

        trace!(
            event.name = "span.exported",
            span.name = %name,
            "exported traceable record as span"
        );
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Default)]
pub struct NoOpExporterAdapter {}

#[async_trait]
impl TraceableExporter for NoOpExporterAdapter {
    async fn export(&self, _traceable: TraceableRecord) {
        // Track as "noop" - span was processed but not exported (no exporter configured)
        metrics::registry::EXPORT_FLOW_SPANS_TOTAL
            .with_label_values(&[ExporterName::Noop.as_str(), ExportStatus::NoOp.as_str()])
            .inc();
        trace!(
            event.name = "span.export_skipped",
            reason = "no_op_exporter_configured",
            "skipping span export"
        );
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
