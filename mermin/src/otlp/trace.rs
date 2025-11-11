use std::{sync::Arc, time::SystemTime};

use async_trait::async_trait;
use opentelemetry::trace::{SpanKind, Tracer, TracerProvider};
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::trace;

use crate::metrics::export::{inc_spans_exported, observe_export_latency};

pub struct TraceExporterAdapter {
    provider: SdkTracerProvider,
}

impl TraceExporterAdapter {
    pub fn new(provider: SdkTracerProvider) -> Self {
        Self { provider }
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
}

#[async_trait]
impl TraceableExporter for TraceExporterAdapter {
    async fn export(&self, traceable: TraceableRecord) {
        let start = std::time::Instant::now();

        let tracer = self.provider.tracer("mermin");
        let name = if let Some(name) = traceable.name() {
            name
        } else {
            "flow".to_string()
        };

        let mut span = tracer
            .span_builder(name.clone())
            // TODO: Once SOURCE & DESTINATION are span kind are available, use them here
            .with_kind(SpanKind::Internal)
            .with_start_time(traceable.start_time())
            .start(&tracer);
        span = traceable.record(span);
        opentelemetry::trace::Span::end_with_timestamp(&mut span, traceable.end_time());

        // Metrics: Span exported successfully
        inc_spans_exported(1);
        observe_export_latency(start.elapsed());

        trace!(
            event.name = "span.exported",
            span.name = %name,
            "exported traceable record as span"
        );
    }
}

#[derive(Default)]
pub struct NoOpExporterAdapter {}

#[async_trait]
impl TraceableExporter for NoOpExporterAdapter {
    async fn export(&self, _traceable: TraceableRecord) {
        trace!(
            event.name = "span.export_skipped",
            reason = "no_op_exporter_configured",
            "skipping span export"
        );
    }
}
