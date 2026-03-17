use std::{any::Any, borrow::Cow, sync::Arc, time::SystemTime};

use async_trait::async_trait;
use opentelemetry::{
    InstrumentationScope,
    trace::{SpanKind, TraceId, Tracer, TracerProvider},
};
use opentelemetry_sdk::{error::OTelSdkResult, trace::SdkTracerProvider};

use crate::metrics::{
    self,
    labels::{ExportStatus, ExporterName},
};

pub struct TraceExporterAdapter {
    provider: SdkTracerProvider,
    tracer: opentelemetry_sdk::trace::SdkTracer,
}

impl TraceExporterAdapter {
    pub fn new(provider: SdkTracerProvider) -> Self {
        let scope = InstrumentationScope::builder("mermin")
            .with_version(env!("CARGO_PKG_VERSION"))
            .build();
        let tracer = provider.tracer_with_scope(scope);
        Self { provider, tracer }
    }

    pub fn shutdown(&self) -> OTelSdkResult {
        self.provider.shutdown()
    }
}

pub type TraceableRecord = Arc<dyn Traceable + Send + Sync + 'static>;

/// Defines a common interface for data structures that can be represented as an
/// OpenTelemetry trace span.
pub trait Traceable {
    /// The logical start time of the event represented by this record.
    fn start_time(&self) -> SystemTime;

    /// The logical end time of the event represented by this record.
    fn end_time(&self) -> SystemTime;

    /// A specific name for the span, if applicable.
    fn name(&self) -> Option<Cow<'static, str>>;

    /// A custom trace ID for this span, if available.
    fn trace_id(&self) -> Option<TraceId>;

    /// The OpenTelemetry span kind for this record.
    fn span_kind(&self) -> SpanKind;

    /// Populates a pre-configured `Span` with the record's specific attributes.
    fn record(&self, span: opentelemetry_sdk::trace::Span) -> opentelemetry_sdk::trace::Span;
}

#[async_trait]
pub trait TraceableExporter: Send + Sync {
    async fn export(&self, traceable_record: TraceableRecord);

    fn as_any(&self) -> &dyn Any;
}

#[async_trait]
impl TraceableExporter for TraceExporterAdapter {
    async fn export(&self, traceable: TraceableRecord) {
        let tracer = &self.tracer;
        let name = traceable.name().unwrap_or(Cow::Borrowed("flow"));

        let mut builder = tracer
            .span_builder(name)
            .with_kind(traceable.span_kind())
            .with_start_time(traceable.start_time());
        if let Some(trace_id) = traceable.trace_id() {
            builder = builder.with_trace_id(trace_id);
        }
        let mut span = builder.start_with_context(tracer, &opentelemetry::Context::new());
        span = traceable.record(span);
        opentelemetry::trace::Span::end_with_timestamp(&mut span, traceable.end_time());
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
        metrics::registry::EXPORT_FLOW_SPANS_TOTAL
            .with_label_values(&[ExporterName::Noop.as_str(), ExportStatus::NoOp.as_str()])
            .inc();
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
