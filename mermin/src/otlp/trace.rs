use std::{sync::Arc, time::SystemTime};

use async_trait::async_trait;
use opentelemetry::trace::{SpanKind, Tracer, TracerProvider};
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::debug;

pub struct TraceExporterAdapter {
    provider: SdkTracerProvider,
}

impl TraceExporterAdapter {
    pub fn new(provider: SdkTracerProvider) -> Self {
        Self { provider }
    }
}

pub type TraceableRecord = Arc<dyn Traceable + Send + Sync + 'static>;

pub trait Traceable {
    fn start_time(&self) -> SystemTime;
    fn end_time(&self) -> SystemTime;
    fn name(&self) -> Option<String>;
    fn record(&self, span: opentelemetry_sdk::trace::Span) -> opentelemetry_sdk::trace::Span;
}

#[async_trait]
pub trait TraceableExporter: Send + Sync {
    async fn export(&self, traceable_record: TraceableRecord);
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

        let mut span = tracer
            .span_builder(name)
            //TODO: Once SOURCE & DESTINATION are span kind are available, use them here
            .with_kind(SpanKind::Internal)
            .with_start_time(traceable.start_time())
            .start(&tracer);
        span = traceable.record(span);
        opentelemetry::trace::Span::end_with_timestamp(&mut span, traceable.end_time());
    }
}

#[derive(Default)]
pub struct NoOpExporterAdapter {}

#[async_trait]
impl TraceableExporter for NoOpExporterAdapter {
    async fn export(&self, _traceable: TraceableRecord) {
        debug!("skipping export - no exporters available");
    }
}
