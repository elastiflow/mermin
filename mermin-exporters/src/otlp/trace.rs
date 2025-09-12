use std::sync::Arc;
use opentelemetry::trace::{Span, SpanKind, Status, Tracer, TracerProvider};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{BatchSpanProcessor, SdkTracerProvider};
use std::time::Duration;
use async_trait::async_trait;
use opentelemetry::global;
use mermincore::{
    ports::FlowExporterPort,
    k8s::resource_parser::EnrichedFlowData,
};
use anyhow::Result;


pub fn init_tracer_provider(svc_name: &str) -> SdkTracerProvider {
    // 1. Create the OTLP exporter
    // This uses a builder pattern to configure the gRPC endpoint.
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint("http://localhost:4317") // Default OTel Collector endpoint
        .with_timeout(Duration::from_secs(5))
        .build()
        .expect("Failed to create OTLP span exporter.");

    // 2. Create a batch span processor.
    // This collects spans and sends them in batches for better performance.
    let processor = BatchSpanProcessor::builder(exporter).build();

    // 3. Create the tracer provider.
    let provider = SdkTracerProvider::builder()
        .with_span_processor(processor)
        .build();

    // Set the global tracer provider and propagator
    global::set_tracer_provider(provider.clone());
    global::set_text_map_propagator(TraceContextPropagator::new());

    provider
}

/// Creates and works with a simple span.
fn test_span() {
    // Get a tracer from the global provider.
    let tracer = global::tracer("flow_exporter_service");

    // Start a new span.
    let mut span = tracer
        .span_builder("mock_flow_exporter_span")
        .with_kind(SpanKind::Internal)
        .start(&tracer);

    // Simulate doing some work.
    span.add_event("Doing some work...", vec![]);
    std::thread::sleep(Duration::from_millis(50));
    span.add_event("Work complete!", vec![]);

    // Set the status of the span.
    span.set_status(Status::Ok);

    // Manually end the span.
    // When the span variable is dropped, `end` is called automatically.
    // Calling it explicitly is fine and gives clear control.
    span.end();
}


// This is the OTLP Adapter.
pub struct TraceExporterAdapter {
    tracer: opentelemetry::global::BoxedTracer,
}

impl TraceExporterAdapter {
    pub fn new() -> Self {
        let tracer = global::tracer("flow-tracer");
        Self { tracer }
    }
}

// Here, the adapter implements the port.
#[async_trait]
impl FlowExporterPort for TraceExporterAdapter {
    #[tracing::instrument(
        name = "network.flow",
        skip(self, packet),
        fields(net.flow.community.id = %packet.id)
    )]
    fn export_flow(&self, packet: Result<EnrichedFlowData>) {
        if packet.is_ok() {
            let data = packet.expect("expected enriched flow data");
            let span = tracing::Span::current();
            span.record("netlfow.community", data.id.as_str());
            // TODO::Map Flows to Spans
            tracing::info!("Flow exported to OTLP");
        }

    }
}
