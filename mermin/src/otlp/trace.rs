pub mod lib {
    use anyhow::Result;
    use async_trait::async_trait;
    use opentelemetry::{
        KeyValue, global,
        trace::{Status, TracerProvider},
    };
    use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
    use opentelemetry_sdk::{
        Resource,
        propagation::TraceContextPropagator,
        runtime,
        trace::{SdkTracerProvider, span_processor_with_async_runtime::BatchSpanProcessor},
    };
    use tonic::transport::{Uri, channel::Channel};
    use tracing::{Span, debug, error, info};
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    use tracing_subscriber::{
        EnvFilter,
        fmt::{Layer, format::FmtSpan},
        layer::SubscriberExt,
        util::SubscriberInitExt,
    };

    use crate::{
        flow::{FlowAttributes, FlowAttributesExporter},
        otlp::opts::{ExporterOptions, ExporterProtocol},
    };

    pub struct TraceExporterAdapter {
        provider: SdkTracerProvider,
    }

    impl TraceExporterAdapter {
        pub fn new(provider: SdkTracerProvider) -> Self {
            Self { provider }
        }
    }

    pub trait Traceable {
        /// Required method: Defines how to create a span with the
        /// correct name and fields for this specific type.
        fn to_span(&self) -> Span;

        /// Provided method: Creates the span using `to_span` and executes
        /// the given closure within its context.
        fn record<F, T>(&self, f: F) -> T
        where
            F: FnOnce() -> T,
        {
            self.to_span().in_scope(f)
        }
    }

    #[async_trait]
    impl FlowAttributesExporter for TraceExporterAdapter {
        async fn export(&self, attrs: FlowAttributes) {
            attrs.record(|| {
                // Close the span with OK status after recording fields
                let span = Span::current();
                span.set_status(Status::Ok);
                debug!("Exported recordable in span");
            });
        }

        async fn shutdown(&self) -> Result<()> {
            self.provider.force_flush().map_err(|e| {
                error!("Error flushing OTLP trace exporter: {}", e);
                anyhow::anyhow!(e)
            })?;

            self.provider
                .shutdown()
                .map(|()| {
                    debug!("OTLP trace exporter shut down gracefully.");
                })
                .map_err(|e| {
                    error!("Error shutting down OTLP trace exporter: {}", e);
                    anyhow::anyhow!(e)
                })
        }
    }

    pub async fn init_tracer_provider(
        opts: ExporterOptions,
    ) -> Result<SdkTracerProvider, anyhow::Error> {
        let uri = Uri::from_static("http://host.docker.internal:4317");
        let channel = Channel::builder(uri).connect().await?;

        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic() // for gRPC
            .with_channel(channel)
            .with_protocol(ExporterProtocol::from(opts.protocol).into())
            .build()
            .expect("Failed to create OTLP span exporter.");

        let processor = BatchSpanProcessor::builder(exporter, runtime::Tokio).build();

        let provider = SdkTracerProvider::builder()
            .with_span_processor(processor)
            .with_resource(
                Resource::builder()
                    .with_attribute(KeyValue::new("service.name", "mermin"))
                    .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
                    .build(),
            )
            .build();

        global::set_tracer_provider(provider.clone());
        global::set_text_map_propagator(TraceContextPropagator::new());

        let filter = EnvFilter::from_default_env();

        let fmt_layer = Layer::new().with_span_events(FmtSpan::FULL);

        let trace_layer =
            tracing_opentelemetry::layer().with_tracer(provider.tracer("otlp-flow-tracer"));

        tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .with(trace_layer)
            .init();

        info!("Tracer initialized. Console logging and OTLP exporting are active.");
        Ok(provider)
    }
}
