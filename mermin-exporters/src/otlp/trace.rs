#[cfg(feature = "otlp")]
pub mod lib {
    use async_trait::async_trait;
    use anyhow::Result;
    use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
    use opentelemetry_sdk::propagation::TraceContextPropagator;
    use opentelemetry_sdk::trace::{ SdkTracerProvider};
    use opentelemetry::global;
    use opentelemetry::trace::{FutureExt, Status, TracerProvider};
    use opentelemetry_sdk::runtime;
    use tracing::{debug, error, info, Span};
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::fmt::format::FmtSpan;
    use tracing_subscriber::fmt::Layer;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use mermincore::flow::base::EnrichedFlowData;
    use mermincore::flow::exporter::FlowExporter;
    use crate::otlp::opts::{ExporterOptions, ExporterProtocol};
    use opentelemetry_sdk::trace::span_processor_with_async_runtime::BatchSpanProcessor;
    use tonic::transport::channel::Channel;
    use tonic::transport::Uri;

    pub struct TraceExporterAdapter {
        provider: SdkTracerProvider,
    }

    impl TraceExporterAdapter {
        pub fn new(provider: SdkTracerProvider) -> Self {
            Self {
                provider
            }
        }
    }

    pub trait Recordable {
        fn record(&self, span: &Span);
    }

    #[async_trait]
    impl FlowExporter for TraceExporterAdapter {
        #[tracing::instrument(
            name = "net.flow",
            skip(self, flow),
            fields(
                community.id = tracing::field::Empty,
                error.message = tracing::field::Empty,
            )
        )]
        async fn export_flow(&self, flow: Result<EnrichedFlowData>) {
            let span = Span::current();
            match flow {
                Ok(data) => {
                    data.record(&span);
                    span.set_status(Status::Ok);
                    debug!("exported recordable: {:?}", data);
                }
                Err(e) => {
                    error!("error exporting recordable: {}", e);
                    span.set_status(
                        Status::error(
                            format!("error_message: {}", e.to_string()),
                        ),
                    );
                }
            }
        }

        async fn shutdown(&self) -> Result<()> {
            self.provider.force_flush().map_err(|e| {
                error!("Error flushing OTLP trace exporter: {}", e);
                anyhow::anyhow!(e)
            })?;
            self.provider.shutdown().map(
                |()| {
                    debug!("OTLP trace exporter shut down gracefully.");
                },
            ).map_err(|e| {
                error!("Error shutting down OTLP trace exporter: {}", e);
                anyhow::anyhow!(e)
            })
        }
    }

    #[macro_export]
    macro_rules! record_fields {
    // Base case: All tokens have been processed, do nothing.
    ($span:expr) => {};

    // Rule for a simple field: `self.field`
    // Matches the field, records it, and recurses on the rest.
    ($span:expr, $owner:ident.$field:ident $(, $($rest:tt)*)?) => {
        $span.record(stringify!($field), &$owner.$field);
        $crate::record_fields!($span $(, $($rest)*)?);
    };

    // Rule for an optional field: `optional self.field`
    ($span:expr, optional $owner:ident.$field:ident $(, $($rest:tt)*)?) => {
        if let Some(value) = &$owner.$field {
            $span.record(stringify!($field), &value);
        }
        $crate::record_fields!($span $(, $($rest)*)?);
    };

    // Rule for a field with a custom name: `("name" => value)`
    ($span:expr, ($name:literal => $value:expr) $(, $($rest:tt)*)?) => {
        $span.record($name, &$value);
        $crate::record_fields!($span $(, $($rest)*)?);
    };
}

    impl Recordable for EnrichedFlowData {
        fn record(&self, span: &Span) {
            record_fields!(
                span,
                ("community.id" => self.id.as_str())
            );
        }
    }

    pub async fn init_tracer_provider(opts: ExporterOptions) -> Result<SdkTracerProvider, tonic::transport::Error>{
        let uri = Uri::from_static(opts.endpoint);
        let channel = Channel::builder(uri)
            .connect().await?;

        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic() // for gRPC
            .with_channel(channel)
            .with_protocol(ExporterProtocol::from(opts.protocol).into())
            .build()
            .expect("Failed to create OTLP span exporter.");

        let processor = BatchSpanProcessor::builder(exporter, runtime::Tokio)
            .build();

        let provider = SdkTracerProvider::builder()
            .with_span_processor(processor)
            .build();

        global::set_tracer_provider(provider.clone());
        global::set_text_map_propagator(TraceContextPropagator::new());

        let filter = EnvFilter::from_default_env();

        let fmt_layer = Layer::new()
            .with_span_events(FmtSpan::FULL);

        let trace_layer = tracing_opentelemetry::layer()
            .with_tracer(provider.tracer("otlp-flow-tracer"));

        tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .with(trace_layer)
            .init();

        info!("Tracer initialized. Console logging and OTLP exporting are active.");
        Ok(provider)
    }
}
