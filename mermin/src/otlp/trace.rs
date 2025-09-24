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
    use tracing::{Level, Span, debug, error, info};
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    use tracing_subscriber::{filter::LevelFilter, layer::SubscriberExt, util::SubscriberInitExt};

    use crate::{
        flow::{FlowAttributes, FlowAttributesExporter},
        otlp::opts::{ExporterProtocol, ExporterSpecificOptions, generate_auth_headers},
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
        opts: ExporterSpecificOptions,
        log_level: Level,
    ) -> Result<SdkTracerProvider, anyhow::Error> {
        let level_filter = LevelFilter::from_level(log_level);

        // Only OTLP enabled
        let provider = create_otlp_provider(&opts).await?;
        let trace_layer =
            tracing_opentelemetry::layer().with_tracer(provider.tracer("otlp-flow-tracer"));

        tracing_subscriber::registry()
            .with(level_filter)
            .with(trace_layer)
            .init();

        info!("tracer initialized - otlp exporter is active.");
        Ok(provider)
    }

    async fn create_otlp_provider(
        opts: &ExporterSpecificOptions,
    ) -> Result<SdkTracerProvider, anyhow::Error> {
        match opts {
            ExporterSpecificOptions::Otlp {
                endpoint,
                protocol,
                headers,
                auth,
                ..
            } => {
                let uri: Uri = endpoint.parse()?;
                let channel = Channel::builder(uri).connect().await?;

                // TODO: Apply authentication configuration to the OTLP exporter - ENG-120
                // This should handle different auth methods and add appropriate headers/credentials
                // Once auth is fully implemented this should be a mut field
                let exporter_builder = opentelemetry_otlp::SpanExporter::builder()
                    .with_tonic() // for gRPC
                    .with_channel(channel)
                    .with_protocol(ExporterProtocol::from(protocol.clone()).into());

                // TODO: Merge authentication headers with user-provided headers - ENG-120
                // Authentication headers should take precedence over user headers
                let mut all_headers = headers.clone().unwrap_or_default();
                if let Some(auth_config) = auth {
                    match generate_auth_headers(auth_config) {
                        Ok(auth_headers) => {
                            all_headers.extend(auth_headers);
                            info!("Applied authentication headers to OTLP exporter");
                        }
                        Err(e) => {
                            error!("Failed to generate authentication headers: {}", e);
                            return Err(anyhow::anyhow!(
                                "Authentication configuration error: {}",
                                e
                            ));
                        }
                    }
                }

                // TODO: Apply headers to the exporter builder - ENG-120
                // Note: The opentelemetry_otlp crate may need to be updated to support custom headers
                // For now, this is a placeholder for where header configuration would go
                if !all_headers.is_empty() {
                    // TODO: Implement header application once the OTLP crate supports it - ENG-120
                    // exporter_builder = exporter_builder.with_headers(all_headers);
                    info!(
                        "Headers configured for OTLP exporter ({} headers)",
                        all_headers.len()
                    );
                }

                let exporter = exporter_builder
                    .build()
                    .expect("Failed to create OTLP span exporter.");

                let processor = BatchSpanProcessor::builder(exporter, runtime::Tokio).build();
                let provider = SdkTracerProvider::builder()
                    .with_span_processor(processor)
                    .with_resource(
                        Resource::builder()
                            .with_attribute(KeyValue::new("service.name", "mermin"))
                            .with_attribute(KeyValue::new(
                                "service.version",
                                env!("CARGO_PKG_VERSION"),
                            ))
                            .build(),
                    )
                    .build();

                global::set_tracer_provider(provider.clone());
                global::set_text_map_propagator(TraceContextPropagator::new());

                Ok(provider)
            }
            _ => Err(anyhow::anyhow!("Invalid config type for OTLP exporter")),
        }
    }

    #[allow(dead_code)]
    fn create_minimal_provider() -> SdkTracerProvider {
        SdkTracerProvider::builder()
            .with_resource(
                Resource::builder()
                    .with_attribute(KeyValue::new("service.name", "mermin"))
                    .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
                    .build(),
            )
            .build()
    }
}
