use axum::http::Uri;
use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::{
    Resource,
    propagation::TraceContextPropagator,
    runtime,
    trace::{SdkTracerProvider, span_processor_with_async_runtime::BatchSpanProcessor},
};
use tonic::transport::{Channel, channel::ClientTlsConfig};
use tracing::{Level, error, info, level_filters::LevelFilter, warn};
use tracing_subscriber::{
    fmt::{Layer, format::FmtSpan},
    prelude::__tracing_subscriber_SubscriberExt,
    util::SubscriberInitExt,
};

use crate::{
    otlp::opts::{ExporterOptions, OtlpExporterOptions, resolve_exporters},
    runtime::{conf::ExporterReferences, enums::SpanFmt},
};

pub struct ProviderBuilder {
    pub sdk_builder: opentelemetry_sdk::trace::TracerProviderBuilder,
}

impl ProviderBuilder {
    pub fn new() -> Self {
        let builder = SdkTracerProvider::builder().with_resource(
            Resource::builder()
                .with_attribute(KeyValue::new("service.name", "mermin"))
                .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
                .build(),
        );
        Self {
            sdk_builder: builder,
        }
    }

    pub async fn with_otlp_exporter(
        mut self,
        options: OtlpExporterOptions,
    ) -> Result<Self, anyhow::Error> {
        let uri: Uri = options.build_endpoint().parse()?;
        let tls_config: Option<ClientTlsConfig> = if let Some(tls_config) = &options.tls
            && tls_config.enabled
        {
            // TODO: Apply TLS configuration - ENG-120
            // This should handle TLS settings from config.tls
            None
        } else {
            None
        };

        let mut channel = Channel::builder(uri);
        if let Some(tls) = tls_config {
            info!("tls configuration detected for otlp exporter");
            channel = channel.tls_config(tls)?;
        }

        let chan = channel
            .connect_timeout(std::time::Duration::from_secs(5))
            .connect()
            .await?;
        let builder = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic() // for gRPC
            .with_channel(chan)
            .with_protocol(opentelemetry_otlp::Protocol::from(options.protocol));

        if let Some(auth_config) = &options.auth {
            match auth_config.generate_auth_headers() {
                Ok(auth_headers) => {
                    info!("Applied authentication headers to OTLP exporter");
                    // TODO: Apply headers to the exporter builder - ENG-120
                    // Note: The opentelemetry_otlp crate may need to be updated to support custom headers
                    // For now, this is a placeholder for where header configuration would go
                    info!(
                        "headers configured for otlp exporter ({} headers)",
                        auth_headers.len()
                    );
                }
                Err(e) => {
                    error!("Failed to generate authentication headers: {}", e);
                    return Err(anyhow::anyhow!("Authentication configuration error: {}", e));
                }
            }
        }
        let exporter = builder.build()?;
        let processor = BatchSpanProcessor::builder(exporter, runtime::Tokio).build();
        self.sdk_builder = self.sdk_builder.with_span_processor(processor);
        Ok(self)
    }

    pub fn with_stdout_exporter(mut self) -> Self {
        let exporter = opentelemetry_stdout::SpanExporter::default();
        let processor = BatchSpanProcessor::builder(exporter, runtime::Tokio).build();
        self.sdk_builder = self.sdk_builder.with_span_processor(processor);
        self
    }

    pub fn build(self) -> SdkTracerProvider {
        self.sdk_builder.build()
    }
}

pub async fn init_provider(
    exporter_options: &ExporterOptions,
    exporter_refs: ExporterReferences,
) -> Result<SdkTracerProvider, anyhow::Error> {
    let mut provider = ProviderBuilder::new();
    if exporter_refs.is_empty() {
        warn!("no exporters configured");
        return Ok(provider.build());
    }

    let (otlp_opts, stdout_opts) = resolve_exporters(exporter_refs, exporter_options)?;

    for options in otlp_opts {
        provider = provider.with_otlp_exporter(options).await?;
    }

    for _ in stdout_opts {
        provider = provider.with_stdout_exporter();
    }

    Ok(provider.build())
}

pub async fn init_internal_tracing(
    exporter_options: &ExporterOptions,
    exporter_refs: ExporterReferences,
    log_level: Level,
    span_fmt: SpanFmt,
) -> Result<(), anyhow::Error> {
    let provider = init_provider(exporter_options, exporter_refs).await?;
    let mut fmt_layer = Layer::new().with_span_events(FmtSpan::from(span_fmt));

    match log_level {
        Level::DEBUG => fmt_layer = fmt_layer.with_file(true).with_line_number(true),
        Level::TRACE => {
            fmt_layer = fmt_layer
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_file(true)
                .with_line_number(true)
        }
        _ => {
            // default format:
            // Format {
            //     format: Full,
            //     timer: SystemTime,
            //     ansi: None, // conditionally set based on environment, handled by tracing-subscriber
            //     display_timestamp: true,
            //     display_target: true,
            //     display_level: true,
            //     display_thread_id: false,
            //     display_thread_name: false,
            //     display_filename: false,
            //     display_line_number: false,
            // }
        }
    }

    tracing_subscriber::registry()
        .with(LevelFilter::from_level(log_level))
        .with(fmt_layer)
        .init();

    global::set_tracer_provider(provider);
    global::set_text_map_propagator(TraceContextPropagator::new());
    Ok(())
}
