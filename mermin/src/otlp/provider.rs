use axum::http::Uri;
use log::{debug, error};
use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::{
    Resource,
    propagation::TraceContextPropagator,
    runtime,
    trace::{SdkTracerProvider, span_processor_with_async_runtime::BatchSpanProcessor},
};
use tonic::transport::{Channel, channel::ClientTlsConfig};
use tracing::{Level, info, level_filters::LevelFilter, warn};
use tracing_subscriber::{
    fmt::{Layer, format::FmtSpan},
    prelude::__tracing_subscriber_SubscriberExt,
    util::SubscriberInitExt,
};

use crate::{
    otlp::opts::{OtlpExporterOptions, StdoutFmt},
    runtime::opts::SpanFmt,
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

    pub async fn with_otlp_exporter(self, options: OtlpExporterOptions) -> ProviderBuilder {
        debug!("creating otlp exporter with options: {options:?}");
        let uri: Uri = options.endpoint.clone().parse().unwrap_or_else(|e| {
            info!("failed to parse OTLP endpoint URL: {}", e);
            Uri::default()
        });

        // TODO: Apply TLS configuration - ENG-120
        // This should handle TLS settings from config.tls
        let tls_config: Option<ClientTlsConfig> = match &options.tls {
            Some(_tls_opts) => None,
            _ => None,
        };

        let mut channel = Channel::builder(uri);
        if let Some(tls) = tls_config {
            debug!("tls configuration detected for otlp exporter");
            let res = channel.tls_config(tls);
            if res.is_err() {
                warn!("failed to apply tls configuration: {}", res.err().unwrap());
                return self;
            }
            channel = res.unwrap();
        };

        let builder = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic() // for gRPC
            .with_channel(channel.connect_lazy())
            .with_protocol(opentelemetry_otlp::Protocol::Grpc);

        if let Some(auth_config) = &options.auth {
            match auth_config.generate_auth_headers() {
                Ok(auth_headers) => {
                    info!("applied authentication headers to otlp exporter");
                    // TODO: Apply headers to the exporter builder - ENG-120
                    // Note: The opentelemetry_otlp crate may need to be updated to support custom headers
                    // For now, this is a placeholder for where header configuration would go
                    debug!(
                        "headers configured for otlp exporter ({} headers)",
                        auth_headers.len()
                    );
                }
                Err(e) => {
                    warn!("failed to generate authentication headers: {}", e);
                    return self;
                }
            }
        }

        match builder.build() {
            Ok(exporter) => {
                debug!("otlp exporter built successfully");

                // SAFETY: Setting environment variables before BatchSpanProcessor initialization.
                // The OpenTelemetry SDK reads these values during processor construction.
                unsafe {
                    std::env::set_var(
                        "OTEL_BSP_MAX_EXPORT_BATCH_SIZE",
                        options.max_batch_size.to_string(),
                    );
                    std::env::set_var(
                        "OTEL_BSP_SCHEDULE_DELAY",
                        options.max_batch_interval.as_millis().to_string(),
                    );
                }

                debug!(
                    "batch config applied: max_batch_size={}, max_batch_interval={:?}",
                    options.max_batch_size, options.max_batch_interval
                );

                let processor = BatchSpanProcessor::builder(exporter, runtime::Tokio).build();
                ProviderBuilder {
                    sdk_builder: self.sdk_builder.with_span_processor(processor),
                }
            }
            Err(e) => {
                error!("failed to build OTLP exporter: {e}");
                self
            }
        }
    }

    pub fn with_stdout_exporter(
        self,
        max_batch_size: usize,
        max_batch_interval: std::time::Duration,
    ) -> ProviderBuilder {
        let exporter = opentelemetry_stdout::SpanExporter::default();

        // SAFETY: Setting environment variables before BatchSpanProcessor initialization.
        // The OpenTelemetry SDK reads these values during processor construction.
        unsafe {
            std::env::set_var("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", max_batch_size.to_string());
            std::env::set_var(
                "OTEL_BSP_SCHEDULE_DELAY",
                max_batch_interval.as_millis().to_string(),
            );
        }

        debug!(
            "batch config applied: max_batch_size={max_batch_size}, max_batch_interval={max_batch_interval:?}"
        );

        let processor = BatchSpanProcessor::builder(exporter, runtime::Tokio).build();
        ProviderBuilder {
            sdk_builder: self.sdk_builder.with_span_processor(processor),
        }
    }

    pub fn build(self) -> SdkTracerProvider {
        self.sdk_builder.build()
    }
}

pub async fn init_provider(
    stdout: Option<StdoutFmt>,
    otlp: Option<OtlpExporterOptions>,
) -> SdkTracerProvider {
    let mut provider = ProviderBuilder::new();

    if stdout.is_none() && otlp.is_none() {
        warn!("no exporters configured");
        return provider.build();
    }

    let (batch_size, batch_interval) = if let Some(ref opts) = otlp {
        (opts.max_batch_size, opts.max_batch_interval)
    } else {
        (512, std::time::Duration::from_secs(5))
    };

    if let Some(otlp_opts) = otlp {
        provider = provider.with_otlp_exporter(otlp_opts.clone()).await;
    }

    if stdout.is_some() {
        provider = provider.with_stdout_exporter(batch_size, batch_interval);
    }

    provider.build()
}

pub async fn init_internal_tracing(
    log_level: Level,
    span_fmt: SpanFmt,
    stdout: Option<StdoutFmt>,
    otlp: Option<OtlpExporterOptions>,
) -> Result<(), anyhow::Error> {
    let provider = init_provider(stdout, otlp).await;
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
