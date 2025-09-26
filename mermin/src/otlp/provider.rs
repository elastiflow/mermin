use crate::otlp::opts::{ExporterOptions, ExporterProtocol, OtlpExporterOptions};
use axum::http::Uri;
use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::{
    Resource,
    propagation::TraceContextPropagator,
    runtime,
    trace::{SdkTracerProvider, span_processor_with_async_runtime::BatchSpanProcessor},
};
use opentelemetry_stdout::SpanExporter;
use tonic::transport::{Certificate, Channel, channel::ClientTlsConfig};
use tracing::{Level, level_filters::LevelFilter};
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use tracing_subscriber::{
    fmt::{Layer, format::FmtSpan},
    util::SubscriberInitExt,
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
        let uri: Uri = options.address.parse()?;
        let mut tls_config: Option<ClientTlsConfig> = None;
        if let Some(tls_opts) = options.tls
            && tls_opts.enabled
        {
            let mut config = ClientTlsConfig::new().domain_name(options.address.to_string());
            if let Some(ca_cert) = tls_opts.ca_cert {
                let ca_certificate = Certificate::from_pem(ca_cert.into_bytes());
                config = config.ca_certificate(ca_certificate)
            }
            tls_config = Some(config);
        }

        let mut channel = Channel::builder(uri);
        if let Some(tls) = tls_config {
            channel = channel.tls_config(tls)?;
        }

        let chan = channel
            .connect_timeout(std::time::Duration::from_secs(5))
            .connect()
            .await?;
        let builder = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic() // for gRPC
            .with_channel(chan)
            .with_protocol(ExporterProtocol::from(options.protocol).into());

        let exporter = builder.build()?;
        let processor = BatchSpanProcessor::builder(exporter, runtime::Tokio).build();
        self.sdk_builder = self.sdk_builder.with_span_processor(processor);
        Ok(self)
    }

    pub fn with_stdout_exporter(mut self) -> Self {
        let exporter = SpanExporter::default();
        let processor = BatchSpanProcessor::builder(exporter, runtime::Tokio).build();
        self.sdk_builder = self.sdk_builder.with_span_processor(processor);
        self
    }

    pub fn build(self) -> SdkTracerProvider {
        let provider = self.sdk_builder.build();
        provider
    }
}

pub async fn init_mermin_provider(
    otlp_exporter_options: ExporterOptions,
) -> Result<SdkTracerProvider, anyhow::Error> {
    let mut provider = ProviderBuilder::new();

    if let Some(otlp_opts) = otlp_exporter_options.otlp {
        for options in otlp_opts {
            provider = provider.with_otlp_exporter(options.1).await?;
        }
    }

    if let Some(stdout_opts) = otlp_exporter_options.stdout {
        for _ in stdout_opts {
            provider = provider.with_stdout_exporter();
        }
    }

    Ok(provider.build())
}

pub fn init_internal_tracing(log_level: Level) -> anyhow::Result<()> {
    let provider = ProviderBuilder::new().with_stdout_exporter().build();
    let fmt_layer = Layer::new().with_span_events(FmtSpan::FULL);
    tracing_subscriber::registry()
        .with(LevelFilter::from_level(log_level))
        .with(fmt_layer)
        .init();

    global::set_tracer_provider(provider);
    global::set_text_map_propagator(TraceContextPropagator::new());
    Ok(())
}
