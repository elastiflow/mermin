use std::{collections::HashMap, fmt::Debug, fs, str::FromStr, sync::Arc};

use figment::{
    Figment,
    providers::{Format, Serialized},
};
use http::{HeaderMap, HeaderName, HeaderValue, Uri};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig, WithTonicConfig};
use opentelemetry_sdk::{
    Resource,
    propagation::TraceContextPropagator,
    runtime,
    trace::{
        BatchConfigBuilder, SdkTracerProvider,
        span_processor_with_async_runtime::BatchSpanProcessor,
    },
};
use reqwest;
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
};
use rustls_pemfile::{certs, private_key};
use serde::{Deserialize, Serialize};
use tonic::{metadata::MetadataMap, transport::Channel};
use tracing::{Level, debug, info, warn};
use tracing_subscriber::{
    EnvFilter, Registry,
    fmt::{Layer, format::FmtSpan},
    layer::Layered,
    prelude::__tracing_subscriber_SubscriberExt,
    reload,
    util::SubscriberInitExt,
};

use crate::{
    metrics::export::ExporterName,
    otlp::{
        MetricsSpanExporter, OtlpError,
        opts::{ExporterProtocol, OtlpExportOptions, StdoutExportOptions, TlsOptions, defaults},
    },
    runtime::{
        cli::Cli,
        conf::{Hcl, conf_serde::level},
        opts::SpanFmt,
    },
};

#[derive(Debug)]
pub struct ProviderBuilder {
    pub sdk_builder: opentelemetry_sdk::trace::TracerProviderBuilder,
}

/// Helper function to load certificates from a PEM file
fn load_certs_from_pem(path: &str) -> Result<Vec<CertificateDer<'static>>, OtlpError> {
    let cert_file = fs::File::open(path).map_err(|e| {
        OtlpError::TlsConfiguration(format!("failed to open certificate file '{path}': {e}"))
    })?;
    let mut reader = std::io::BufReader::new(cert_file);

    certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            OtlpError::TlsConfiguration(format!("failed to parse certificates from '{path}': {e}"))
        })
}

/// Helper function to load a private key from a PEM file
fn load_private_key_from_pem(path: &str) -> Result<PrivateKeyDer<'static>, OtlpError> {
    let key_file = fs::File::open(path).map_err(|e| {
        OtlpError::TlsConfiguration(format!("failed to open private key file '{path}': {e}"))
    })?;
    let mut reader = std::io::BufReader::new(key_file);

    private_key(&mut reader)
        .map_err(|e| {
            OtlpError::TlsConfiguration(format!("failed to parse private key from '{path}': {e}"))
        })?
        .ok_or_else(|| OtlpError::TlsConfiguration(format!("no private key found in '{path}'")))
}

/// A custom ServerCertVerifier that accepts all certificates without verification.
/// This is used for insecure mode where certificate validation is intentionally skipped.
///
/// WARNING: This should only be used for development/testing purposes, as it makes
/// the connection vulnerable to man-in-the-middle attacks.
#[derive(Debug)]
struct NoCertVerifier;

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // Accept any certificate without verification
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        // Accept any signature without verification
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        // Accept any signature without verification
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Support modern signature schemes (excluding deprecated SHA1-based schemes)
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
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

    pub fn build(self) -> SdkTracerProvider {
        self.sdk_builder.build()
    }

    /// Build OTLP exporter from options. It will prepare the headers, build the TLS configuration, and build the appropriate exporter based on the protocol.
    pub async fn with_otlp_exporter(self, options: OtlpExportOptions) -> Result<Self, OtlpError> {
        debug!(
            event.name = "exporter.otlp.started",
            "starting otlp exporter"
        );

        // Prepare headers (merge user + auth headers)
        let (options, headers) = Self::prepare_headers(options)?;

        // Parse endpoint and determine TLS requirements
        let endpoint = options.endpoint.clone();
        let uri: Uri = endpoint.parse().map_err(|e| {
            OtlpError::invalid_endpoint(&endpoint, format!("failed to parse as uri: {e}"))
        })?;
        let is_https = uri.scheme_str() == Some("https");
        let tls_config = Self::build_tls_config(is_https, options.tls.as_ref())?;

        if options
            .tls
            .as_ref()
            .and_then(|t| t.insecure_skip_verify)
            .unwrap_or(false)
        {
            warn!("insecure skip verify mode enabled - not suitable for production");
        }

        let exporter = match options.protocol {
            ExporterProtocol::Grpc => {
                Self::build_grpc_exporter(uri, tls_config.as_ref(), headers.as_ref())?
            }
            ExporterProtocol::HttpBinary => Self::build_http_exporter(
                endpoint,
                tls_config.as_ref(),
                headers.as_ref(),
                options.timeout,
            )?,
        };

        debug!(
            event.name = "exporter.otlp.build_success",
            "otlp exporter built successfully"
        );

        let batch_config = BatchConfigBuilder::default()
            .with_max_export_batch_size(options.max_batch_size)
            .with_scheduled_delay(options.max_batch_interval)
            .with_max_queue_size(options.max_queue_size)
            .with_max_concurrent_exports(options.max_concurrent_exports)
            .with_max_export_timeout(options.max_export_timeout)
            .build();

        info!(
            event.name = "batch_span_processor.config",
            max_queue_size = options.max_queue_size,
            max_concurrent_exports = options.max_concurrent_exports,
            max_batch_size = options.max_batch_size,
            "configured batch span processor for high throughput"
        );

        let wrapped_exporter = MetricsSpanExporter::new(exporter, ExporterName::Otlp);
        let processor = BatchSpanProcessor::builder(wrapped_exporter, runtime::Tokio)
            .with_batch_config(batch_config)
            .build();

        Ok(ProviderBuilder {
            sdk_builder: self.sdk_builder.with_span_processor(processor),
        })
    }

    /// Build stdout exporter from batch configuration. It will wrap the exporter in a metrics exporter and configure the batch processor.
    pub fn with_stdout_exporter(
        self,
        max_batch_size: usize,
        max_batch_interval: std::time::Duration,
        max_queue_size: usize,
        max_concurrent_exports: usize,
        max_export_timeout: std::time::Duration,
    ) -> ProviderBuilder {
        let exporter = opentelemetry_stdout::SpanExporter::default();
        // Wrap exporter to observe batch sizes
        let wrapped_exporter = MetricsSpanExporter::new(exporter, ExporterName::Stdout);

        let batch_config = BatchConfigBuilder::default()
            .with_max_export_batch_size(max_batch_size)
            .with_scheduled_delay(max_batch_interval)
            .with_max_queue_size(max_queue_size)
            .with_max_concurrent_exports(max_concurrent_exports)
            .with_max_export_timeout(max_export_timeout)
            .build();

        let processor = BatchSpanProcessor::builder(wrapped_exporter, runtime::Tokio)
            .with_batch_config(batch_config)
            .build();
        ProviderBuilder {
            sdk_builder: self.sdk_builder.with_span_processor(processor),
        }
    }

    // Build TLS configuration from TLS options.
    fn build_tls_config(
        is_https: bool,
        tls_opts: Option<&TlsOptions>,
    ) -> Result<Option<ClientConfig>, OtlpError> {
        Self::validate_tls_options(tls_opts)?;

        let is_insecure = tls_opts
            .and_then(|t| t.insecure_skip_verify)
            .unwrap_or(false);

        // No TLS needed for plain HTTP without explicit TLS options
        if !is_https && tls_opts.is_none() {
            return Ok(None);
        }

        if is_insecure {
            let config = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|e| {
                OtlpError::TlsConfiguration(format!(
                    "failed to configure tls protocol versions: {e}"
                ))
            })?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
            .with_no_client_auth();
            return Ok(Some(config));
        }

        let root_store = Self::build_root_cert_store(is_https, tls_opts)?;

        let config_builder = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| {
            OtlpError::TlsConfiguration(format!("failed to configure tls protocol versions: {e}"))
        })?
        .with_root_certificates(root_store);

        if let Some(tls_opts) = tls_opts
            && let (Some(client_cert_path), Some(client_key_path)) =
                (&tls_opts.client_cert, &tls_opts.client_key)
        {
            debug!(
                "loading client certificate for mutual tls from: {}",
                client_cert_path
            );

            let client_certs = load_certs_from_pem(client_cert_path).map_err(|e| {
                let error_msg = e.to_string();
                if error_msg.contains("failed to open certificate file") {
                    OtlpError::TlsConfiguration(
                        error_msg.replace("certificate file", "client certificate file"),
                    )
                } else {
                    e
                }
            })?;

            if client_certs.is_empty() {
                return Err(OtlpError::TlsConfiguration(format!(
                    "no valid certificates found in client certificate file '{client_cert_path}'",
                )));
            }

            let client_key = load_private_key_from_pem(client_key_path)?;

            let config = config_builder
                .with_client_auth_cert(client_certs, client_key)
                .map_err(|e| {
                    OtlpError::TlsConfiguration(format!(
                        "failed to configure client certificate: {e}"
                    ))
                })?;
            return Ok(Some(config));
        }

        Ok(Some(config_builder.with_no_client_auth()))
    }

    // Build gRPC exporter from URI, TLS configuration, and headers.
    fn build_grpc_exporter(
        uri: Uri,
        tls_config: Option<&ClientConfig>,
        headers: Option<&HashMap<String, String>>,
    ) -> Result<opentelemetry_otlp::SpanExporter, OtlpError> {
        let channel = match tls_config {
            None => {
                debug!("using plain http connection");
                Channel::builder(uri).connect_lazy()
            }
            Some(tls_config) => {
                let mut http = HttpConnector::new();
                http.enforce_http(false);

                let connector = HttpsConnectorBuilder::new()
                    .with_tls_config(tls_config.clone())
                    .https_or_http()
                    .enable_http2()
                    .wrap_connector(http);

                Channel::builder(uri).connect_with_connector_lazy(connector)
            }
        };

        let mut builder = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_channel(channel)
            .with_protocol(Protocol::Grpc);

        if let Some(headers) = headers {
            let metadata = Self::headers_to_grpc_metadata(headers)?;
            builder = builder.with_metadata(metadata);
        }

        builder.build().map_err(|e| {
            OtlpError::ExporterConfiguration(format!("failed to build otlp grpc exporter: {e}"))
        })
    }

    // Build HTTP exporter from endpoint, TLS configuration, headers, and timeout.
    fn build_http_exporter(
        endpoint: String,
        tls_config: Option<&ClientConfig>,
        headers: Option<&HashMap<String, String>>,
        timeout: std::time::Duration,
    ) -> Result<opentelemetry_otlp::SpanExporter, OtlpError> {
        let http_client = match tls_config {
            None => reqwest::Client::builder().build(),
            Some(tls_config) => reqwest::Client::builder()
                .use_preconfigured_tls(tls_config.clone())
                .build(),
        }
        .map_err(|e| {
            OtlpError::ExporterConfiguration(format!("failed to build http client: {e}"))
        })?;

        let mut builder = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(endpoint)
            .with_protocol(Protocol::HttpBinary)
            .with_timeout(timeout)
            .with_http_client(http_client);

        if let Some(headers) = headers {
            builder = builder.with_headers(headers.clone());
        }

        builder.build().map_err(|e| {
            OtlpError::ExporterConfiguration(format!(
                "failed to build otlp http_binary exporter: {e}"
            ))
        })
    }

    // Build root certificate store from TLS options.
    fn build_root_cert_store(
        is_https: bool,
        tls_opts: Option<&TlsOptions>,
    ) -> Result<RootCertStore, OtlpError> {
        let mut root_store = RootCertStore::empty();

        if is_https {
            debug!("detected https:// endpoint, loading system root certificates");
            let native_certs = rustls_native_certs::load_native_certs();

            if let Some(err) = native_certs.errors.first() {
                warn!("some system certificates failed to load: {}", err);
            }

            for cert in native_certs.certs {
                root_store.add(cert).map_err(|e| {
                    OtlpError::TlsConfiguration(format!("failed to add system certificate: {e}"))
                })?;
            }
        }

        if let Some(tls_opts) = tls_opts
            && let Some(ca_cert_path) = &tls_opts.ca_cert
        {
            debug!("loading custom ca certificate from: {}", ca_cert_path);
            let ca_certs = load_certs_from_pem(ca_cert_path)?;

            if ca_certs.is_empty() {
                return Err(OtlpError::TlsConfiguration(format!(
                    "no valid certificates found in ca certificate file '{ca_cert_path}'",
                )));
            }

            for cert in ca_certs {
                root_store.add(cert).map_err(|e| {
                    OtlpError::TlsConfiguration(format!(
                        "failed to add ca certificate from '{ca_cert_path}': {e}",
                    ))
                })?;
            }
        }

        if root_store.is_empty() {
            return Err(OtlpError::TlsConfiguration(
                "tls configuration requires at least one trusted ca certificate, \
                 either use an https:// endpoint (for system roots) or provide a ca_cert"
                    .to_string(),
            ));
        }

        Ok(root_store)
    }

    // Validate TLS options, returning an error if the options are invalid.
    fn validate_tls_options(tls_opts: Option<&TlsOptions>) -> Result<(), OtlpError> {
        let Some(tls_opts) = tls_opts else {
            return Ok(());
        };

        if tls_opts.insecure_skip_verify.unwrap_or_default()
            && (tls_opts.client_cert.is_some() || tls_opts.client_key.is_some())
        {
            return Err(OtlpError::TlsConfiguration(
                "insecure_skip_verify mode cannot be combined with client certificates, \
                 please either set insecure_skip_verify to false or remove client certificate configuration"
                    .to_string(),
            ));
        }

        if tls_opts.client_cert.is_some() ^ tls_opts.client_key.is_some() {
            return Err(OtlpError::TlsConfiguration(
                "both client_cert and client_key must be provided for mutual TLS".to_string(),
            ));
        }

        Ok(())
    }

    // Convert headers to gRPC metadata.
    fn headers_to_grpc_metadata(
        headers: &HashMap<String, String>,
    ) -> Result<MetadataMap, OtlpError> {
        let header_map = headers.iter().try_fold(
            HeaderMap::new(),
            |mut map, (key, value)| -> Result<HeaderMap, OtlpError> {
                let header_name = HeaderName::from_str(key).map_err(|e| {
                    OtlpError::ExporterConfiguration(format!("invalid header name '{key}': {e}"))
                })?;
                let header_value = HeaderValue::from_str(value).map_err(|e| {
                    OtlpError::ExporterConfiguration(format!(
                        "invalid header value for key '{key}': {e}"
                    ))
                })?;
                map.insert(header_name, header_value);
                Ok(map)
            },
        )?;

        Ok(MetadataMap::from_headers(header_map))
    }

    // Prepare headers by merging user and auth headers, returning an error if there is a collision.
    fn prepare_headers(
        mut options: OtlpExportOptions,
    ) -> Result<(OtlpExportOptions, Option<HashMap<String, String>>), OtlpError> {
        let user_headers = options.headers.take().filter(|h| !h.is_empty());
        let auth_headers = options
            .auth
            .as_ref()
            .map(|auth_config| {
                auth_config.generate_auth_headers().map_err(|e| {
                    OtlpError::ExporterConfiguration(format!(
                        "failed to generate authentication headers: {e}"
                    ))
                })
            })
            .transpose()?
            .filter(|h| !h.is_empty());
        let headers = match (user_headers, auth_headers) {
            (Some(user), Some(auth)) => Some(Self::merge_headers(user, auth)?),
            (user, auth) => user.or(auth),
        };

        Ok((options, headers))
    }

    // Merge user and auth headers, returning an error if there is a collision.
    fn merge_headers(
        mut user: HashMap<String, String>,
        auth: HashMap<String, String>,
    ) -> Result<HashMap<String, String>, OtlpError> {
        let seen_lower: std::collections::HashSet<_> =
            user.keys().map(|k| k.to_ascii_lowercase()).collect();

        for k in auth.keys() {
            let lower = k.to_ascii_lowercase();
            if seen_lower.contains(&lower) {
                return Err(OtlpError::ExporterConfiguration(format!(
                    "header name collision between user headers and auth headers on '{k}', \
                     collisions are not allowed (header names are case-insensitive)"
                )));
            }
        }

        user.extend(auth);
        Ok(user)
    }
}

pub async fn init_provider(
    stdout: Option<StdoutExportOptions>,
    otlp: Option<OtlpExportOptions>,
) -> Result<SdkTracerProvider, OtlpError> {
    let mut provider = ProviderBuilder::new();

    if stdout.is_none() && otlp.is_none() {
        warn!(
            event.name = "exporter.misconfigured",
            reason = "no_exporters_defined",
            "no exporters configured, traces will not be exported"
        );
        return Ok(provider.build());
    }

    let (batch_size, batch_interval, max_queue_size, max_concurrent_exports, max_export_timeout) =
        if let Some(ref opts) = otlp {
            (
                opts.max_batch_size,
                opts.max_batch_interval,
                opts.max_queue_size,
                opts.max_concurrent_exports,
                opts.max_export_timeout,
            )
        } else {
            (
                defaults::max_batch_size(),
                defaults::max_batch_interval(),
                defaults::max_queue_size(),
                defaults::max_concurrent_exports(),
                defaults::max_export_timeout(),
            )
        };

    if let Some(otlp_opts) = otlp {
        provider = provider.with_otlp_exporter(otlp_opts.clone()).await?;
    }

    if stdout.is_some() {
        provider = provider.with_stdout_exporter(
            batch_size,
            batch_interval,
            max_queue_size,
            max_concurrent_exports,
            max_export_timeout,
        );
    }

    Ok(provider.build())
}

pub async fn init_internal_tracing(
    handles: LogReloadHandles,
    log_level: Level,
    span_fmt: SpanFmt,
    log_color: bool,
    stdout: Option<StdoutExportOptions>,
    otlp: Option<OtlpExportOptions>,
) -> Result<(), OtlpError> {
    let provider = init_provider(stdout, otlp).await?;
    let mut fmt_layer = Layer::new()
        .with_span_events(FmtSpan::from(span_fmt))
        .with_ansi(log_color);

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
            //     ansi: set explicitly via with_ansi() based on log_color configuration
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

    let filter = EnvFilter::new(format!(
        "warn,mermin={log_level},opentelemetry_sdk={log_level},opentelemetry={log_level},opentelemetry_otlp={log_level}"
    ));

    if let Err(e) = handles.filter.modify(|f| *f = filter) {
        warn!(
            event.name = "system.logger_reload_failed",
            error.message = %e,
            error.kind = "filter",
            "failed to reload logger filter"
        );
    }
    if let Err(e) = handles.fmt.modify(|l| *l = fmt_layer) {
        warn!(
            event.name = "system.logger_reload_failed",
            error.message = %e,
            error.kind = "formatter",
            "failed to reload logger formatter"
        );
    }

    global::set_tracer_provider(provider);
    global::set_text_map_propagator(TraceContextPropagator::new());

    info!(
        event.name = "system.tracing_initialized",
        system.log_level = %log_level,
        "internal tracing and logging initialized"
    );

    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(default)]
struct BootstrapLogConf {
    #[serde(with = "level")]
    log_level: Level,
    log_color: bool,
}

impl Default for BootstrapLogConf {
    fn default() -> Self {
        Self {
            log_level: Level::INFO,
            log_color: false,
        }
    }
}

type SubscriberWithFilter = Layered<reload::Layer<EnvFilter, Registry>, Registry>;
type FmtReloadHandle = reload::Handle<Layer<SubscriberWithFilter>, SubscriberWithFilter>;
pub struct LogReloadHandles {
    pub filter: reload::Handle<EnvFilter, Registry>,
    pub fmt: FmtReloadHandle,
}

/// Initializes a simple, console-only logger and returns a handle to reconfigure it.
pub fn init_bootstrap_logger(cli: &Cli) -> LogReloadHandles {
    let mut figment = Figment::new().merge(Serialized::defaults(BootstrapLogConf::default()));

    if let Some(config_path) = &cli.config
        && config_path.exists()
    {
        figment = figment.merge(Hcl::file(config_path));
    }

    let bootstrap_conf: BootstrapLogConf = figment.extract().unwrap_or_default();

    let (filter_layer, filter_handle) =
        reload::Layer::new(EnvFilter::new(bootstrap_conf.log_level.to_string()));

    let default_layer = Layer::new()
        .with_span_events(FmtSpan::FULL)
        .with_ansi(bootstrap_conf.log_color);
    let (fmt_layer, fmt_handle) = reload::Layer::new(default_layer);

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();

    info!(
        event.name = "system.bootstrap_logger_initialized",
        "bootstrap logger initialized, awaiting full configuration"
    );

    LogReloadHandles {
        filter: filter_handle,
        fmt: fmt_handle,
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, io::Write};

    use tempfile::NamedTempFile;

    use super::*;
    use crate::otlp::opts::{AuthOptions, TlsOptions};

    fn create_test_cert_file(content: &[u8]) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("Failed to create temp file");
        file.write_all(content)
            .expect("Failed to write to temp file");
        file.flush().expect("Failed to flush temp file");
        file
    }

    fn default_opts() -> OtlpExportOptions {
        OtlpExportOptions {
            endpoint: "http://localhost:4317".to_string(),
            protocol: ExporterProtocol::Grpc,
            timeout: std::time::Duration::from_secs(10),
            max_batch_size: 512,
            max_batch_interval: std::time::Duration::from_secs(5),
            max_queue_size: 2048,
            max_concurrent_exports: 1,
            max_export_timeout: std::time::Duration::from_secs(30),
            auth: None,
            headers: None,
            tls: None,
        }
    }

    const TEST_CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQCKz8Vz6Vr8VjANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
UzAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMA0xCzAJBgNVBAYTAlVT
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z1234567890abcdefgh
ijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefgh
ijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefgh
ijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefgh
ijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefgh
ijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefgh
ijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZIDAQABMA0GCSqGSIb3DQEB
CwUAA4IBAQAxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefghijklmn
opqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefghijklmnop
qrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefghijklmnopqr
stuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefghijklmnopqrst
uvwxyz
-----END CERTIFICATE-----";

    const TEST_KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDRnXTz1234567
890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
AgMBAAECggEABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefghijklmno
pqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefghijklmnop
qrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefghijklmnopq
rstuvwxyz
-----END PRIVATE KEY-----";

    #[tokio::test]
    async fn test_grpc_http_endpoint_no_tls() {
        let options = default_opts();

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;

        // Should succeed without TLS configuration for http:// endpoint
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_grpc_https_endpoint_auto_tls() {
        let mut options = default_opts();
        options.endpoint = "https://localhost:4317".to_string();

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;

        // Should succeed with automatic TLS for https:// endpoint
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_grpc_insecure_skip_verify_mode_success() {
        // Note: This test verifies that insecure_skip_verify mode configuration is accepted.
        // With lazy connection, the channel is created successfully without immediately
        // connecting to the server. The actual connection attempt happens later when
        // data is sent through the channel.
        let mut options = default_opts();
        options.endpoint = "https://localhost:4317".to_string();
        options.tls = Some(TlsOptions {
            insecure_skip_verify: Some(true),
            ca_cert: None,
            client_cert: None,
            client_key: None,
        });

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;

        // With lazy connection, the channel creation should succeed
        // The actual connection happens later when data is sent
        assert!(
            result.is_ok(),
            "Expected insecure_skip_verify mode configuration to be accepted, but got error: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_http_binary_endpoint_no_tls() {
        let mut options = default_opts();
        options.endpoint = "http://localhost:4318".to_string();
        options.protocol = ExporterProtocol::HttpBinary;

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;
        assert!(
            result.is_ok(),
            "Failed to build HTTP/Binary client without TLS"
        );
    }

    #[tokio::test]
    async fn test_http_binary_https_auto_tls() {
        let mut options = default_opts();
        options.endpoint = "https://localhost:4318".to_string();
        options.protocol = ExporterProtocol::HttpBinary;

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;
        // This fails if the system cannot load native certs (e.g. no ca-certificates installed)
        assert!(
            result.is_ok(),
            "Failed to build HTTP/Binary client with system TLS"
        );
    }

    #[tokio::test]
    async fn test_http_binary_with_custom_ca() {
        let cert_file = create_test_cert_file(TEST_CERT_PEM);
        let cert_path = cert_file.path().to_str().unwrap().to_string();

        let mut options = default_opts();
        options.endpoint = "https://localhost:4318".to_string();
        options.protocol = ExporterProtocol::HttpBinary;
        options.tls = Some(TlsOptions {
            insecure_skip_verify: Some(false),
            ca_cert: Some(cert_path),
            client_cert: None,
            client_key: None,
        });

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;

        // The test certificates may not be valid, so we just verify
        // that the configuration was processed (either success or TLS error, not file I/O error)
        match result {
            Ok(_) => {
                // Success - configuration was accepted
            }
            Err(e) => {
                // If it fails, it should be a TLS configuration error (invalid cert format),
                // not a file I/O error (which would mean the loading logic failed)
                assert!(matches!(e, OtlpError::TlsConfiguration(_)));
                // Verify it's a certificate validation error, not a file read error
                assert!(!e.to_string().contains("failed to open certificate file"));
            }
        }
    }

    #[tokio::test]
    async fn test_http_binary_mutual_tls() {
        let cert_file = create_test_cert_file(TEST_CERT_PEM);
        let key_file = create_test_cert_file(TEST_KEY_PEM);
        let cert_path = cert_file.path().to_str().unwrap().to_string();
        let key_path = key_file.path().to_str().unwrap().to_string();

        let mut options = default_opts();
        options.endpoint = "https://localhost:4318".to_string();
        options.protocol = ExporterProtocol::HttpBinary;
        options.tls = Some(TlsOptions {
            insecure_skip_verify: Some(false),
            ca_cert: None,
            client_cert: Some(cert_path),
            client_key: Some(key_path),
        });

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;

        // The test certificates may not be valid PEM format, so we just verify
        // that the configuration was processed (either success or TLS error, not file I/O error)
        match result {
            Ok(_) => {
                // Success - configuration was accepted
            }
            Err(e) => {
                // If it fails, it should be a TLS configuration error (invalid cert format),
                // not a file I/O error (which would mean the loading logic failed)
                assert!(matches!(e, OtlpError::TlsConfiguration(_)));
            }
        }
    }

    #[tokio::test]
    async fn test_http_binary_insecure_skip_verify() {
        let mut options = default_opts();
        options.endpoint = "https://localhost:4318".to_string();
        options.protocol = ExporterProtocol::HttpBinary;
        options.tls = Some(TlsOptions {
            insecure_skip_verify: Some(true),
            ca_cert: None,
            client_cert: None,
            client_key: None,
        });

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;
        assert!(
            result.is_ok(),
            "Failed to build insecure HTTP/Binary client"
        );
    }

    #[tokio::test]
    async fn test_insecure_skip_verify_with_client_cert_fails() {
        let cert_file = create_test_cert_file(TEST_CERT_PEM);
        let key_file = create_test_cert_file(TEST_KEY_PEM);
        let cert_path = cert_file.path().to_str().unwrap().to_string();
        let key_path = key_file.path().to_str().unwrap().to_string();

        let mut options = default_opts();
        options.endpoint = "https://localhost:4317".to_string();
        options.tls = Some(TlsOptions {
            insecure_skip_verify: Some(true),
            ca_cert: None,
            client_cert: Some(cert_path),
            client_key: Some(key_path),
        });

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OtlpError::TlsConfiguration(_)));
        assert!(
            err.to_string()
                .contains("insecure_skip_verify mode cannot be combined")
        );
    }

    #[tokio::test]
    async fn test_missing_ca_cert_file() {
        let mut options = default_opts();
        options.endpoint = "https://localhost:4317".to_string();
        options.tls = Some(TlsOptions {
            insecure_skip_verify: Some(false),
            ca_cert: Some("/nonexistent/path/to/ca.crt".to_string()),
            client_cert: None,
            client_key: None,
        });

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OtlpError::TlsConfiguration(_)));
        assert!(err.to_string().contains("failed to open certificate file"));
    }

    #[tokio::test]
    async fn test_mutual_tls_missing_cert() {
        let key_file = create_test_cert_file(TEST_KEY_PEM);
        let key_path = key_file.path().to_str().unwrap().to_string();

        let mut options = default_opts();
        options.endpoint = "https://localhost:4317".to_string();
        options.tls = Some(TlsOptions {
            insecure_skip_verify: Some(false),
            ca_cert: None,
            client_cert: None,
            client_key: Some(key_path),
        });

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OtlpError::TlsConfiguration(_)));
        assert!(err.to_string().contains("both client_cert and client_key"));
    }

    #[tokio::test]
    async fn test_mutual_tls_missing_key() {
        let cert_file = create_test_cert_file(TEST_CERT_PEM);
        let cert_path = cert_file.path().to_str().unwrap().to_string();

        let mut options = default_opts();
        options.endpoint = "https://localhost:4317".to_string();
        options.tls = Some(TlsOptions {
            insecure_skip_verify: Some(false),
            ca_cert: None,
            client_cert: Some(cert_path),
            client_key: None,
        });

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;

        // Should fail when only cert is provided without key
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OtlpError::TlsConfiguration(_)));
        assert!(err.to_string().contains("both client_cert and client_key"));
    }

    #[tokio::test]
    async fn test_http_scheme_with_tls_config_override() {
        let cert_file = create_test_cert_file(TEST_CERT_PEM);
        let cert_path = cert_file.path().to_str().unwrap().to_string();

        let mut options = default_opts();
        // endpoint is http but we provide TLS
        options.tls = Some(TlsOptions {
            insecure_skip_verify: Some(false),
            ca_cert: Some(cert_path),
            client_cert: None,
            client_key: None,
        });

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;

        // http:// endpoint with explicit TLS config should still work
        // (TLS will be applied even though scheme is http)
        // The test certificates may not be valid, so we just verify
        // that the configuration was processed (either success or TLS error, not file I/O error)
        match result {
            Ok(_) => {}
            Err(e) => {
                // If it fails, it should be a TLS configuration error (invalid cert format),
                // not a file I/O error (which would mean the loading logic failed)
                assert!(matches!(e, OtlpError::TlsConfiguration(_)));
                // Verify it's a certificate validation error, not a file read error
                assert!(!e.to_string().contains("failed to open certificate file"));
            }
        }
    }

    #[tokio::test]
    async fn test_missing_client_cert_file() {
        let key_file = create_test_cert_file(TEST_KEY_PEM);
        let key_path = key_file.path().to_str().unwrap().to_string();

        let mut options = default_opts();
        options.endpoint = "https://localhost:4317".to_string();
        options.tls = Some(TlsOptions {
            insecure_skip_verify: Some(false),
            ca_cert: None,
            client_cert: Some("/nonexistent/cert.crt".to_string()),
            client_key: Some(key_path),
        });

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;

        // Should fail with clear error about missing cert file
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OtlpError::TlsConfiguration(_)));
        assert!(
            err.to_string()
                .contains("failed to open client certificate file")
        );
    }

    #[tokio::test]
    async fn test_missing_client_key_file() {
        let cert_file = create_test_cert_file(TEST_CERT_PEM);
        let cert_path = cert_file.path().to_str().unwrap().to_string();

        let mut options = default_opts();
        options.endpoint = "https://localhost:4317".to_string();
        options.tls = Some(TlsOptions {
            insecure_skip_verify: Some(false),
            ca_cert: None,
            client_cert: Some(cert_path),
            client_key: Some("/nonexistent/key.key".to_string()),
        });

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;

        // Should fail with clear error about missing key file
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OtlpError::TlsConfiguration(_)));
        assert!(err.to_string().contains("failed to open private key file"));
    }

    #[test]
    fn test_load_certs_from_pem_success() {
        let cert_file = create_test_cert_file(TEST_CERT_PEM);
        let cert_path = cert_file.path().to_str().unwrap();

        let result = load_certs_from_pem(cert_path);
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }

    #[test]
    fn test_load_certs_from_pem_missing_file() {
        let result = load_certs_from_pem("/nonexistent/ca.crt");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OtlpError::TlsConfiguration(_)));
        assert!(err.to_string().contains("failed to open certificate file"));
    }

    #[test]
    fn test_load_private_key_success() {
        let key_file = create_test_cert_file(TEST_KEY_PEM);
        let key_path = key_file.path().to_str().unwrap();

        let result = load_private_key_from_pem(key_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_private_key_missing_cert() {
        let result = load_private_key_from_pem("/nonexistent/key.key");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OtlpError::TlsConfiguration(_)));
        assert!(err.to_string().contains("failed to open private key file"));
    }

    #[test]
    fn test_load_client_certs_and_key_success() {
        let cert_file = create_test_cert_file(TEST_CERT_PEM);
        let key_file = create_test_cert_file(TEST_KEY_PEM);

        let cert_path = cert_file.path().to_str().unwrap();
        let key_path = key_file.path().to_str().unwrap();

        let certs = load_certs_from_pem(cert_path);
        let key = load_private_key_from_pem(key_path);

        assert!(certs.is_ok());
        assert!(key.is_ok());
    }

    #[test]
    fn test_prepare_headers_none_when_no_auth_and_no_user_headers() {
        let opts = default_opts();

        let (_opts, headers) =
            ProviderBuilder::prepare_headers(opts).expect("prepare_headers should succeed");

        assert!(headers.is_none());
    }

    #[test]
    fn test_prepare_headers_user_only() {
        let mut opts = default_opts();
        let mut user = HashMap::new();
        user.insert("x-greptime-db-name".to_string(), "public".to_string());
        user.insert(
            "x-greptime-pipeline-name".to_string(),
            "greptime_trace_v1".to_string(),
        );
        opts.headers = Some(user);

        let (_opts, headers) =
            ProviderBuilder::prepare_headers(opts).expect("prepare_headers should succeed");

        let headers = headers.expect("expected Some(headers)");
        assert_eq!(
            headers.get("x-greptime-db-name").map(String::as_str),
            Some("public")
        );
        assert_eq!(
            headers.get("x-greptime-pipeline-name").map(String::as_str),
            Some("greptime_trace_v1")
        );
        assert!(headers.get("Authorization").is_none());
    }

    #[test]
    fn test_prepare_headers_auth_only() {
        let mut opts = default_opts();
        opts.auth = Some(AuthOptions {
            basic: None,
            bearer: Some("TOKEN".to_string()),
        });

        let (_opts, headers) =
            ProviderBuilder::prepare_headers(opts).expect("prepare_headers should succeed");

        let headers = headers.expect("expected Some(headers)");
        assert_eq!(
            headers.get("Authorization").map(String::as_str),
            Some("Bearer TOKEN")
        );
    }

    #[test]
    fn test_prepare_headers_combined_when_both_present() {
        let mut opts = default_opts();

        let mut user = HashMap::new();
        user.insert("x-greptime-db-name".to_string(), "public".to_string());
        opts.headers = Some(user);

        opts.auth = Some(AuthOptions {
            basic: None,
            bearer: Some("TOKEN".to_string()),
        });

        let (_opts, headers) =
            ProviderBuilder::prepare_headers(opts).expect("prepare_headers should succeed");

        let headers = headers.expect("expected Some(headers)");
        assert_eq!(
            headers.get("x-greptime-db-name").map(String::as_str),
            Some("public")
        );
        assert_eq!(
            headers.get("Authorization").map(String::as_str),
            Some("Bearer TOKEN")
        );
    }

    #[test]
    fn test_prepare_headers_auth_only_when_user_headers_is_empty_map() {
        let mut opts = default_opts();

        opts.headers = Some(HashMap::new());
        opts.auth = Some(AuthOptions {
            basic: None,
            bearer: Some("TOKEN".to_string()),
        });

        let (_opts, headers) =
            ProviderBuilder::prepare_headers(opts).expect("prepare_headers should succeed");

        let headers = headers.expect("expected Some(headers)");
        assert_eq!(
            headers.get("Authorization").map(String::as_str),
            Some("Bearer TOKEN")
        );
    }

    #[test]
    fn test_prepare_headers_rejects_authorization_collision_case_insensitive() {
        let mut opts = default_opts();

        let mut user = HashMap::new();
        user.insert("authorization".to_string(), "user-value".to_string()); // collision with auth
        opts.headers = Some(user);

        opts.auth = Some(AuthOptions {
            basic: None,
            bearer: Some("TOKEN".to_string()),
        });

        let err = ProviderBuilder::prepare_headers(opts)
            .expect_err("expected prepare_headers to fail due to collision");

        let msg = err.to_string().to_ascii_lowercase();
        assert!(msg.contains("collision"), "unexpected error: {msg}");
        assert!(msg.contains("authorization"), "unexpected error: {msg}");
    }
}
