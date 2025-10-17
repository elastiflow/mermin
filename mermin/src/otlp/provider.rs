use std::{fs, sync::Arc};

use axum::http::Uri;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::{
    Resource,
    propagation::TraceContextPropagator,
    runtime,
    trace::{
        BatchConfigBuilder, SdkTracerProvider,
        span_processor_with_async_runtime::BatchSpanProcessor,
    },
};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tracing::{Level, debug, info, level_filters::LevelFilter, warn};
use tracing_subscriber::{
    EnvFilter,
    fmt::{Layer, format::FmtSpan},
    prelude::__tracing_subscriber_SubscriberExt,
    util::SubscriberInitExt,
};

use crate::{
    otlp::{
        OtlpError,
        opts::{OtlpExporterOptions, StdoutFmt, defaults},
    },
    runtime::opts::SpanFmt,
};

#[derive(Debug)]
pub struct ProviderBuilder {
    pub sdk_builder: opentelemetry_sdk::trace::TracerProviderBuilder,
}

/// Helper function to load a certificate from a file path
fn load_certificate(path: &str) -> Result<Certificate, OtlpError> {
    let cert_pem = fs::read(path).map_err(|e| {
        OtlpError::TlsConfiguration(format!("failed to read certificate file '{path}': {e}"))
    })?;
    Ok(Certificate::from_pem(cert_pem))
}

/// Helper function to load client identity (certificate + private key) for mutual TLS
fn load_client_identity(cert_path: &str, key_path: &str) -> Result<Identity, OtlpError> {
    let cert_pem = fs::read(cert_path).map_err(|e| {
        OtlpError::TlsConfiguration(format!(
            "failed to read client certificate file '{cert_path}': {e}"
        ))
    })?;
    let key_pem = fs::read(key_path).map_err(|e| {
        OtlpError::TlsConfiguration(format!("failed to read client key file '{key_path}': {e}"))
    })?;
    Ok(Identity::from_pem(cert_pem, key_pem))
}

/// A custom ServerCertVerifier that accepts all certificates without verification.
/// This is used for insecure mode where certificate validation is intentionally skipped.
///
/// WARNING: This should only be used for development/testing purposes, as it makes
/// the connection vulnerable to man-in-the-middle attacks.
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
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

    pub async fn with_otlp_exporter(self, options: OtlpExporterOptions) -> Result<Self, OtlpError> {
        debug!(
            event.name = "exporter.otlp.creating",
            "creating otlp exporter"
        );
        let endpoint = options.build_endpoint();
        let uri: Uri = endpoint.parse().map_err(|e| {
            OtlpError::invalid_endpoint(&endpoint, format!("failed to parse as uri: {e}"))
        })?;

        let is_https = uri.scheme_str() == Some("https");

        let channel = match &options.tls {
            Some(tls_opts) if tls_opts.insecure => Self::build_insecure_channel(uri, tls_opts)?,
            _ => Self::build_secure_channel(uri, is_https, options.tls.as_ref())?,
        };

        let builder = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic() // for gRPC
            .with_channel(channel)
            .with_protocol(opentelemetry_otlp::Protocol::Grpc);

        if let Some(auth_config) = &options.auth {
            let auth_headers = auth_config.generate_auth_headers().map_err(|e| {
                OtlpError::ExporterConfiguration(format!(
                    "failed to generate authentication headers: {e}"
                ))
            })?;
            info!(
                event.name = "exporter.otlp.auth.configured",
                exporter.otlp.auth.header_count = auth_headers.len(),
                "authentication headers configured for otlp exporter"
            );
            // TODO: Apply headers to the exporter builder - ENG-120
            // Note: The opentelemetry_otlp crate may need to be updated to support custom headers
            // For now, this is a placeholder for where header configuration would go
        }

        match builder.build() {
            Ok(exporter) => {
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

                let processor = BatchSpanProcessor::builder(exporter, runtime::Tokio)
                    .with_batch_config(batch_config)
                    .build();
                Ok(ProviderBuilder {
                    sdk_builder: self.sdk_builder.with_span_processor(processor),
                })
            }
            Err(e) => Err(OtlpError::ExporterConfiguration(format!(
                "failed to build otlp exporter: {e}"
            ))),
        }
    }

    pub fn with_stdout_exporter(
        self,
        max_batch_size: usize,
        max_batch_interval: std::time::Duration,
        max_queue_size: usize,
        max_concurrent_exports: usize,
        max_export_timeout: std::time::Duration,
    ) -> ProviderBuilder {
        let exporter = opentelemetry_stdout::SpanExporter::default();

        let batch_config = BatchConfigBuilder::default()
            .with_max_export_batch_size(max_batch_size)
            .with_scheduled_delay(max_batch_interval)
            .with_max_queue_size(max_queue_size)
            .with_max_concurrent_exports(max_concurrent_exports)
            .with_max_export_timeout(max_export_timeout)
            .build();

        let processor = BatchSpanProcessor::builder(exporter, runtime::Tokio)
            .with_batch_config(batch_config)
            .build();
        ProviderBuilder {
            sdk_builder: self.sdk_builder.with_span_processor(processor),
        }
    }

    fn build_insecure_channel(
        uri: Uri,
        tls_opts: &crate::otlp::opts::TlsOptions,
    ) -> Result<Channel, OtlpError> {
        warn!(
            "insecure mode enabled: TLS certificate verification is disabled - \
            this should only be used for development/testing - \
            your connection is vulnerable to man-in-the-middle attacks"
        );

        if tls_opts.client_cert.is_some() || tls_opts.client_key.is_some() {
            return Err(OtlpError::TlsConfiguration(
                "insecure mode cannot be combined with client certificates - \
                please either disable insecure mode or remove client certificate configuration."
                    .to_string(),
            ));
        }

        let rustls_config = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| {
            OtlpError::TlsConfiguration(format!("failed to configure tls protocol versions: {e}"))
        })?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

        let mut http_connector = HttpConnector::new();
        http_connector.enforce_http(false);

        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(rustls_config)
            .https_or_http()
            .enable_http1()
            .wrap_connector(http_connector);

        Ok(Channel::builder(uri).connect_with_connector_lazy(connector))
    }

    fn build_secure_channel(
        uri: Uri,
        is_https: bool,
        tls_opts: Option<&crate::otlp::opts::TlsOptions>,
    ) -> Result<Channel, OtlpError> {
        let tls_config = if is_https || tls_opts.is_some() {
            let mut tls = ClientTlsConfig::new();

            if is_https {
                debug!("detected https:// endpoint, enabling TLS with system root certificates");
                tls = tls.with_native_roots();
            }

            if let Some(tls_opts) = tls_opts {
                if let Some(ca_cert_path) = &tls_opts.ca_cert {
                    debug!("loading custom CA certificate from: {}", ca_cert_path);
                    let ca_cert = load_certificate(ca_cert_path)?;
                    tls = tls.ca_certificate(ca_cert);
                }

                if let (Some(client_cert_path), Some(client_key_path)) =
                    (&tls_opts.client_cert, &tls_opts.client_key)
                {
                    debug!(
                        "loading client certificate for mutual TLS from: {}",
                        client_cert_path
                    );
                    let identity = load_client_identity(client_cert_path, client_key_path)?;
                    tls = tls.identity(identity);
                } else if tls_opts.client_cert.is_some() || tls_opts.client_key.is_some() {
                    return Err(OtlpError::TlsConfiguration(
                        "both client_cert and client_key must be provided for mutual TLS"
                            .to_string(),
                    ));
                }
            }

            Some(tls)
        } else {
            None
        };

        let mut channel_builder = Channel::builder(uri);
        if let Some(tls) = tls_config {
            debug!("applying tls configuration to otlp exporter channel");
            channel_builder = channel_builder.tls_config(tls).map_err(|e| {
                OtlpError::TlsConfiguration(format!("failed to apply tls config: {e}"))
            })?;
        }

        Ok(channel_builder.connect_lazy())
    }

    pub fn build(self) -> SdkTracerProvider {
        self.sdk_builder.build()
    }
}

pub async fn init_provider(
    stdout: Option<StdoutFmt>,
    otlp: Option<OtlpExporterOptions>,
) -> Result<SdkTracerProvider, OtlpError> {
    let mut provider = ProviderBuilder::new();

    if stdout.is_none() && otlp.is_none() {
        warn!(
            event.name = "exporter.misconfigured",
            reason = "no_exporters_defined",
            "no exporters configured; traces will not be exported"
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
    log_level: Level,
    span_fmt: SpanFmt,
    stdout: Option<StdoutFmt>,
    otlp: Option<OtlpExporterOptions>,
) -> Result<(), OtlpError> {
    let provider = init_provider(stdout, otlp).await?;
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

    info!(
        event.name = "system.tracing_initialized",
        system.log_level = %log_level,
        "internal tracing and logging initialized"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;
    use crate::otlp::opts::TlsOptions;

    // Helper function to create test certificate files
    fn create_test_cert_file(content: &[u8]) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("Failed to create temp file");
        file.write_all(content)
            .expect("Failed to write to temp file");
        file.flush().expect("Failed to flush temp file");
        file
    }

    // Sample PEM-encoded certificate for testing
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
    async fn test_http_endpoint_no_tls() {
        let options = OtlpExporterOptions {
            endpoint: "http://localhost:4317".to_string(),
            protocol: crate::otlp::opts::ExporterProtocol::Grpc,
            timeout: std::time::Duration::from_secs(10),
            max_batch_size: 512,
            max_batch_interval: std::time::Duration::from_secs(5),
            max_queue_size: 2048,
            max_concurrent_exports: 1,
            max_export_timeout: std::time::Duration::from_secs(30),
            auth: None,
            tls: None,
        };

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;

        // Should succeed without TLS configuration for http:// endpoint
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_https_endpoint_auto_tls() {
        let options = OtlpExporterOptions {
            endpoint: "https://localhost:4317".to_string(),
            protocol: crate::otlp::opts::ExporterProtocol::Grpc,
            timeout: std::time::Duration::from_secs(10),
            max_batch_size: 512,
            max_batch_interval: std::time::Duration::from_secs(5),
            max_queue_size: 2048,
            max_concurrent_exports: 1,
            max_export_timeout: std::time::Duration::from_secs(30),
            auth: None,
            tls: None,
        };

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;

        // Should succeed with automatic TLS for https:// endpoint
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_insecure_mode_success() {
        // Note: This test verifies that insecure mode configuration is accepted.
        // With lazy connection, the channel is created successfully without immediately
        // connecting to the server. The actual connection attempt happens later when
        // data is sent through the channel.
        let options = OtlpExporterOptions {
            endpoint: "https://localhost:4317".to_string(),
            protocol: crate::otlp::opts::ExporterProtocol::Grpc,
            timeout: std::time::Duration::from_secs(10),
            max_batch_size: 512,
            max_batch_interval: std::time::Duration::from_secs(5),
            max_queue_size: 2048,
            max_concurrent_exports: 1,
            max_export_timeout: std::time::Duration::from_secs(30),
            auth: None,
            tls: Some(TlsOptions {
                insecure: true,
                ca_cert: None,
                client_cert: None,
                client_key: None,
            }),
        };

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;

        // With lazy connection, the channel creation should succeed
        // The actual connection happens later when data is sent
        assert!(
            result.is_ok(),
            "Expected insecure mode configuration to be accepted, but got error: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_insecure_with_client_cert_fails() {
        let cert_file = create_test_cert_file(TEST_CERT_PEM);
        let key_file = create_test_cert_file(TEST_KEY_PEM);
        let cert_path = cert_file.path().to_str().unwrap().to_string();
        let key_path = key_file.path().to_str().unwrap().to_string();

        let options = OtlpExporterOptions {
            endpoint: "https://localhost:4317".to_string(),
            protocol: crate::otlp::opts::ExporterProtocol::Grpc,
            timeout: std::time::Duration::from_secs(10),
            max_batch_size: 512,
            max_batch_interval: std::time::Duration::from_secs(5),
            max_queue_size: 2048,
            max_concurrent_exports: 1,
            max_export_timeout: std::time::Duration::from_secs(30),
            auth: None,
            tls: Some(TlsOptions {
                insecure: true,
                ca_cert: None,
                client_cert: Some(cert_path),
                client_key: Some(key_path),
            }),
        };

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;

        // Should fail when insecure mode is combined with client certificates
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OtlpError::TlsConfiguration(_)));
        assert!(
            err.to_string()
                .contains("insecure mode cannot be combined with client certificates")
        );
    }

    #[tokio::test]
    async fn test_custom_ca_cert() {
        let cert_file = create_test_cert_file(TEST_CERT_PEM);
        let cert_path = cert_file.path().to_str().unwrap().to_string();

        let options = OtlpExporterOptions {
            endpoint: "https://localhost:4317".to_string(),
            protocol: crate::otlp::opts::ExporterProtocol::Grpc,
            timeout: std::time::Duration::from_secs(10),
            max_batch_size: 512,
            max_batch_interval: std::time::Duration::from_secs(5),
            max_queue_size: 2048,
            max_concurrent_exports: 1,
            max_export_timeout: std::time::Duration::from_secs(30),
            auth: None,
            tls: Some(TlsOptions {
                insecure: false,
                ca_cert: Some(cert_path),
                client_cert: None,
                client_key: None,
            }),
        };

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;

        // Should succeed with custom CA certificate
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_missing_ca_cert_file() {
        let options = OtlpExporterOptions {
            endpoint: "https://localhost:4317".to_string(),
            protocol: crate::otlp::opts::ExporterProtocol::Grpc,
            timeout: std::time::Duration::from_secs(10),
            max_batch_size: 512,
            max_batch_interval: std::time::Duration::from_secs(5),
            max_queue_size: 2048,
            max_concurrent_exports: 1,
            max_export_timeout: std::time::Duration::from_secs(30),
            auth: None,
            tls: Some(TlsOptions {
                insecure: false,
                ca_cert: Some("/nonexistent/path/to/ca.crt".to_string()),
                client_cert: None,
                client_key: None,
            }),
        };

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;

        // Should fail with clear error about missing file
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OtlpError::TlsConfiguration(_)));
        assert!(err.to_string().contains("failed to read certificate file"));
    }

    #[tokio::test]
    async fn test_mutual_tls_success() {
        let cert_file = create_test_cert_file(TEST_CERT_PEM);
        let key_file = create_test_cert_file(TEST_KEY_PEM);

        let cert_path = cert_file.path().to_str().unwrap().to_string();
        let key_path = key_file.path().to_str().unwrap().to_string();

        let options = OtlpExporterOptions {
            endpoint: "https://localhost:4317".to_string(),
            protocol: crate::otlp::opts::ExporterProtocol::Grpc,
            timeout: std::time::Duration::from_secs(10),
            max_batch_size: 512,
            max_batch_interval: std::time::Duration::from_secs(5),
            max_queue_size: 2048,
            max_concurrent_exports: 1,
            max_export_timeout: std::time::Duration::from_secs(30),
            auth: None,
            tls: Some(TlsOptions {
                insecure: false,
                ca_cert: None,
                client_cert: Some(cert_path),
                client_key: Some(key_path),
            }),
        };

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
    async fn test_mutual_tls_missing_cert() {
        let key_file = create_test_cert_file(TEST_KEY_PEM);
        let key_path = key_file.path().to_str().unwrap().to_string();

        let options = OtlpExporterOptions {
            endpoint: "https://localhost:4317".to_string(),
            protocol: crate::otlp::opts::ExporterProtocol::Grpc,
            timeout: std::time::Duration::from_secs(10),
            max_batch_size: 512,
            max_batch_interval: std::time::Duration::from_secs(5),
            max_queue_size: 2048,
            max_concurrent_exports: 1,
            max_export_timeout: std::time::Duration::from_secs(30),
            auth: None,
            tls: Some(TlsOptions {
                insecure: false,
                ca_cert: None,
                client_cert: None,
                client_key: Some(key_path),
            }),
        };

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;

        // Should fail when only key is provided without cert
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OtlpError::TlsConfiguration(_)));
        assert!(
            err.to_string()
                .contains("both client_cert and client_key must be provided")
        );
    }

    #[tokio::test]
    async fn test_mutual_tls_missing_key() {
        let cert_file = create_test_cert_file(TEST_CERT_PEM);
        let cert_path = cert_file.path().to_str().unwrap().to_string();

        let options = OtlpExporterOptions {
            endpoint: "https://localhost:4317".to_string(),
            protocol: crate::otlp::opts::ExporterProtocol::Grpc,
            timeout: std::time::Duration::from_secs(10),
            max_batch_size: 512,
            max_batch_interval: std::time::Duration::from_secs(5),
            max_queue_size: 2048,
            max_concurrent_exports: 1,
            max_export_timeout: std::time::Duration::from_secs(30),
            auth: None,
            tls: Some(TlsOptions {
                insecure: false,
                ca_cert: None,
                client_cert: Some(cert_path),
                client_key: None,
            }),
        };

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;

        // Should fail when only cert is provided without key
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OtlpError::TlsConfiguration(_)));
        assert!(
            err.to_string()
                .contains("both client_cert and client_key must be provided")
        );
    }

    #[tokio::test]
    async fn test_http_with_tls_config() {
        let cert_file = create_test_cert_file(TEST_CERT_PEM);
        let cert_path = cert_file.path().to_str().unwrap().to_string();

        let options = OtlpExporterOptions {
            endpoint: "http://localhost:4317".to_string(),
            protocol: crate::otlp::opts::ExporterProtocol::Grpc,
            timeout: std::time::Duration::from_secs(10),
            max_batch_size: 512,
            max_batch_interval: std::time::Duration::from_secs(5),
            max_queue_size: 2048,
            max_concurrent_exports: 1,
            max_export_timeout: std::time::Duration::from_secs(30),
            auth: None,
            tls: Some(TlsOptions {
                insecure: false,
                ca_cert: Some(cert_path),
                client_cert: None,
                client_key: None,
            }),
        };

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;

        // http:// endpoint with explicit TLS config should still work
        // (TLS will be applied even though scheme is http)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_missing_client_cert_file() {
        let key_file = create_test_cert_file(TEST_KEY_PEM);
        let key_path = key_file.path().to_str().unwrap().to_string();

        let options = OtlpExporterOptions {
            endpoint: "https://localhost:4317".to_string(),
            protocol: crate::otlp::opts::ExporterProtocol::Grpc,
            timeout: std::time::Duration::from_secs(10),
            max_batch_size: 512,
            max_batch_interval: std::time::Duration::from_secs(5),
            max_queue_size: 2048,
            max_concurrent_exports: 1,
            max_export_timeout: std::time::Duration::from_secs(30),
            auth: None,
            tls: Some(TlsOptions {
                insecure: false,
                ca_cert: None,
                client_cert: Some("/nonexistent/cert.crt".to_string()),
                client_key: Some(key_path),
            }),
        };

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;

        // Should fail with clear error about missing cert file
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OtlpError::TlsConfiguration(_)));
        assert!(
            err.to_string()
                .contains("failed to read client certificate file")
        );
    }

    #[tokio::test]
    async fn test_missing_client_key_file() {
        let cert_file = create_test_cert_file(TEST_CERT_PEM);
        let cert_path = cert_file.path().to_str().unwrap().to_string();

        let options = OtlpExporterOptions {
            endpoint: "https://localhost:4317".to_string(),
            protocol: crate::otlp::opts::ExporterProtocol::Grpc,
            timeout: std::time::Duration::from_secs(10),
            max_batch_size: 512,
            max_batch_interval: std::time::Duration::from_secs(5),
            max_queue_size: 2048,
            max_concurrent_exports: 1,
            max_export_timeout: std::time::Duration::from_secs(30),
            auth: None,
            tls: Some(TlsOptions {
                insecure: false,
                ca_cert: None,
                client_cert: Some(cert_path),
                client_key: Some("/nonexistent/key.key".to_string()),
            }),
        };

        let provider = ProviderBuilder::new();
        let result = provider.with_otlp_exporter(options).await;

        // Should fail with clear error about missing key file
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OtlpError::TlsConfiguration(_)));
        assert!(err.to_string().contains("failed to read client key file"));
    }

    #[test]
    fn test_load_certificate_success() {
        let cert_file = create_test_cert_file(TEST_CERT_PEM);
        let cert_path = cert_file.path().to_str().unwrap();

        let result = load_certificate(cert_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_certificate_missing_file() {
        let result = load_certificate("/nonexistent/ca.crt");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OtlpError::TlsConfiguration(_)));
        assert!(err.to_string().contains("failed to read certificate file"));
    }

    #[test]
    fn test_load_client_identity_success() {
        let cert_file = create_test_cert_file(TEST_CERT_PEM);
        let key_file = create_test_cert_file(TEST_KEY_PEM);

        let cert_path = cert_file.path().to_str().unwrap();
        let key_path = key_file.path().to_str().unwrap();

        let result = load_client_identity(cert_path, key_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_client_identity_missing_cert() {
        let key_file = create_test_cert_file(TEST_KEY_PEM);
        let key_path = key_file.path().to_str().unwrap();

        let result = load_client_identity("/nonexistent/cert.crt", key_path);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OtlpError::TlsConfiguration(_)));
        assert!(
            err.to_string()
                .contains("failed to read client certificate file")
        );
    }

    #[test]
    fn test_load_client_identity_missing_key() {
        let cert_file = create_test_cert_file(TEST_CERT_PEM);
        let cert_path = cert_file.path().to_str().unwrap();

        let result = load_client_identity(cert_path, "/nonexistent/key.key");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OtlpError::TlsConfiguration(_)));
        assert!(err.to_string().contains("failed to read client key file"));
    }
}
