use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::{
    metrics::opts::MetricsOptions,
    otlp::opts::{OtlpExportOptions, StdoutExportOptions},
};

/// Represents the entire top-level `internal` block for internal monitoring.
#[derive(Default, Debug, Deserialize, Serialize, Clone)]
pub struct InternalOptions {
    pub traces: InternalTraceOptions,
    pub metrics: MetricsOptions,
    pub server: ServerConf,
}

/// Configuration for the internal HTTP server (health endpoints).
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerConf {
    /// Enable the HTTP server.
    pub enabled: bool,
    /// The network address the HTTP server will listen on.
    pub listen_address: String,
    /// The port the HTTP server will listen on.
    pub port: u16,
}

impl Default for ServerConf {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_address: Ipv4Addr::UNSPECIFIED.to_string(),
            port: 8080,
        }
    }
}

#[derive(Default, Debug, Deserialize, Serialize, Clone)]
pub struct InternalTraceOptions {
    /// The level of span events to record.
    pub span_fmt: SpanFmt,

    /// Stdout exporter configuration options.
    pub stdout: Option<StdoutExportOptions>,

    /// OTLP (OpenTelemetry Protocol) exporter configurations.
    pub otlp: Option<OtlpExportOptions>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SpanFmt {
    #[default]
    #[serde(rename = "full")]
    Full,
}

impl From<SpanFmt> for tracing_subscriber::fmt::format::FmtSpan {
    fn from(fmt: SpanFmt) -> Self {
        match fmt {
            SpanFmt::Full => tracing_subscriber::fmt::format::FmtSpan::FULL,
        }
    }
}

impl From<String> for SpanFmt {
    fn from(_: String) -> Self {
        SpanFmt::Full
    }
}
