use serde::{Deserialize, Serialize};

use crate::otlp::opts::{OtlpExportOptions, StdoutExportOptions};

/// Represents the entire top-level `traces` block for internal monitoring.
#[derive(Default, Debug, Deserialize, Serialize, Clone)]
pub struct InternalOptions {
    pub traces: InternalTraceOptions,
}

#[derive(Default, Debug, Deserialize, Serialize, Clone)]
pub struct InternalTraceOptions {
    /// The level of span events to record. The current default is `FmtSpan::FULL`,
    /// which records all events (enter, exit, close) for all spans. The level can also be
    /// one of the following:
    /// - `SpanFmt::Full`: Records all span events (enter, exit, close).
    /// - `FmtSpan::ENTER`: Only span enter events are recorded.
    /// - `FmtSpan::EXIT`: Only span exit events are recorded.
    /// - `FmtSpan::CLOSE`: Only span close events are recorded.
    /// - `FmtSpan::ACTIVE`: Only span events for spans that are active (i.e., not closed) are recorded.
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
    fn from(s: String) -> Self {
        match s.to_lowercase().as_str() {
            "plain" => SpanFmt::Full,
            _ => SpanFmt::Full,
        }
    }
}
