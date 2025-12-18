//! Enums for export-related metrics labels.

/// Export status for flow spans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportStatus {
    Ok,
    Attempted,
    Error,
    NoOp,
}

impl AsRef<str> for ExportStatus {
    fn as_ref(&self) -> &str {
        match self {
            ExportStatus::Ok => "ok",
            ExportStatus::Attempted => "attempted",
            ExportStatus::Error => "error",
            ExportStatus::NoOp => "noop",
        }
    }
}

/// Exporter name for metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExporterName {
    Otlp,
    Stdout,
    Noop,
}

impl AsRef<str> for ExporterName {
    fn as_ref(&self) -> &str {
        match self {
            ExporterName::Otlp => "otlp",
            ExporterName::Stdout => "stdout",
            ExporterName::Noop => "noop",
        }
    }
}
