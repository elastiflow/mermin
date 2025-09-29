use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpanFmt {
    Full,
}

impl Default for SpanFmt {
    fn default() -> Self {
        SpanFmt::Full
    }
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
            "full" => SpanFmt::Full,
            _ => SpanFmt::Full,
        }
    }
}
