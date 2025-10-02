use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SpanFmt {
    #[default]
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
