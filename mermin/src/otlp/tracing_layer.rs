//! Custom tracing layer to intercept OpenTelemetry errors and update metrics.

use tracing::{Event, Level, Subscriber};
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

use crate::metrics::export::{ExportStatus, inc_export_flow_spans};

pub struct OtelErrorLayer;

impl<S> Layer<S> for OtelErrorLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let level = *metadata.level();

        if level != Level::ERROR {
            return;
        }

        let target = metadata.target();

        if target.starts_with("opentelemetry") {
            inc_export_flow_spans("otlp", ExportStatus::Error);
        }
    }
}
