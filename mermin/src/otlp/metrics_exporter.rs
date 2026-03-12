//! Wrapper SpanExporter that observes batch sizes and tracks export success/error metrics.

use opentelemetry_sdk::{
    error::{OTelSdkError, OTelSdkResult},
    resource::Resource,
    trace::{SpanData, SpanExporter},
};

use crate::metrics::{
    self,
    labels::{ExportStatus, ExporterName},
};

#[derive(Debug)]
pub struct MetricsSpanExporter<E> {
    inner: E,
    exporter_name: ExporterName,
}

impl<E> MetricsSpanExporter<E> {
    pub fn new(inner: E, exporter_name: ExporterName) -> Self {
        Self {
            inner,
            exporter_name,
        }
    }
}

impl<E> SpanExporter for MetricsSpanExporter<E>
where
    E: SpanExporter,
{
    #[allow(refining_impl_trait)]
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        let batch_size = batch.len();
        if batch_size > 0 {
            metrics::registry::EXPORT_BATCH_SIZE
                .get()
                .unwrap()
                .observe(batch_size as f64);
        }

        let result = self.inner.export(batch).await;

        let exporter_name = self.exporter_name;
        match &result {
            Ok(()) => {
                metrics::registry::EXPORT_FLOW_SPANS_TOTAL
                    .with_label_values(&[exporter_name.as_str(), ExportStatus::Ok.as_str()])
                    .inc_by(batch_size as u64);
            }
            Err(_) => {
                metrics::registry::EXPORT_FLOW_SPANS_TOTAL
                    .with_label_values(&[exporter_name.as_str(), ExportStatus::Error.as_str()])
                    .inc_by(batch_size as u64);
            }
        }

        result
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }

    fn shutdown(&mut self) -> Result<(), OTelSdkError> {
        self.inner.shutdown()
    }
}
