//! Wrapper SpanExporter that observes batch sizes and tracks export success/error metrics.

use futures::future::BoxFuture;
use opentelemetry_sdk::{
    error::{OTelSdkError, OTelSdkResult},
    trace::{SpanData, SpanExporter},
};

use crate::metrics::{
    self,
    export::{ExportStatus, ExporterName},
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
    fn export(&self, batch: Vec<SpanData>) -> BoxFuture<'static, OTelSdkResult> {
        // Observe batch size before delegating to inner exporter
        let batch_size = batch.len();
        if batch_size > 0 {
            metrics::registry::EXPORT_BATCH_SIZE
                .get()
                .unwrap()
                .observe(batch_size as f64);
        }

        let exporter_name = self.exporter_name;

        // Delegate to inner exporter - the trait guarantees 'static but compiler can't prove it
        // due to associated type. We use unsafe to assert the lifetime per trait contract.
        let inner_export = self.inner.export(batch);
        let pinned: BoxFuture<'_, OTelSdkResult> = Box::pin(inner_export);
        // SAFETY: SpanExporter::export() guarantees BoxFuture<'static, ...> per trait contract.
        // The batch is moved, so no borrows remain. We're only asserting 'static lifetime.
        let inner_export_static = unsafe {
            std::mem::transmute::<BoxFuture<'_, OTelSdkResult>, BoxFuture<'static, OTelSdkResult>>(
                pinned,
            )
        };

        Box::pin(async move {
            let result = inner_export_static.await;

            match &result {
                Ok(()) => {
                    // Track successful export - increment by batch size since each span succeeded
                    metrics::registry::EXPORT_FLOW_SPANS_TOTAL
                        .with_label_values(&[exporter_name.as_str(), ExportStatus::Ok.as_str()])
                        .inc_by(batch_size as u64);
                }
                Err(_) => {
                    // Track export error - increment by batch size since each span in the batch failed
                    metrics::registry::EXPORT_FLOW_SPANS_TOTAL
                        .with_label_values(&[exporter_name.as_str(), ExportStatus::Error.as_str()])
                        .inc_by(batch_size as u64);
                }
            }

            result
        })
    }

    fn shutdown(&mut self) -> Result<(), OTelSdkError> {
        self.inner.shutdown()
    }
}
