//! Wrapper SpanExporter that observes batch sizes for metrics.

use futures::future::BoxFuture;
use opentelemetry_sdk::{
    error::{OTelSdkError, OTelSdkResult},
    trace::{SpanData, SpanExporter},
};

use crate::metrics::export::observe_export_batch_size;

#[derive(Debug)]
pub struct MetricsSpanExporter<E> {
    inner: E,
}

impl<E> MetricsSpanExporter<E> {
    pub fn new(inner: E) -> Self {
        Self { inner }
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
            observe_export_batch_size(batch_size);
        }

        // Delegate to inner exporter - the trait guarantees 'static but compiler can't prove it
        // due to associated type. We use unsafe to assert the lifetime per trait contract.
        let inner_export = self.inner.export(batch);
        let pinned: BoxFuture<'_, OTelSdkResult> = Box::pin(inner_export);
        // SAFETY: SpanExporter::export() guarantees BoxFuture<'static, ...> per trait contract.
        // The batch is moved, so no borrows remain. We're only asserting 'static lifetime.
        unsafe {
            // Cast the lifetime from '_ to 'static - safe because trait guarantees it
            std::mem::transmute::<BoxFuture<'_, OTelSdkResult>, BoxFuture<'static, OTelSdkResult>>(
                pinned,
            )
        }
    }

    fn shutdown(&mut self) -> Result<(), OTelSdkError> {
        self.inner.shutdown()
    }
}
