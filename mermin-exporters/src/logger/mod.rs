#[cfg(feature = "logger")]
pub mod lib {
    use env_logger;
    use async_trait::async_trait;
    use mermincore::flow::base::EnrichedFlowData;
    use mermincore::flow::exporter::FlowExporter;

    /// An adapter that implements the FlowExporter by logging the flow data.
    /// This is useful for local development, debugging, or as a default exporter.
    pub struct LoggingExporterAdapter;

    impl LoggingExporterAdapter {
        pub fn new() -> Self {
            env_logger::Builder::from_default_env()
                .target(env_logger::Target::Stdout)
                .init();
            Self
        }
    }

    impl Default for LoggingExporterAdapter {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl FlowExporter for LoggingExporterAdapter {
        async fn export_flow(&self, packet: anyhow::Result<EnrichedFlowData>) {
            tracing::log::info!("Enriched packet: {packet:?}");
        }

        async fn shutdown(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

}

