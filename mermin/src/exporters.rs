use anyhow::Result;
use tracing::{debug, error, info, warn};

use crate::{
    flow::{FlowAttributes, FlowAttributesExporter},
    otlp::{
        opts::{ExporterOptions, OtlpExporterOptions, StdoutExporterOptions, build_endpoint},
        trace::lib::{TraceExporterAdapter, init_tracer_provider},
    },
};

pub mod stdout;
use stdout::StdoutExporter;

pub struct ExporterManager {
    exporters: Vec<Box<dyn FlowAttributesExporter>>,
}

impl ExporterManager {
    pub async fn new(
        config: ExporterOptions,
        log_level: tracing::Level,
    ) -> Result<Self, anyhow::Error> {
        let mut exporters: Vec<Box<dyn FlowAttributesExporter>> = Vec::new();

        // Initialize OTLP exporters
        if let Some(otlp_configs) = &config.otlp {
            for (name, otlp_config) in otlp_configs {
                debug!("creating otlp exporter for: {}", name);
                match create_otlp_exporter(otlp_config, log_level).await {
                    Ok(exporter) => {
                        exporters.push(exporter);
                        debug!("successfully created exporter: {}", name);
                    }
                    Err(e) => {
                        error!("failed to create exporter {}: {}", name, e);
                        // Continue processing other exporters instead of failing completely
                        warn!("skipping OTLP exporter '{}' due to error", name);
                    }
                }
            }
        }

        // Initialize STDOUT exporters
        if let Some(stdout_configs) = &config.stdout {
            for (name, stdout_config) in stdout_configs {
                debug!("creating stdout exporter for: {}", name);
                match create_stdout_exporter(stdout_config) {
                    Ok(exporter) => {
                        exporters.push(exporter);
                        debug!("successfully created exporter: {}", name);
                    }
                    Err(e) => {
                        error!("failed to create exporter {}: {}", name, e);
                    }
                }
            }
        }

        info!("initialized with {} active exporters", exporters.len());

        if exporters.is_empty() {
            warn!("no exporters were successfully initialized");
        }

        Ok(Self { exporters })
    }

    pub async fn export(&self, attrs: FlowAttributes) {
        info!(
            "exporting flow attributes to {} exporters",
            self.exporters.len()
        );

        // Fan out to all exporters concurrently
        let futures = self
            .exporters
            .iter()
            .map(|exporter| exporter.export(attrs.clone()));

        futures::future::join_all(futures).await;
        info!("all exporters completed processing");
    }

    pub async fn shutdown(&self) -> Result<(), anyhow::Error> {
        let futures = self.exporters.iter().map(|exporter| exporter.shutdown());

        let results = futures::future::join_all(futures).await;

        // Handle any shutdown errors
        for result in results {
            if let Err(e) = result {
                error!("error during exporter shutdown: {}", e);
            }
        }

        Ok(())
    }
}

// Exporter creation functions
async fn create_otlp_exporter(
    config: &OtlpExporterOptions,
    log_level: tracing::Level,
) -> Result<Box<dyn FlowAttributesExporter>, anyhow::Error> {
    let endpoint = build_endpoint(&config.address, config.port);

    info!(
        "creating otlp exporter with endpoint: '{endpoint}', port: '{}'",
        config.port
    );

    // TODO: Log authentication configuration (without exposing credentials) - ENG-120
    if let Some(auth_config) = &config.auth {
        if auth_config.basic.is_some() {
            debug!("using basic authentication");
        }
        // TODO: Add support for other auth methods - ENG-120
    } else {
        debug!("no authentication configured");
    }

    // TODO: Log TLS configuration (without exposing credentials) - ENG-120
    if let Some(tls_config) = &config.tls {
        if tls_config.enabled {
            debug!("TLS enabled for OTLP exporter");
            if tls_config.insecure {
                warn!("TLS insecure mode enabled - this is not recommended for production");
            }
        }
    } else {
        debug!("no TLS configuration - using default settings");
    }

    let provider = init_tracer_provider(config, log_level).await?;
    let exporter = TraceExporterAdapter::new(provider);

    Ok(Box::new(exporter))
}

fn create_stdout_exporter(
    config: &StdoutExporterOptions,
) -> Result<Box<dyn FlowAttributesExporter>, anyhow::Error> {
    debug!("creating stdout exporter with format: '{}'", config.format);
    let exporter = StdoutExporter {
        format: config.format.clone(),
    };
    debug!("stdout exporter created successfully");
    Ok(Box::new(exporter))
}
