use anyhow::Result;

use crate::{
    flow::{FlowAttributes, FlowAttributesExporter},
    otlp::{
        opts::{ExporterOption, ExporterSpecificOptions, ExporterType},
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
        configs: Vec<ExporterOption>,
        log_level: tracing::Level,
    ) -> Result<Self, anyhow::Error> {
        let mut exporters: Vec<Box<dyn FlowAttributesExporter>> = Vec::new();

        tracing::info!(
            "[EXPORTER-MANAGER-NEW] Initializing with {} configurations",
            configs.len()
        );

        for config in configs {
            match config.exporter_type {
                ExporterType::Otlp => {
                    tracing::info!(
                        "[EXPORTER-MANAGER-NEW] Creating OTLP exporter for: {}",
                        config.name
                    );
                    match create_otlp_exporter(&config.config, log_level).await {
                        Ok(exporter) => {
                            exporters.push(exporter);
                            tracing::info!(
                                "[EXPORTER-MANAGER-NEW] Successfully created exporter: {}",
                                config.name
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                "[EXPORTER-MANAGER-NEW] Failed to create exporter {}: {}",
                                config.name,
                                e
                            );
                            return Err(anyhow::anyhow!(
                                "Failed to create exporter {}: {}",
                                config.name,
                                e
                            ));
                        }
                    }
                }
                ExporterType::Stdout => {
                    tracing::info!(
                        "[EXPORTER-MANAGER-NEW] Creating Stdout exporter for: {}",
                        config.name
                    );
                    match create_stdout_exporter(&config.config) {
                        Ok(exporter) => {
                            exporters.push(exporter);
                            tracing::info!(
                                "[EXPORTER-MANAGER-NEW] Successfully created exporter: {}",
                                config.name
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                "[EXPORTER-MANAGER-NEW] Failed to create exporter {}: {}",
                                config.name,
                                e
                            );
                        }
                    }
                }
            };
        }

        tracing::info!(
            "[EXPORTER-MANAGER-NEW] Initialized with {} active exporters",
            exporters.len()
        );
        Ok(Self { exporters })
    }

    pub async fn export(&self, attrs: FlowAttributes) {
        tracing::info!(
            "[EXPORTER-MANAGER-EXPORT] Exporting flow attributes to {} exporters",
            self.exporters.len()
        );

        // Fan out to all exporters concurrently
        let futures = self
            .exporters
            .iter()
            .map(|exporter| exporter.export(attrs.clone()));

        futures::future::join_all(futures).await;
        tracing::info!("[EXPORTER-MANAGER-EXPORT] All exporters completed processing");
    }

    pub async fn shutdown(&self) -> Result<(), anyhow::Error> {
        let futures = self.exporters.iter().map(|exporter| exporter.shutdown());

        let results = futures::future::join_all(futures).await;

        // Handle any shutdown errors
        for result in results {
            if let Err(e) = result {
                tracing::error!("Error during exporter shutdown: {}", e);
            }
        }

        Ok(())
    }
}

// Exporter creation functions
async fn create_otlp_exporter(
    config: &ExporterSpecificOptions,
    log_level: tracing::Level,
) -> Result<Box<dyn FlowAttributesExporter>, anyhow::Error> {
    match config {
        ExporterSpecificOptions::Otlp {
            endpoint,
            timeout_seconds,
            protocol,
            auth,
            ..
        } => {
            tracing::info!(
                "[CREATE-OTLP-EXPORTER] Creating OTLP exporter with endpoint: '{endpoint}', timeout: '{timeout_seconds}', protocol: '{protocol}'"
            );

            // TODO: Log authentication configuration (without exposing credentials) - ENG-120
            if let Some(auth_config) = auth {
                match auth_config {
                    crate::otlp::opts::AuthConfig::Basic { .. } => {
                        tracing::info!("[CREATE-OTLP-EXPORTER] Using basic authentication");
                    }
                    crate::otlp::opts::AuthConfig::Bearer { .. } => {
                        tracing::info!("[CREATE-OTLP-EXPORTER] Using bearer token authentication");
                    }
                    crate::otlp::opts::AuthConfig::ApiKey { key, .. } => {
                        tracing::info!(
                            "[CREATE-OTLP-EXPORTER] Using API key authentication with key: '{key}'"
                        );
                    }
                }
            } else {
                tracing::info!("[CREATE-OTLP-EXPORTER] No authentication configured");
            }

            let provider = init_tracer_provider(config.clone(), log_level).await?;
            let exporter = TraceExporterAdapter::new(provider);

            Ok(Box::new(exporter))
        }
        _ => Err(anyhow::anyhow!("Invalid config type for OTLP exporter")),
    }
}

fn create_stdout_exporter(
    config: &ExporterSpecificOptions,
) -> Result<Box<dyn FlowAttributesExporter>, anyhow::Error> {
    match config {
        ExporterSpecificOptions::Stdout { format } => {
            tracing::info!(
                "[CREATE-STDOUT-EXPORTER] Creating stdout exporter with format: '{format}'",
            );
            let exporter = StdoutExporter {
                format: format.clone(),
            };
            tracing::info!("[CREATE-STDOUT-EXPORTER] Stdout exporter created successfully");
            Ok(Box::new(exporter))
        }
        _ => Err(anyhow::anyhow!("Invalid config type for stdout exporter")),
    }
}
