use std::sync::Arc;

use anyhow::Result;

use crate::{
    flow::{FlowAttributes, FlowAttributesExporter},
    otlp::{
        opts::{ExporterConf, ExporterSpecificConfig, ExporterType},
        trace::lib::{TraceExporterAdapter, init_tracer_provider},
    },
};

pub mod stdout;
use stdout::StdoutExporter;

pub struct ExporterManager {
    exporters: Vec<Arc<dyn FlowAttributesExporter>>,
}

impl ExporterManager {
    pub async fn new(
        configs: Vec<ExporterConf>,
        log_level: tracing::Level,
    ) -> Result<Self, anyhow::Error> {
        let mut exporters = Vec::new();

        println!(
            "[EXPORTER-MANAGER-NEW] Initializing with {} configurations",
            configs.len()
        );

        for config in configs {
            match config.exporter_type {
                ExporterType::Otlp => {
                    println!(
                        "[EXPORTER-MANAGER-NEW] Creating OTLP exporter for: {}",
                        config.name
                    );
                    match create_otlp_exporter(&config.config, log_level).await {
                        Ok(exporter) => {
                            exporters.push(exporter);
                            println!(
                                "[EXPORTER-MANAGER-NEW] Successfully created exporter: {}",
                                config.name
                            );
                        }
                        Err(e) => {
                            println!(
                                "[EXPORTER-MANAGER-NEW] Failed to create exporter {}: {}",
                                config.name, e
                            );
                        }
                    }
                }
                ExporterType::Stdout => {
                    println!(
                        "[EXPORTER-MANAGER-NEW] Creating Stdout exporter for: {}",
                        config.name
                    );
                    match create_stdout_exporter(&config.config) {
                        Ok(exporter) => {
                            exporters.push(exporter);
                            println!(
                                "[EXPORTER-MANAGER-NEW] Successfully created exporter: {}",
                                config.name
                            );
                        }
                        Err(e) => {
                            println!(
                                "[EXPORTER-MANAGER-NEW] Failed to create exporter {}: {}",
                                config.name, e
                            );
                        }
                    }
                }
            };
        }

        println!(
            "[EXPORTER-MANAGER-NEW] Initialized with {} active exporters",
            exporters.len()
        );
        Ok(Self { exporters })
    }

    pub async fn export(&self, attrs: FlowAttributes) {
        println!(
            "[EXPORTER-MANAGER-EXPORT] Exporting flow attributes to {} exporters",
            self.exporters.len()
        );

        // Fan out to all exporters concurrently
        let futures = self
            .exporters
            .iter()
            .map(|exporter| exporter.export(attrs.clone()));

        futures::future::join_all(futures).await;
        println!("[EXPORTER-MANAGER-EXPORT] All exporters completed processing");
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
    config: &ExporterSpecificConfig,
    log_level: tracing::Level,
) -> Result<Arc<dyn FlowAttributesExporter>, anyhow::Error> {
    match config {
        ExporterSpecificConfig::Otlp {
            endpoint,
            timeout_seconds,
            protocol,
            auth,
            ..
        } => {
            println!(
                "[CREATE-OTLP-EXPORTER] Creating OTLP exporter with endpoint: '{endpoint}', timeout: '{timeout_seconds}', protocol: '{protocol}'"
            );

            // TODO: Log authentication configuration (without exposing credentials)
            if let Some(auth_config) = auth {
                match auth_config {
                    crate::otlp::opts::AuthConfig::Basic { .. } => {
                        println!("[CREATE-OTLP-EXPORTER] Using basic authentication");
                    }
                    crate::otlp::opts::AuthConfig::Bearer { .. } => {
                        println!("[CREATE-OTLP-EXPORTER] Using bearer token authentication");
                    }
                    crate::otlp::opts::AuthConfig::ApiKey { key, .. } => {
                        println!(
                            "[CREATE-OTLP-EXPORTER] Using API key authentication with key: '{key}'"
                        );
                    }
                }
            } else {
                println!("[CREATE-OTLP-EXPORTER] No authentication configured");
            }

            let provider = init_tracer_provider(config.clone(), log_level).await?;
            let exporter = TraceExporterAdapter::new(provider);

            Ok(Arc::new(exporter))
        }
        _ => Err(anyhow::anyhow!("Invalid config type for OTLP exporter")),
    }
}

fn create_stdout_exporter(
    config: &ExporterSpecificConfig,
) -> Result<Arc<dyn FlowAttributesExporter>, anyhow::Error> {
    match config {
        ExporterSpecificConfig::Stdout { format } => {
            println!("[CREATE-STDOUT-EXPORTER] Creating stdout exporter with format: '{format}'",);
            let exporter = StdoutExporter {
                format: format.clone(),
            };
            println!("[CREATE-STDOUT-EXPORTER] Stdout exporter created successfully");
            Ok(Arc::new(exporter))
        }
        _ => Err(anyhow::anyhow!("Invalid config type for stdout exporter")),
    }
}
