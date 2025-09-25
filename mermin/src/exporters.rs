use anyhow::Result;
use stdout::StdoutExporter;
use tracing::{debug, error, info, warn};

use crate::{
    flow::{FlowAttributes, FlowAttributesExporter},
    otlp::{
        opts::{ExporterOptions, OtlpExporterOptions, StdoutExporterOptions},
        trace::lib::{TraceExporterAdapter, init_tracer_provider},
    },
    runtime::conf::{ExporterReferences, ExporterReferencesParser},
};

pub struct ExporterResolver {
    exporters: Vec<Box<dyn FlowAttributesExporter>>,
}

impl ExporterResolver {
    pub async fn new(
        exporter_refs: ExporterReferences,
        exporter_config: &ExporterOptions,
        log_level: tracing::Level,
    ) -> Result<Self, anyhow::Error> {
        if exporter_refs.is_empty() {
            warn!("no exporters enabled in agent configuration");
            return Ok(Self {
                exporters: Vec::new(),
            });
        }

        let enabled_exporters = exporter_refs.parse().map_err(|e| anyhow::anyhow!(e))?;
        let mut exporters: Vec<Box<dyn FlowAttributesExporter>> = Vec::new();

        // Initialize only the enabled exporters
        for exporter_ref in enabled_exporters {
            match exporter_ref.type_.as_str() {
                "otlp" => {
                    if let Some(otlp_configs) = &exporter_config.otlp {
                        if let Some(otlp_config) = otlp_configs.get(&exporter_ref.name) {
                            debug!("creating otlp exporter for: {}", exporter_ref.name);
                            match create_otlp_exporter(otlp_config, log_level).await {
                                Ok(exporter) => {
                                    exporters.push(exporter);
                                    debug!("successfully created exporter: {}", exporter_ref.name);
                                }
                                Err(e) => {
                                    error!(
                                        "failed to create exporter {}: {}",
                                        exporter_ref.name, e
                                    );
                                    warn!(
                                        "skipping OTLP exporter '{}' due to error",
                                        exporter_ref.name
                                    );
                                }
                            }
                        } else {
                            error!(
                                "OTLP exporter '{}' referenced in agent config but not found in exporter config",
                                exporter_ref.name
                            );
                        }
                    } else {
                        error!(
                            "OTLP exporter '{}' referenced in agent config but no OTLP exporters configured",
                            exporter_ref.name
                        );
                    }
                }
                "stdout" => {
                    if let Some(stdout_configs) = &exporter_config.stdout {
                        if let Some(stdout_config) = stdout_configs.get(&exporter_ref.name) {
                            debug!("creating stdout exporter for: {}", exporter_ref.name);
                            match create_stdout_exporter(stdout_config) {
                                Ok(exporter) => {
                                    exporters.push(exporter);
                                    debug!("successfully created exporter: {}", exporter_ref.name);
                                }
                                Err(e) => {
                                    error!(
                                        "failed to create exporter {}: {}",
                                        exporter_ref.name, e
                                    );
                                }
                            }
                        } else {
                            error!(
                                "STDOUT exporter '{}' referenced in agent config but not found in exporter config",
                                exporter_ref.name
                            );
                        }
                    } else {
                        error!(
                            "STDOUT exporter '{}' referenced in agent config but no STDOUT exporters configured",
                            exporter_ref.name
                        );
                    }
                }
                _ => {
                    error!("unsupported exporter type: {}", exporter_ref.type_);
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
    let endpoint = config.build_endpoint();

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
