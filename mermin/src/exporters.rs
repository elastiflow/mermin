use anyhow::Result;
use tracing::{debug, error, info, warn};

use crate::{
    flow::{FlowAttributes, FlowAttributesExporter},
    otlp::{
        opts::{ExporterOptions, OtlpExporterOptions, StdoutExporterOptions},
        trace::lib::{TraceExporterAdapter, init_tracer_provider},
    },
};

pub mod stdout;
use stdout::StdoutExporter;

/// Represents a parsed exporter reference from the agent configuration.
/// Example: "exporter.otlp.main" -> ExporterRef { exporter_type: "otlp", name: "main" }
#[derive(Debug, Clone, PartialEq)]
pub struct ExporterRef {
    pub exporter_type: String,
    pub name: String,
}

/// Parses an exporter reference string into its components.
///
/// # Arguments
/// * `reference` - The exporter reference string (e.g., "exporter.otlp.main")
///
/// # Returns
/// * `Result<ExporterRef>` - The parsed exporter reference or an error if parsing fails
///
/// # Examples
/// ```
/// let ref_str = "exporter.otlp.main";
/// let exporter_ref = parse_exporter_reference(ref_str).unwrap();
/// assert_eq!(exporter_ref.exporter_type, "otlp");
/// assert_eq!(exporter_ref.name, "main");
/// ```
pub fn parse_exporter_reference(reference: &str) -> Result<ExporterRef, String> {
    // Expected format: "exporter.<type>.<name>"
    // Example: "exporter.otlp.main" or "exporter.stdout.json"

    let parts: Vec<&str> = reference.split('.').collect();

    if parts.len() != 3 {
        return Err(format!(
            "Invalid exporter reference format: '{reference}'. Expected format: 'exporter.<type>.<name>'"
        ));
    }

    if parts[0] != "exporter" {
        return Err(format!(
            "Invalid exporter reference: '{reference}'. Must start with 'exporter.'"
        ));
    }

    let exporter_type = parts[1].to_string();
    let name = parts[2].to_string();

    // Validate exporter type
    match exporter_type.as_str() {
        "otlp" | "stdout" => {
            // Valid exporter types
        }
        _ => {
            return Err(format!(
                "Unsupported exporter type: '{exporter_type}'. Supported types: otlp, stdout"
            ));
        }
    }

    Ok(ExporterRef {
        exporter_type,
        name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_exporter_reference_valid() {
        let result = parse_exporter_reference("exporter.otlp.main").unwrap();
        assert_eq!(result.exporter_type, "otlp");
        assert_eq!(result.name, "main");

        let result = parse_exporter_reference("exporter.stdout.json").unwrap();
        assert_eq!(result.exporter_type, "stdout");
        assert_eq!(result.name, "json");
    }

    #[test]
    fn test_parse_exporter_reference_invalid_format() {
        let result = parse_exporter_reference("invalid.format");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Invalid exporter reference format")
        );

        let result = parse_exporter_reference("exporter.otlp");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Invalid exporter reference format")
        );

        let result = parse_exporter_reference("exporter.otlp.main.extra");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Invalid exporter reference format")
        );
    }

    #[test]
    fn test_parse_exporter_reference_invalid_prefix() {
        let result = parse_exporter_reference("invalid.otlp.main");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Must start with 'exporter.'"));
    }

    #[test]
    fn test_parse_exporter_reference_unsupported_type() {
        let result = parse_exporter_reference("exporter.invalid.main");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported exporter type"));
    }
}

pub struct ExporterManager {
    exporters: Vec<Box<dyn FlowAttributesExporter>>,
}

impl ExporterManager {
    pub async fn new(
        agent_config: Option<&crate::runtime::conf::AgentOptions>,
        exporter_config: &ExporterOptions,
        log_level: tracing::Level,
    ) -> Result<Self, anyhow::Error> {
        let mut exporters: Vec<Box<dyn FlowAttributesExporter>> = Vec::new();

        // If no agent config is provided, fall back to creating all available exporters
        let enabled_exporters = if let Some(agent_config) = agent_config {
            // Parse exporter references from agent configuration
            let mut enabled_refs = Vec::new();
            for exporter_ref_str in &agent_config.traces.main.exporters {
                match parse_exporter_reference(exporter_ref_str) {
                    Ok(exporter_ref) => {
                        enabled_refs.push(exporter_ref);
                        debug!("parsed enabled exporter: {}", exporter_ref_str);
                    }
                    Err(e) => {
                        error!(
                            "failed to parse exporter reference '{}': {}",
                            exporter_ref_str, e
                        );
                        warn!("skipping invalid exporter reference: {}", exporter_ref_str);
                    }
                }
            }
            enabled_refs
        } else {
            warn!("no agent configuration provided - initializing all available exporters");
            // Fallback: create all available exporters
            let mut all_refs = Vec::new();
            if let Some(otlp_configs) = &exporter_config.otlp {
                for name in otlp_configs.keys() {
                    all_refs.push(ExporterRef {
                        exporter_type: "otlp".to_string(),
                        name: name.clone(),
                    });
                }
            }
            if let Some(stdout_configs) = &exporter_config.stdout {
                for name in stdout_configs.keys() {
                    all_refs.push(ExporterRef {
                        exporter_type: "stdout".to_string(),
                        name: name.clone(),
                    });
                }
            }
            all_refs
        };

        // Initialize only the enabled exporters
        for exporter_ref in enabled_exporters {
            match exporter_ref.exporter_type.as_str() {
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
                    error!("unsupported exporter type: {}", exporter_ref.exporter_type);
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
