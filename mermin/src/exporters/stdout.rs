use anyhow::Result;
use async_trait::async_trait;
use tracing::{debug, error, info};

use crate::flow::{FlowAttributes, FlowAttributesExporter};

pub struct StdoutExporter {
    pub format: String,
}

#[async_trait]
impl FlowAttributesExporter for StdoutExporter {
    async fn export(&self, attrs: FlowAttributes) {
        info!(
            "format: '{}' - Processing flow: {}",
            self.format, attrs.community_id
        );

        match self.format.as_str() {
            "json" | "full" => {
                debug!("using json pretty format");
                match serde_json::to_string_pretty(&attrs) {
                    Ok(json) => println!("{json}"),
                    Err(e) => error!("error serializing to json: {e}"),
                }
            }
            "json-compact" | "compact" => {
                debug!("using json compact format");
                match serde_json::to_string(&attrs) {
                    Ok(json) => println!("{json}"),
                    Err(e) => error!("error serializing to json: {e}"),
                }
            }
            "pretty" => {
                debug!("using pretty debug format");
                println!("{attrs:#?}");
            }
            _ => {
                debug!("using default debug format for format: '{}'", self.format);
                println!("{attrs:?}");
            }
        }
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(()) // Nothing to shutdown for stdout
    }
}
