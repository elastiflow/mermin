use anyhow::Result;
use async_trait::async_trait;

use crate::flow::{FlowAttributes, FlowAttributesExporter};

pub struct StdoutExporter {
    pub format: String,
}

#[async_trait]
impl FlowAttributesExporter for StdoutExporter {
    async fn export(&self, attrs: FlowAttributes) {
        println!(
            "[STDOUT-EXPORTER] Format: '{}' - Processing flow: {}",
            self.format, attrs.community_id
        );

        match self.format.as_str() {
            "json" => {
                println!("[STDOUT-EXPORTER] Using JSON pretty format");
                match serde_json::to_string_pretty(&attrs) {
                    Ok(json) => println!("{json}"),
                    Err(e) => println!("Error serializing to JSON: {e}"),
                }
            }
            "json-compact" => {
                println!("[STDOUT-EXPORTER] Using JSON compact format");
                match serde_json::to_string(&attrs) {
                    Ok(json) => println!("{json}"),
                    Err(e) => println!("Error serializing to JSON: {e}"),
                }
            }
            "pretty" => {
                println!("[STDOUT-EXPORTER] Using pretty debug format");
                println!("{attrs:#?}");
            }
            _ => {
                println!("[STDOUT-EXPORTER] Using default debug format");
                println!("{attrs:?}");
            }
        }
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(()) // Nothing to shutdown for stdout
    }
}
