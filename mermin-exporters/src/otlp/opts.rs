use opentelemetry_otlp::Protocol;

pub struct ExporterOptions {
    pub endpoint: &'static str,
    pub timeout_seconds: u64,
    pub protocol: String,
}

pub enum  ExporterProtocol  {
    Grpc,
    HttpProto,
}

impl Into<Protocol> for ExporterProtocol {
    fn into(self) -> Protocol {
        match self {
            ExporterProtocol::Grpc => Protocol::Grpc,
            ExporterProtocol::HttpProto => Protocol::HttpBinary,
        }
    }
}

impl From<String> for ExporterProtocol {
    fn from(value: String) -> Self {
        match value.to_lowercase().as_str() {
            "grpc" => ExporterProtocol::Grpc,
            "http_proto" => ExporterProtocol::HttpProto,
            _ => ExporterProtocol::Grpc,
        }
    }
}
