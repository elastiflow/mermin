use crate::k8s::resource_parser::EnrichedInfo;

#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct EnrichedFlowData {
    pub id: String,
    pub source: Option<EnrichedInfo>,
    pub destination: Option<EnrichedInfo>,
}



