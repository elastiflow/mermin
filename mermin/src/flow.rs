use crate::k8s::{EnrichedInfo, resource_parser::NetworkPolicy};

#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct EnrichedFlowData {
    pub id: String,
    pub src: Option<EnrichedInfo>,
    pub dst: Option<EnrichedInfo>,
    pub network_policies: Option<Vec<NetworkPolicy>>,
}

/// Flow direction for policy evaluation
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FlowDirection {
    Ingress,
    Egress,
}
