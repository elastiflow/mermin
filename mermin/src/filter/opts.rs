use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FilteringOptions {
    pub address: Option<FilteringPair>,
    pub port: Option<FilteringPair>,
    pub transport: Option<FilteringPair>,
    #[serde(rename = "type")]
    pub type_: Option<FilteringPair>,
    pub interface_name: Option<FilteringPair>,
    pub interface_index: Option<FilteringPair>,
    pub interface_mac: Option<FilteringPair>,
    pub connection_state: Option<FilteringPair>,
    pub ip_dscp_name: Option<FilteringPair>,
    pub ip_ecn_name: Option<FilteringPair>,
    pub ip_ttl: Option<FilteringPair>,
    pub ip_flow_label: Option<FilteringPair>,
    pub icmp_type_name: Option<FilteringPair>,
    pub icmp_code_name: Option<FilteringPair>,
    pub tcp_flags: Option<FilteringPair>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FilteringPair {
    #[serde(default, rename = "match")]
    pub match_glob: String,
    #[serde(default, rename = "not_match")]
    pub not_match_glob: String,
}
