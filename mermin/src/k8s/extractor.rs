use jsonpath_rust::JsonPath;
use k8s_openapi::api::{
    core::v1::{Node, Pod, Service},
    discovery::v1::EndpointSlice,
    networking::v1::Ingress,
};
use kube::{Resource, ResourceExt};
use serde_json::Value;
use tracing::debug;

#[derive(Debug, Clone)]
pub enum K8sAccessor {
    PodIp,
    PodIps,
    HostIp,
    HostIps,
    NodeInternalIp,
    ServiceClusterIp,
    ServiceClusterIps,
    ServiceExternalIps,
    ServiceLoadBalancerIp,
    ServiceExternalName,
    Annotation(String),
    Label(String),
    JsonPath(String),
}

impl K8sAccessor {
    pub fn parse(path: &str) -> Self {
        match path {
            "status.podIP" => Self::PodIp,
            "status.podIPs[*]" => Self::PodIps,
            "status.hostIP" => Self::HostIp,
            "status.hostIPs[*]" => Self::HostIps,
            "status.addresses[*].address" => Self::NodeInternalIp,
            "spec.clusterIP" => Self::ServiceClusterIp,
            "spec.clusterIPs[*]" => Self::ServiceClusterIps,
            "spec.externalIPs[*]" => Self::ServiceExternalIps,
            "spec.loadBalancerIP" => Self::ServiceLoadBalancerIp,
            "spec.externalName" => Self::ServiceExternalName,
            _ if path.starts_with("metadata.annotations['") => {
                let key = path
                    .strip_prefix("metadata.annotations['")
                    .and_then(|s| s.strip_suffix("']"))
                    .unwrap_or("");
                Self::Annotation(key.to_string())
            }
            _ if path.starts_with("metadata.labels['") => {
                let key = path
                    .strip_prefix("metadata.labels['")
                    .and_then(|s| s.strip_suffix("']"))
                    .unwrap_or("");
                Self::Label(key.to_string())
            }
            _ => Self::JsonPath(format!("$.{path}")),
        }
    }

    pub fn is_hostname(&self) -> bool {
        matches!(self, Self::ServiceExternalName)
            || matches!(self, Self::JsonPath(p) if p.contains("hostname") || p.contains("externalName"))
    }
}

fn extract_common<K: Resource + serde::Serialize>(
    resource: &K,
    accessor: &K8sAccessor,
    json_cache: &mut Option<Value>,
) -> Option<Vec<String>> {
    match accessor {
        K8sAccessor::Annotation(key) => Some(
            resource
                .annotations()
                .get(key)
                .cloned()
                .into_iter()
                .collect(),
        ),
        K8sAccessor::Label(key) => Some(resource.labels().get(key).cloned().into_iter().collect()),
        K8sAccessor::JsonPath(jp) => Some(extract_via_jsonpath(resource, jp, json_cache)),
        _ => None,
    }
}

fn extract_via_jsonpath<K: serde::Serialize>(
    resource: &K,
    jp_str: &str,
    json_cache: &mut Option<Value>,
) -> Vec<String> {
    let json = match json_cache {
        Some(val) => val,
        None => match serde_json::to_value(resource) {
            Ok(val) => json_cache.insert(val),
            Err(e) => {
                debug!(
                    event.name = "k8s.decorator.serialization_failed",
                    error.message = %e,
                    "failed to serialize resource to json for extraction"
                );
                return vec![];
            }
        },
    };

    match json.query(jp_str) {
        Ok(results) => results
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        Err(e) => {
            debug!(
                event.name = "k8s.decorator.value_extraction_failed",
                k8s.jsonpath.expression = %jp_str,
                error.message = %e,
                "failed to extract values for configured jsonpath"
            );
            vec![]
        }
    }
}

pub trait K8sMetadataExt {
    fn extract(&self, accessor: &K8sAccessor, json_cache: &mut Option<Value>) -> Vec<String>;
}

impl K8sMetadataExt for Pod {
    fn extract(&self, accessor: &K8sAccessor, json_cache: &mut Option<Value>) -> Vec<String> {
        match accessor {
            K8sAccessor::PodIp => self
                .status
                .as_ref()
                .and_then(|s| s.pod_ip.clone())
                .into_iter()
                .collect(),
            K8sAccessor::PodIps => self
                .status
                .as_ref()
                .and_then(|s| s.pod_ips.as_ref())
                .into_iter()
                .flatten()
                .map(|ip_obj| ip_obj.ip.clone())
                .collect(),
            K8sAccessor::HostIp => self
                .status
                .as_ref()
                .and_then(|s| s.host_ip.clone())
                .into_iter()
                .collect(),
            K8sAccessor::HostIps => self
                .status
                .as_ref()
                .and_then(|s| s.host_ips.as_ref())
                .into_iter()
                .flatten()
                .map(|ip_obj| ip_obj.ip.clone())
                .collect(),
            _ => extract_common(self, accessor, json_cache).unwrap_or_default(),
        }
    }
}

impl K8sMetadataExt for Node {
    fn extract(&self, accessor: &K8sAccessor, json_cache: &mut Option<Value>) -> Vec<String> {
        match accessor {
            K8sAccessor::NodeInternalIp => self
                .status
                .as_ref()
                .and_then(|s| s.addresses.as_ref())
                .into_iter()
                .flatten()
                .filter(|a| a.type_ == "InternalIP")
                .map(|a| a.address.clone())
                .collect(),
            _ => extract_common(self, accessor, json_cache).unwrap_or_default(),
        }
    }
}

impl K8sMetadataExt for Service {
    fn extract(&self, accessor: &K8sAccessor, json_cache: &mut Option<Value>) -> Vec<String> {
        match accessor {
            K8sAccessor::ServiceClusterIp => self
                .spec
                .as_ref()
                .and_then(|s| s.cluster_ip.clone())
                .into_iter()
                .collect(),
            K8sAccessor::ServiceClusterIps => self
                .spec
                .as_ref()
                .and_then(|s| s.cluster_ips.clone())
                .unwrap_or_default(),
            K8sAccessor::ServiceExternalIps => self
                .spec
                .as_ref()
                .and_then(|s| s.external_ips.clone())
                .unwrap_or_default(),
            K8sAccessor::ServiceLoadBalancerIp => self
                .spec
                .as_ref()
                .and_then(|s| s.load_balancer_ip.clone())
                .into_iter()
                .collect(),
            K8sAccessor::ServiceExternalName => self
                .spec
                .as_ref()
                .and_then(|s| s.external_name.clone())
                .into_iter()
                .collect(),
            _ => extract_common(self, accessor, json_cache).unwrap_or_default(),
        }
    }
}

impl K8sMetadataExt for Ingress {
    fn extract(&self, accessor: &K8sAccessor, json_cache: &mut Option<Value>) -> Vec<String> {
        extract_common(self, accessor, json_cache).unwrap_or_default()
    }
}

impl K8sMetadataExt for EndpointSlice {
    fn extract(&self, accessor: &K8sAccessor, json_cache: &mut Option<Value>) -> Vec<String> {
        extract_common(self, accessor, json_cache).unwrap_or_default()
    }
}

pub fn is_hostname_accessor(accessor: &K8sAccessor) -> bool {
    accessor.is_hostname()
}
