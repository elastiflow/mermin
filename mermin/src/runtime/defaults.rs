use std::collections::HashMap;

use crate::runtime::conf::{
    AssociationBlock, AssociationSource, AttributesConf, ExtractConf, ObjectAssociationRule,
};

/// Creates the default Kubernetes attribution configuration.
/// This enables pod, service, and node enrichment out-of-the-box.
pub fn default_attributes() -> HashMap<String, HashMap<String, AttributesConf>> {
    let source_conf = create_k8s_attributes_conf("source");
    let dest_conf = create_k8s_attributes_conf("destination");

    HashMap::from([
        (
            "source".to_string(),
            HashMap::from([("k8s".to_string(), source_conf)]),
        ),
        (
            "destination".to_string(),
            HashMap::from([("k8s".to_string(), dest_conf)]),
        ),
    ])
}

/// Helper to create an `AttributesConf` for a given flow direction ("source" or "destination").
fn create_k8s_attributes_conf(direction: &str) -> AttributesConf {
    let ip_attr_name = format!("{direction}.ip");
    let port_attr_name = format!("{direction}.port");

    AttributesConf {
        extract: ExtractConf {
            metadata: vec![
                "[*].metadata.name".to_string(),
                "[*].metadata.namespace".to_string(),
                "[*].metadata.uid".to_string(),
            ],
        },
        association: AssociationBlock {
            pod: Some(ObjectAssociationRule {
                sources: vec![
                    AssociationSource {
                        from: "flow".to_string(),
                        name: ip_attr_name.clone(),
                        to: vec![
                            "status.podIP".to_string(),
                            "status.podIPs[*]".to_string(),
                            "status.hostIP".to_string(),
                            "status.hostIPs[*]".to_string(),
                        ],
                    },
                    AssociationSource {
                        from: "flow".to_string(),
                        name: port_attr_name.clone(),
                        to: vec![
                            "spec.containers[*].ports[*].containerPort".to_string(),
                            "spec.containers[*].ports[*].hostPort".to_string(),
                        ],
                    },
                    AssociationSource {
                        from: "flow".to_string(),
                        name: "network.transport".to_string(),
                        to: vec!["spec.containers[*].ports[*].protocol".to_string()],
                    },
                ],
            }),
            service: Some(ObjectAssociationRule {
                sources: vec![
                    AssociationSource {
                        from: "flow".to_string(),
                        name: ip_attr_name.clone(),
                        to: vec![
                            "spec.clusterIP".to_string(),
                            "spec.clusterIPs[*]".to_string(),
                            "spec.externalIPs[*]".to_string(),
                            "spec.loadBalancerIP".to_string(),
                        ],
                    },
                    AssociationSource {
                        from: "flow".to_string(),
                        name: port_attr_name.clone(),
                        to: vec!["spec.ports[*].port".to_string()],
                    },
                    AssociationSource {
                        from: "flow".to_string(),
                        name: "network.transport".to_string(),
                        to: vec!["spec.ports[*].protocol".to_string()],
                    },
                ],
            }),
            node: Some(ObjectAssociationRule {
                sources: vec![AssociationSource {
                    from: "flow".to_string(),
                    name: ip_attr_name.clone(),
                    to: vec!["status.addresses[*].address".to_string()],
                }],
            }),
            endpoint: Some(ObjectAssociationRule {
                sources: vec![AssociationSource {
                    from: "flow".to_string(),
                    name: ip_attr_name,
                    to: vec!["endpoints[*].addresses[*]".to_string()],
                }],
            }),
            ..Default::default()
        },
    }
}
