use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{
    k8s::{
        owner_relations::OwnerRelationsRules,
        selector::{Selectors, default_selectors},
        selector_relations::SelectorRelationRule,
    },
    runtime::conf::conf_serde::duration,
};

/// Kubernetes informer configuration
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct K8sInformerOptions {
    /// Path to kubeconfig file for API server connection.
    /// Empty string uses in-cluster config (default for pods).
    pub kubeconfig_path: String,
    /// Timeout for initial informer synchronization.
    /// Mermin won't be ready until sync completes.
    /// Large clusters may need longer timeout.
    #[serde(with = "duration")]
    pub informers_sync_timeout: Duration,
    /// Owner relations configuration
    pub owner_relations: Option<OwnerRelationsRules>,
    /// Which K8s resources to watch and cache
    /// Defaults to standard workload and network resources if not provided
    #[serde(default = "default_selectors")]
    pub selectors: Vec<Selectors>,
    /// Selector-based resource relations configuration
    ///
    /// If None or an empty list, selector-based matching is disabled.
    /// Rules are required for selector matching to function.
    pub selector_relations: Option<Vec<SelectorRelationRule>>,
}

impl Default for K8sInformerOptions {
    fn default() -> Self {
        Self {
            kubeconfig_path: String::new(),
            informers_sync_timeout: Duration::from_secs(30),
            owner_relations: None,
            selectors: default_selectors(),
            selector_relations: None,
        }
    }
}
