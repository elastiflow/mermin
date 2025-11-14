use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{
    k8s::{owner_relations::OwnerRelationsRules, selector_relations::SelectorRelationRule},
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
    /// Period between full cache resyncs from API server.
    /// Helps recover from potential drift between cache and actual state.
    #[serde(with = "duration")]
    pub informers_resync_period: Duration,
    /// Owner relations configuration
    pub owner_relations: Option<OwnerRelationsRules>,
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
            informers_resync_period: Duration::from_secs(5),
            owner_relations: None,
            selector_relations: None,
        }
    }
}
