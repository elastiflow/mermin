use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum MatchOperator {
    In,
    NotIn,
    Exists,
    DoesNotExist,
}

/// Match expression for Kubernetes label selectors
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MatchExpression {
    pub key: String,
    pub operator: MatchOperator, // "In", "NotIn", "Exists", "DoesNotExist"
    pub values: Option<Vec<String>>,
}

/// Selector for filtering which K8s resources the informer should watch
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct InformerSelector {
    /// K8s resource kind (e.g., "Pod", "Service")
    pub kind: String,
    /// Optional namespace filter
    pub namespaces: Option<Vec<String>>,
    /// Whether to include (true) or exclude (false). Defaults to true if not specified.
    pub include: Option<bool>,
    /// Optional label selector
    pub match_labels: Option<HashMap<String, String>>,
    /// Optional match expressions
    pub match_expressions: Option<Vec<MatchExpression>>,
}

/// Configuration for K8s informer discovery
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct InformerOptions {
    /// Which K8s resources to watch and cache
    pub selectors: Vec<InformerSelector>,

    /// Owner reference walking configuration
    pub owner_relations: K8sOwnerOptions,

    /// Selector-based resource relationships
    pub selector_relations: Vec<K8sObjectSelector>,
}

/// Options for discovering Kubernetes resource owners.
/// Controls which resource kinds to include/exclude and the search depth.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct K8sOwnerOptions {
    /// Kinds to exclude from owner discovery (e.g., EndpointSlice).
    pub exclude_kinds: Vec<String>,
    /// Kinds to include in owner discovery (e.g., Service).
    pub include_kinds: Vec<String>,
    /// Maximum depth to traverse owner references.
    pub max_depth: u32,
}

impl Default for K8sOwnerOptions {
    fn default() -> Self {
        Self {
            exclude_kinds: Vec::new(),
            include_kinds: Vec::new(),
            max_depth: 10,
        }
    }
}

/// Selector for a specific Kubernetes object kind.
/// Used to match and enrich resources based on label/field selectors.
#[derive(Default, Debug, Deserialize, Serialize, Clone)]
pub struct K8sObjectSelector {
    /// The kind of Kubernetes object (e.g., NetworkPolicy, Service).
    pub kind: String,
    /// Optional field for matchExpressions (e.g., spec.podSelector.matchExpressions).
    pub selector_match_expressions_field: Option<String>,
    /// Optional field for matchLabels (e.g., spec.podSelector.matchLabels).
    pub selector_match_labels_field: Option<String>,
    /// Target resource kind to associate with (e.g., Pod).
    pub to: String,
}
