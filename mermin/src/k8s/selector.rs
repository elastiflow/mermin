use std::collections::{BTreeMap, HashMap, HashSet};

use kube::{Resource, ResourceExt};
use serde::{Deserialize, Serialize};

/// Selector for filtering which K8s resources the informer should watch
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Selectors {
    /// K8s resource kind (e.g., "Pod", "Service")
    pub kind: String,
    /// Optional namespace filter
    pub namespaces: Option<Vec<String>>,

    /// Optional label selector
    pub match_labels: Option<HashMap<String, String>>,
    /// Optional match expressions
    pub match_expressions: Option<Vec<MatchExpression>>,
}

impl Selectors {
    pub fn new(kind: &str) -> Self {
        Self {
            kind: kind.to_string(),
            namespaces: None,
            match_labels: None,
            match_expressions: None,
        }
    }

    /// Determines if a specific Kubernetes resource matches this selector rule.
    pub fn matches<K>(&self, resource: &K) -> bool
    where
        K: Resource,
    {
        if let Some(allowed_ns) = &self.namespaces
            && !allowed_ns.is_empty()
        {
            match resource.meta().namespace.as_deref() {
                Some(ns) => {
                    if !allowed_ns.contains(&ns.to_string()) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        let resource_labels = resource.labels();

        if let Some(required_labels) = &self.match_labels {
            for (k, v) in required_labels {
                if resource_labels.get(k) != Some(v) {
                    return false;
                }
            }
        }

        if let Some(expressions) = &self.match_expressions {
            for expr in expressions {
                if !expr.matches(resource_labels) {
                    return false;
                }
            }
        }

        true
    }
}

pub fn default_selectors() -> Vec<Selectors> {
    vec![
        // Core resources
        Selectors::new("Service"),
        Selectors::new("EndpointSlice"),
        Selectors::new("Pod"),
        // Workload controllers
        Selectors::new("ReplicaSet"),
        Selectors::new("Deployment"),
        Selectors::new("DaemonSet"),
        Selectors::new("StatefulSet"),
        Selectors::new("Job"),
        Selectors::new("CronJob"),
        // Network resources
        Selectors::new("NetworkPolicy"),
        Selectors::new("Ingress"),
        Selectors::new("Gateway"),
    ]
}

/// Merges user-provided selectors with the defaults.
pub fn merge_with_defaults(user_selectors: Vec<Selectors>) -> Vec<Selectors> {
    if user_selectors.is_empty() {
        return default_selectors();
    }

    let mut defaults = default_selectors();
    let user_kinds: HashSet<String> = user_selectors
        .iter()
        .map(|s| s.kind.to_lowercase())
        .collect();

    defaults.retain(|s| !user_kinds.contains(&s.kind.to_lowercase()));

    defaults.extend(user_selectors);

    defaults
}

/// Match expression for Kubernetes label selectors
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MatchExpression {
    pub key: String,
    pub operator: Operator,
    pub values: Option<Vec<String>>,
}

impl MatchExpression {
    pub fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        let label_value = labels.get(&self.key);

        match self.operator {
            Operator::In => {
                let Some(values) = &self.values else {
                    return false;
                };
                match label_value {
                    Some(v) => values.contains(v),
                    None => false,
                }
            }
            Operator::NotIn => {
                let Some(values) = &self.values else {
                    return true;
                };
                match label_value {
                    Some(v) => !values.contains(v),
                    None => true,
                }
            }
            Operator::Exists => label_value.is_some(),
            Operator::DoesNotExist => label_value.is_none(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum Operator {
    In,
    NotIn,
    Exists,
    DoesNotExist,
}

#[derive(Debug, Clone)]
pub struct ResourceFilter {
    /// Map of Lowercase Kind -> List of Rules
    rules: HashMap<String, Vec<Selectors>>,
}

impl ResourceFilter {
    pub fn new(user_selectors: Vec<Selectors>) -> Self {
        let merged = merge_with_defaults(user_selectors);
        let mut rules: HashMap<String, Vec<Selectors>> = HashMap::new();

        for selector in merged {
            let key = selector.kind.to_lowercase();
            rules.entry(key).or_default().push(selector);
        }

        Self { rules }
    }

    /// Checks if a resource is allowed based on the configured selectors.
    ///
    /// Logic:
    /// 1. If no rules exist for this Kind, return FALSE (Whitelist).
    /// 2. If rules exist, the resource must match ANY of the rules for that Kind (OR logic).
    pub fn is_allowed<K>(&self, resource: &K) -> bool
    where
        K: Resource,
        K::DynamicType: Default,
    {
        let kind = K::kind(&Default::default()).to_string().to_lowercase();

        let Some(kind_rules) = self.rules.get(&kind) else {
            return false;
        };

        for rule in kind_rules {
            if rule.matches(resource) {
                return true;
            }
        }

        false
    }
}
