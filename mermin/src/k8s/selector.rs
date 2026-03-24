use std::collections::{BTreeMap, HashMap, HashSet};

use kube::{Resource, ResourceExt};
use serde::{Deserialize, Serialize};

/// Serde Default::default() is `false`, but `include` must default to `true`.
const fn default_true() -> bool {
    true
}

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
    /// Whether to include or exclude matching resources
    #[serde(default = "default_true")]
    pub include: bool,
}

impl Selectors {
    pub fn new(kind: &str) -> Self {
        Self {
            kind: kind.to_string(),
            namespaces: None,
            match_labels: None,
            match_expressions: None,
            include: true,
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
    /// 2. Exclude rules (include=false) are checked first: if any exclude rule matches → DENY.
    /// 3. Include rules (include=true):
    ///    - If at least one include rule exists for this kind → ALLOW if any include rule matches (OR).
    ///    - If no include rules exist (exclude-only) → ALLOW (non-matching resources pass through).
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
            if !rule.include && rule.matches(resource) {
                return false;
            }
        }

        let include_rules: Vec<_> = kind_rules.iter().filter(|r| r.include).collect();

        if include_rules.is_empty() {
            return true;
        }

        for rule in include_rules {
            if rule.matches(resource) {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use k8s_openapi::{api::core::v1::Pod, apimachinery::pkg::apis::meta::v1::ObjectMeta};

    use super::*;

    fn create_test_pod(name: &str, namespace: &str, labels: BTreeMap<String, String>) -> Pod {
        Pod {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                labels: Some(labels),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn test_include_field_defaults_to_true() {
        let selector = Selectors::new("Pod");
        assert!(selector.include, "include should default to true");
    }

    #[test]
    fn test_serde_include_default() {
        // Test that serde defaults include to true when not specified
        let json = r#"{"kind": "Pod"}"#;
        let selector: Selectors = serde_json::from_str(json).unwrap();
        assert!(selector.include, "include should default to true via serde");
    }

    #[test]
    fn test_serde_include_explicit_false() {
        let json = r#"{"kind": "Pod", "include": false}"#;
        let selector: Selectors = serde_json::from_str(json).unwrap();
        assert!(
            !selector.include,
            "include should be false when explicitly set"
        );
    }

    #[test]
    fn test_exclude_only_allows_non_matching() {
        let mut exclude_selector = Selectors::new("Pod");
        exclude_selector.include = false;
        exclude_selector.match_labels = Some(HashMap::from([(
            "app.kubernetes.io/name".to_string(),
            "netobserv-flow".to_string(),
        )]));

        let filter = ResourceFilter::new(vec![exclude_selector]);

        let excluded_pod = create_test_pod(
            "netobserv-pod",
            "default",
            BTreeMap::from([(
                "app.kubernetes.io/name".to_string(),
                "netobserv-flow".to_string(),
            )]),
        );
        assert!(
            !filter.is_allowed(&excluded_pod),
            "Pod matching exclude rule should be denied"
        );

        let allowed_pod = create_test_pod(
            "other-pod",
            "default",
            BTreeMap::from([("app".to_string(), "myapp".to_string())]),
        );
        assert!(
            filter.is_allowed(&allowed_pod),
            "Pod not matching exclude rule should be allowed"
        );
    }

    #[test]
    fn test_include_only_or_logic() {
        let mut include_dev = Selectors::new("Pod");
        include_dev.match_labels = Some(HashMap::from([("env".to_string(), "dev".to_string())]));

        let mut include_stage = Selectors::new("Pod");
        include_stage.match_labels =
            Some(HashMap::from([("env".to_string(), "stage".to_string())]));

        let filter = ResourceFilter::new(vec![include_dev, include_stage]);

        let dev_pod = create_test_pod(
            "dev-pod",
            "default",
            BTreeMap::from([("env".to_string(), "dev".to_string())]),
        );
        assert!(
            filter.is_allowed(&dev_pod),
            "Pod matching first include rule should be allowed"
        );

        let stage_pod = create_test_pod(
            "stage-pod",
            "default",
            BTreeMap::from([("env".to_string(), "stage".to_string())]),
        );
        assert!(
            filter.is_allowed(&stage_pod),
            "Pod matching second include rule should be allowed"
        );

        let prod_pod = create_test_pod(
            "prod-pod",
            "default",
            BTreeMap::from([("env".to_string(), "prod".to_string())]),
        );
        assert!(
            !filter.is_allowed(&prod_pod),
            "Pod not matching any include rule should be denied"
        );
    }

    #[test]
    fn test_exclude_overrides_include() {
        let mut include_rule = Selectors::new("Pod");
        include_rule.match_labels = Some(HashMap::from([("app".to_string(), "myapp".to_string())]));

        let mut exclude_rule = Selectors::new("Pod");
        exclude_rule.include = false;
        exclude_rule.match_labels = Some(HashMap::from([("env".to_string(), "test".to_string())]));

        let filter = ResourceFilter::new(vec![include_rule, exclude_rule]);

        let excluded_pod = create_test_pod(
            "test-pod",
            "default",
            BTreeMap::from([
                ("app".to_string(), "myapp".to_string()),
                ("env".to_string(), "test".to_string()),
            ]),
        );
        assert!(
            !filter.is_allowed(&excluded_pod),
            "Pod matching both include and exclude should be denied (exclude wins)"
        );

        let allowed_pod = create_test_pod(
            "prod-pod",
            "default",
            BTreeMap::from([
                ("app".to_string(), "myapp".to_string()),
                ("env".to_string(), "prod".to_string()),
            ]),
        );
        assert!(
            filter.is_allowed(&allowed_pod),
            "Pod matching include but not exclude should be allowed"
        );

        let other_pod = create_test_pod(
            "other-pod",
            "default",
            BTreeMap::from([("app".to_string(), "other".to_string())]),
        );
        assert!(
            !filter.is_allowed(&other_pod),
            "Pod not matching include rule should be denied"
        );
    }

    #[test]
    fn test_match_expression_with_exclude() {
        let mut exclude_selector = Selectors::new("Pod");
        exclude_selector.include = false;
        exclude_selector.match_expressions = Some(vec![MatchExpression {
            key: "app.kubernetes.io/name".to_string(),
            operator: Operator::In,
            values: Some(vec!["netobserv-flow".to_string(), "opensearch".to_string()]),
        }]);

        let filter = ResourceFilter::new(vec![exclude_selector]);

        let netobserv_pod = create_test_pod(
            "netobserv-pod",
            "default",
            BTreeMap::from([(
                "app.kubernetes.io/name".to_string(),
                "netobserv-flow".to_string(),
            )]),
        );
        assert!(
            !filter.is_allowed(&netobserv_pod),
            "Pod matching exclude In expression should be denied"
        );

        let opensearch_pod = create_test_pod(
            "opensearch-pod",
            "default",
            BTreeMap::from([(
                "app.kubernetes.io/name".to_string(),
                "opensearch".to_string(),
            )]),
        );
        assert!(
            !filter.is_allowed(&opensearch_pod),
            "Pod matching exclude In expression should be denied"
        );

        let other_pod = create_test_pod(
            "myapp-pod",
            "default",
            BTreeMap::from([("app.kubernetes.io/name".to_string(), "myapp".to_string())]),
        );
        assert!(
            filter.is_allowed(&other_pod),
            "Pod not matching exclude expression should be allowed"
        );
    }

    #[test]
    fn test_namespace_filter_with_exclude() {
        let mut exclude_selector = Selectors::new("Pod");
        exclude_selector.include = false;
        exclude_selector.namespaces = Some(vec!["system".to_string()]);

        let filter = ResourceFilter::new(vec![exclude_selector]);

        let system_pod = create_test_pod(
            "system-pod",
            "system",
            BTreeMap::from([("app".to_string(), "myapp".to_string())]),
        );
        assert!(
            !filter.is_allowed(&system_pod),
            "Pod in excluded namespace should be denied"
        );

        let default_pod = create_test_pod(
            "default-pod",
            "default",
            BTreeMap::from([("app".to_string(), "myapp".to_string())]),
        );
        assert!(
            filter.is_allowed(&default_pod),
            "Pod in non-excluded namespace should be allowed"
        );
    }

    #[test]
    fn test_no_rules_for_kind_denies() {
        let pod_selector = Selectors::new("Pod");
        let filter = ResourceFilter::new(vec![pod_selector]);

        use k8s_openapi::api::core::v1::Node;
        let node = Node {
            metadata: ObjectMeta {
                name: Some("test-node".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(
            !filter.is_allowed(&node),
            "Resource with no configured rules should be denied"
        );
    }

    #[test]
    fn test_default_selectors_all_include_true() {
        let defaults = default_selectors();
        for selector in defaults {
            assert!(
                selector.include,
                "All default selectors should have include=true"
            );
        }
    }

    #[test]
    fn test_merge_with_defaults_preserves_include() {
        let mut user_pod_selector = Selectors::new("Pod");
        user_pod_selector.include = false;
        user_pod_selector.match_labels =
            Some(HashMap::from([("exclude".to_string(), "true".to_string())]));

        let merged = merge_with_defaults(vec![user_pod_selector.clone()]);

        let pod_selector = merged
            .iter()
            .find(|s| s.kind.to_lowercase() == "pod")
            .expect("Pod selector should exist in merged results");

        assert!(
            !pod_selector.include,
            "User's include=false should be preserved after merge"
        );
        assert_eq!(
            pod_selector.match_labels, user_pod_selector.match_labels,
            "User's match_labels should be preserved"
        );
    }

    #[test]
    fn test_complex_mixed_rules() {
        let mut include_myapp = Selectors::new("Pod");
        include_myapp.match_labels =
            Some(HashMap::from([("app".to_string(), "myapp".to_string())]));

        let mut include_yourapp = Selectors::new("Pod");
        include_yourapp.match_labels =
            Some(HashMap::from([("app".to_string(), "yourapp".to_string())]));

        let mut exclude_test = Selectors::new("Pod");
        exclude_test.include = false;
        exclude_test.match_labels = Some(HashMap::from([("env".to_string(), "test".to_string())]));

        let filter = ResourceFilter::new(vec![include_myapp, include_yourapp, exclude_test]);

        let allowed_pod1 = create_test_pod(
            "pod1",
            "default",
            BTreeMap::from([
                ("app".to_string(), "myapp".to_string()),
                ("env".to_string(), "prod".to_string()),
            ]),
        );
        assert!(
            filter.is_allowed(&allowed_pod1),
            "Pod matching include and not exclude should be allowed"
        );

        let allowed_pod2 = create_test_pod(
            "pod2",
            "default",
            BTreeMap::from([
                ("app".to_string(), "yourapp".to_string()),
                ("env".to_string(), "prod".to_string()),
            ]),
        );
        assert!(
            filter.is_allowed(&allowed_pod2),
            "Pod matching second include and not exclude should be allowed"
        );

        let excluded_pod = create_test_pod(
            "pod3",
            "default",
            BTreeMap::from([
                ("app".to_string(), "myapp".to_string()),
                ("env".to_string(), "test".to_string()),
            ]),
        );
        assert!(
            !filter.is_allowed(&excluded_pod),
            "Pod matching both include and exclude should be denied"
        );

        let denied_pod = create_test_pod(
            "pod4",
            "default",
            BTreeMap::from([
                ("app".to_string(), "other".to_string()),
                ("env".to_string(), "prod".to_string()),
            ]),
        );
        assert!(
            !filter.is_allowed(&denied_pod),
            "Pod not matching any include should be denied"
        );
    }

    #[test]
    fn test_exclude_only_with_match_expressions() {
        let mut exclude_selector = Selectors::new("Pod");
        exclude_selector.include = false;
        exclude_selector.match_expressions = Some(vec![MatchExpression {
            key: "app.kubernetes.io/name".to_string(),
            operator: Operator::In,
            values: Some(vec!["netobserv-flow".to_string(), "opensearch".to_string()]),
        }]);

        let filter = ResourceFilter::new(vec![exclude_selector]);

        let netobserv_pod = create_test_pod(
            "netobserv",
            "default",
            BTreeMap::from([(
                "app.kubernetes.io/name".to_string(),
                "netobserv-flow".to_string(),
            )]),
        );
        assert!(
            !filter.is_allowed(&netobserv_pod),
            "netobserv-flow pod should be excluded"
        );

        let opensearch_pod = create_test_pod(
            "opensearch",
            "default",
            BTreeMap::from([(
                "app.kubernetes.io/name".to_string(),
                "opensearch".to_string(),
            )]),
        );
        assert!(
            !filter.is_allowed(&opensearch_pod),
            "opensearch pod should be excluded"
        );

        let myapp_pod = create_test_pod(
            "myapp",
            "default",
            BTreeMap::from([("app.kubernetes.io/name".to_string(), "myapp".to_string())]),
        );
        assert!(
            filter.is_allowed(&myapp_pod),
            "Pod not in exclude list should be allowed"
        );

        let unlabeled_pod = create_test_pod("unlabeled", "default", BTreeMap::new());
        assert!(
            filter.is_allowed(&unlabeled_pod),
            "Pod without excluded label should be allowed"
        );
    }

    #[test]
    fn test_namespace_exclude_with_label_include() {
        let mut exclude_ns = Selectors::new("Pod");
        exclude_ns.include = false;
        exclude_ns.namespaces = Some(vec!["kube-system".to_string()]);

        let mut include_monitored = Selectors::new("Pod");
        include_monitored.match_labels = Some(HashMap::from([(
            "app".to_string(),
            "monitored".to_string(),
        )]));

        let filter = ResourceFilter::new(vec![exclude_ns, include_monitored]);

        let excluded_pod = create_test_pod(
            "system-pod",
            "kube-system",
            BTreeMap::from([("app".to_string(), "monitored".to_string())]),
        );
        assert!(
            !filter.is_allowed(&excluded_pod),
            "Pod in excluded namespace should be denied even if it matches include"
        );

        let allowed_pod = create_test_pod(
            "monitored-pod",
            "default",
            BTreeMap::from([("app".to_string(), "monitored".to_string())]),
        );
        assert!(
            filter.is_allowed(&allowed_pod),
            "Pod matching include and not in excluded namespace should be allowed"
        );

        let denied_pod = create_test_pod(
            "other-pod",
            "default",
            BTreeMap::from([("app".to_string(), "other".to_string())]),
        );
        assert!(
            !filter.is_allowed(&denied_pod),
            "Pod not matching include should be denied"
        );
    }

    #[test]
    fn test_multiple_exclude_rules() {
        let mut exclude_netobserv = Selectors::new("Pod");
        exclude_netobserv.include = false;
        exclude_netobserv.match_labels = Some(HashMap::from([(
            "app".to_string(),
            "netobserv".to_string(),
        )]));

        let mut exclude_opensearch = Selectors::new("Pod");
        exclude_opensearch.include = false;
        exclude_opensearch.match_labels = Some(HashMap::from([(
            "app".to_string(),
            "opensearch".to_string(),
        )]));

        let filter = ResourceFilter::new(vec![exclude_netobserv, exclude_opensearch]);

        let netobserv_pod = create_test_pod(
            "netobserv",
            "default",
            BTreeMap::from([("app".to_string(), "netobserv".to_string())]),
        );
        assert!(
            !filter.is_allowed(&netobserv_pod),
            "netobserv should be excluded"
        );

        let opensearch_pod = create_test_pod(
            "opensearch",
            "default",
            BTreeMap::from([("app".to_string(), "opensearch".to_string())]),
        );
        assert!(
            !filter.is_allowed(&opensearch_pod),
            "opensearch should be excluded"
        );

        let other_pod = create_test_pod(
            "myapp",
            "default",
            BTreeMap::from([("app".to_string(), "myapp".to_string())]),
        );
        assert!(
            filter.is_allowed(&other_pod),
            "Non-excluded pod should be allowed"
        );
    }
}
