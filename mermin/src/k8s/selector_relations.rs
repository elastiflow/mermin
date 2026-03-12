use std::collections::BTreeMap;

use k8s_openapi::{
    api::{
        apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet},
        batch::v1::{CronJob, Job},
        core::v1::Service,
        networking::v1::NetworkPolicy,
    },
    apimachinery::pkg::apis::meta::v1::{LabelSelector, LabelSelectorRequirement},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, warn};

use crate::k8s::attributor::{K8sObjectMeta, ResourceStore};

/// Configuration for a single selector-based resource relation rule
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SelectorRelationRule {
    /// The kind of resource that contains the selector (e.g., "NetworkPolicy", "Service")
    /// Case insensitive
    pub kind: String,
    /// The kind of resource to match against (e.g., "Pod")
    /// Case insensitive
    pub to: String,
    /// JSON path to the matchLabels field in the source resource
    /// Example: "spec.podSelector.matchLabels" or "spec.selector"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector_match_labels_field: Option<String>,
    /// JSON path to the matchExpressions field in the source resource
    /// Example: "spec.podSelector.matchExpressions"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector_match_expressions_field: Option<String>,
}

/// Manages selector-based resource relations according to configuration rules.
///
/// This type is thread-safe (`Send + Sync`) and can be shared across tasks.
/// All state is immutable after construction.
pub struct SelectorRelationsManager {
    pub(crate) rules: Vec<NormalizedRule>,
}

/// Internal representation of a selector relation rule with normalized (lowercase) kinds
#[derive(Clone, Debug)]
pub(crate) struct NormalizedRule {
    /// Source resource kind (normalized to lowercase)
    pub(crate) kind: String,
    /// Target resource kind (normalized to lowercase)
    pub(crate) to: String,
    /// JSON path to matchLabels field
    pub(crate) selector_match_labels_field: Option<String>,
    /// JSON path to matchExpressions field
    pub(crate) selector_match_expressions_field: Option<String>,
}

impl SelectorRelationsManager {
    /// All kind names are normalized to lowercase for case-insensitive matching.
    pub fn new(rules: Vec<SelectorRelationRule>) -> Self {
        let normalized_rules = rules
            .into_iter()
            .map(|rule| NormalizedRule {
                kind: rule.kind.to_lowercase(),
                to: rule.to.to_lowercase(),
                selector_match_labels_field: rule.selector_match_labels_field,
                selector_match_expressions_field: rule.selector_match_expressions_field,
            })
            .collect();

        Self {
            rules: normalized_rules,
        }
    }

    /// Finds all resources that have selectors matching the given Pod's labels.
    ///
    /// Returns metadata for resources (e.g., NetworkPolicies, Services) whose selectors
    /// match the pod's labels according to the configured rules.
    ///
    /// Returns None if no matching resources are found.
    #[must_use]
    pub fn get_related_resources(
        &self,
        pod_labels: &BTreeMap<String, String>,
        pod_namespace: &str,
        store: &ResourceStore,
    ) -> Option<Vec<K8sObjectMeta>> {
        let mut related = Vec::new();

        for rule in &self.rules {
            // Only process rules that target Pods
            if rule.to != "pod" {
                continue;
            }

            match rule.kind.as_str() {
                "networkpolicy" => {
                    related.extend(self.find_matching_network_policies(
                        pod_labels,
                        pod_namespace,
                        rule,
                        store,
                    ));
                }
                "service" => {
                    related.extend(self.find_matching_services(
                        pod_labels,
                        pod_namespace,
                        rule,
                        store,
                    ));
                }
                "replicaset" => {
                    related.extend(self.find_matching_replicasets(
                        pod_labels,
                        pod_namespace,
                        rule,
                        store,
                    ));
                }
                "deployment" => {
                    related.extend(self.find_matching_deployments(
                        pod_labels,
                        pod_namespace,
                        rule,
                        store,
                    ));
                }
                "statefulset" => {
                    related.extend(self.find_matching_statefulsets(
                        pod_labels,
                        pod_namespace,
                        rule,
                        store,
                    ));
                }
                "daemonset" => {
                    related.extend(self.find_matching_daemonsets(
                        pod_labels,
                        pod_namespace,
                        rule,
                        store,
                    ));
                }
                "job" => {
                    related.extend(self.find_matching_jobs(pod_labels, pod_namespace, rule, store));
                }
                "cronjob" => {
                    related.extend(self.find_matching_cronjobs(
                        pod_labels,
                        pod_namespace,
                        rule,
                        store,
                    ));
                }
                _ => {
                    debug!(
                        event.name = "selector_relations.unsupported_kind",
                        k8s.selector_rule.kind = %rule.kind,
                        "selector relation matching for this resource kind is not implemented"
                    );
                }
            }
        }

        if related.is_empty() {
            None
        } else {
            Some(related)
        }
    }

    fn find_matching_network_policies(
        &self,
        pod_labels: &BTreeMap<String, String>,
        pod_namespace: &str,
        rule: &NormalizedRule,
        store: &ResourceStore,
    ) -> Vec<K8sObjectMeta> {
        store
            .get_by_namespace::<NetworkPolicy>(pod_namespace)
            .iter()
            .filter_map(|policy| {
                let selector = self.extract_selector_from_network_policy(policy, rule)?;
                self.selector_matches(&selector, pod_labels)
                    .then(|| K8sObjectMeta::from(policy.as_ref()))
            })
            .collect()
    }

    fn find_matching_services(
        &self,
        pod_labels: &BTreeMap<String, String>,
        pod_namespace: &str,
        rule: &NormalizedRule,
        store: &ResourceStore,
    ) -> Vec<K8sObjectMeta> {
        store
            .get_by_namespace::<Service>(pod_namespace)
            .iter()
            .filter_map(|service| {
                let selector = self.extract_selector_from_service(service, rule)?;
                self.selector_matches(&selector, pod_labels)
                    .then(|| K8sObjectMeta::from(service.as_ref()))
            })
            .collect()
    }

    fn extract_selector_from_network_policy(
        &self,
        policy: &NetworkPolicy,
        rule: &NormalizedRule,
    ) -> Option<LabelSelector> {
        if rule.selector_match_labels_field.is_some()
            || rule.selector_match_expressions_field.is_some()
        {
            return self.extract_selector_generic(policy, rule);
        }

        policy.spec.as_ref().map(|spec| spec.pod_selector.clone())
    }

    fn extract_selector_from_service(
        &self,
        service: &Service,
        rule: &NormalizedRule,
    ) -> Option<LabelSelector> {
        if rule.selector_match_labels_field.is_some()
            || rule.selector_match_expressions_field.is_some()
        {
            return self.extract_selector_generic(service, rule);
        }

        let selector_map = service.spec.as_ref()?.selector.as_ref()?;

        if selector_map.is_empty() {
            return None;
        }

        Some(LabelSelector {
            match_labels: Some(selector_map.clone()),
            match_expressions: None,
        })
    }

    fn find_matching_replicasets(
        &self,
        pod_labels: &BTreeMap<String, String>,
        pod_namespace: &str,
        rule: &NormalizedRule,
        store: &ResourceStore,
    ) -> Vec<K8sObjectMeta> {
        store
            .get_by_namespace::<ReplicaSet>(pod_namespace)
            .iter()
            .filter_map(|rs| {
                let selector = self.extract_selector_from_replicaset(rs, rule)?;
                self.selector_matches(&selector, pod_labels)
                    .then(|| K8sObjectMeta::from(rs.as_ref()))
            })
            .collect()
    }

    fn extract_selector_from_replicaset(
        &self,
        replicaset: &ReplicaSet,
        rule: &NormalizedRule,
    ) -> Option<LabelSelector> {
        if rule.selector_match_labels_field.is_some()
            || rule.selector_match_expressions_field.is_some()
        {
            return self.extract_selector_generic(replicaset, rule);
        }
        Some(replicaset.spec.as_ref()?.selector.clone())
    }

    fn find_matching_deployments(
        &self,
        pod_labels: &BTreeMap<String, String>,
        pod_namespace: &str,
        rule: &NormalizedRule,
        store: &ResourceStore,
    ) -> Vec<K8sObjectMeta> {
        store
            .get_by_namespace::<Deployment>(pod_namespace)
            .iter()
            .filter_map(|deployment| {
                let selector = self.extract_selector_from_deployment(deployment, rule)?;
                self.selector_matches(&selector, pod_labels)
                    .then(|| K8sObjectMeta::from(deployment.as_ref()))
            })
            .collect()
    }

    fn extract_selector_from_deployment(
        &self,
        deployment: &Deployment,
        rule: &NormalizedRule,
    ) -> Option<LabelSelector> {
        if rule.selector_match_labels_field.is_some()
            || rule.selector_match_expressions_field.is_some()
        {
            return self.extract_selector_generic(deployment, rule);
        }
        Some(deployment.spec.as_ref()?.selector.clone())
    }

    fn find_matching_statefulsets(
        &self,
        pod_labels: &BTreeMap<String, String>,
        pod_namespace: &str,
        rule: &NormalizedRule,
        store: &ResourceStore,
    ) -> Vec<K8sObjectMeta> {
        store
            .get_by_namespace::<StatefulSet>(pod_namespace)
            .iter()
            .filter_map(|sts| {
                let selector = self.extract_selector_from_statefulset(sts, rule)?;
                self.selector_matches(&selector, pod_labels)
                    .then(|| K8sObjectMeta::from(sts.as_ref()))
            })
            .collect()
    }

    fn extract_selector_from_statefulset(
        &self,
        statefulset: &StatefulSet,
        rule: &NormalizedRule,
    ) -> Option<LabelSelector> {
        if rule.selector_match_labels_field.is_some()
            || rule.selector_match_expressions_field.is_some()
        {
            return self.extract_selector_generic(statefulset, rule);
        }
        Some(statefulset.spec.as_ref()?.selector.clone())
    }

    fn find_matching_daemonsets(
        &self,
        pod_labels: &BTreeMap<String, String>,
        pod_namespace: &str,
        rule: &NormalizedRule,
        store: &ResourceStore,
    ) -> Vec<K8sObjectMeta> {
        store
            .get_by_namespace::<DaemonSet>(pod_namespace)
            .iter()
            .filter_map(|ds| {
                let selector = self.extract_selector_from_daemonset(ds, rule)?;
                self.selector_matches(&selector, pod_labels)
                    .then(|| K8sObjectMeta::from(ds.as_ref()))
            })
            .collect()
    }

    fn extract_selector_from_daemonset(
        &self,
        daemonset: &DaemonSet,
        rule: &NormalizedRule,
    ) -> Option<LabelSelector> {
        if rule.selector_match_labels_field.is_some()
            || rule.selector_match_expressions_field.is_some()
        {
            return self.extract_selector_generic(daemonset, rule);
        }
        Some(daemonset.spec.as_ref()?.selector.clone())
    }

    fn find_matching_jobs(
        &self,
        pod_labels: &BTreeMap<String, String>,
        pod_namespace: &str,
        rule: &NormalizedRule,
        store: &ResourceStore,
    ) -> Vec<K8sObjectMeta> {
        store
            .get_by_namespace::<Job>(pod_namespace)
            .iter()
            .filter_map(|job| {
                let selector = self.extract_selector_from_job(job, rule)?;
                self.selector_matches(&selector, pod_labels)
                    .then(|| K8sObjectMeta::from(job.as_ref()))
            })
            .collect()
    }

    fn extract_selector_from_job(&self, job: &Job, rule: &NormalizedRule) -> Option<LabelSelector> {
        if rule.selector_match_labels_field.is_some()
            || rule.selector_match_expressions_field.is_some()
        {
            return self.extract_selector_generic(job, rule);
        }
        job.spec.as_ref()?.selector.clone()
    }

    fn find_matching_cronjobs(
        &self,
        pod_labels: &BTreeMap<String, String>,
        pod_namespace: &str,
        rule: &NormalizedRule,
        store: &ResourceStore,
    ) -> Vec<K8sObjectMeta> {
        store
            .get_by_namespace::<CronJob>(pod_namespace)
            .iter()
            .filter_map(|cronjob| {
                let selector = self.extract_selector_from_cronjob(cronjob, rule)?;
                self.selector_matches(&selector, pod_labels)
                    .then(|| K8sObjectMeta::from(cronjob.as_ref()))
            })
            .collect()
    }

    fn extract_selector_from_cronjob(
        &self,
        cronjob: &CronJob,
        rule: &NormalizedRule,
    ) -> Option<LabelSelector> {
        if rule.selector_match_labels_field.is_some()
            || rule.selector_match_expressions_field.is_some()
        {
            return self.extract_selector_generic(cronjob, rule);
        }

        cronjob
            .spec
            .as_ref()?
            .job_template
            .spec
            .as_ref()?
            .selector
            .clone()
    }

    pub(crate) fn selector_matches(
        &self,
        selector: &LabelSelector,
        labels: &BTreeMap<String, String>,
    ) -> bool {
        if let Some(match_labels) = &selector.match_labels {
            for (key, value) in match_labels {
                if labels.get(key) != Some(value) {
                    return false;
                }
            }
        }

        if let Some(match_expressions) = &selector.match_expressions {
            for expr in match_expressions {
                if !self.expression_matches(expr, labels) {
                    return false;
                }
            }
        }

        true
    }

    fn expression_matches(
        &self,
        expr: &LabelSelectorRequirement,
        labels: &BTreeMap<String, String>,
    ) -> bool {
        let label_value = labels.get(&expr.key);
        let binding = vec![];
        let values = expr.values.as_ref().unwrap_or(&binding);

        match expr.operator.as_str() {
            "In" => {
                if let Some(value) = label_value {
                    values.contains(value)
                } else {
                    false
                }
            }
            "NotIn" => {
                if let Some(value) = label_value {
                    !values.contains(value)
                } else {
                    true
                }
            }
            "Exists" => label_value.is_some(),
            "DoesNotExist" => label_value.is_none(),
            _ => {
                warn!(
                    event.name = "selector_relations.unknown_operator",
                    k8s.selector.operator = %expr.operator,
                    "unknown label selector operator"
                );
                false
            }
        }
    }

    /// Extracts a `LabelSelector` from a resource using JSON field paths defined in the rule.
    /// Enables selector matching for CRDs where selectors may be at non-standard locations.
    pub(crate) fn extract_selector_generic<T: serde::Serialize>(
        &self,
        resource: &T,
        rule: &NormalizedRule,
    ) -> Option<LabelSelector> {
        let json_value = serde_json::to_value(resource).ok()?;

        let mut selector = LabelSelector::default();
        let mut has_content = false;

        if let Some(labels_path) = &rule.selector_match_labels_field
            && let Some(labels_value) = self.extract_json_field(&json_value, labels_path)
            && let Some(labels_map) = labels_value.as_object()
        {
            let match_labels: BTreeMap<String, String> = labels_map
                .iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect();

            if !match_labels.is_empty() {
                selector.match_labels = Some(match_labels);
                has_content = true;
            }
        }

        if let Some(expr_path) = &rule.selector_match_expressions_field
            && let Some(expressions_value) = self.extract_json_field(&json_value, expr_path)
            && let Some(expr_array) = expressions_value.as_array()
        {
            let match_expressions: Vec<LabelSelectorRequirement> = expr_array
                .iter()
                .filter_map(|e| self.parse_label_selector_requirement(e))
                .collect();

            if !match_expressions.is_empty() {
                selector.match_expressions = Some(match_expressions);
                has_content = true;
            }
        }

        if has_content { Some(selector) } else { None }
    }

    fn extract_json_field<'a>(&self, value: &'a Value, path: &str) -> Option<&'a Value> {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = value;

        for part in parts {
            current = current.get(part)?;
        }

        Some(current)
    }

    fn parse_label_selector_requirement(&self, value: &Value) -> Option<LabelSelectorRequirement> {
        let obj = value.as_object()?;

        let key = obj.get("key")?.as_str()?.to_string();
        let operator = obj.get("operator")?.as_str()?.to_string();
        let values = obj.get("values").and_then(|v| v.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        });

        Some(LabelSelectorRequirement {
            key,
            operator,
            values,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_rule(
        kind: &str,
        to: &str,
        match_labels_field: Option<&str>,
        match_expressions_field: Option<&str>,
    ) -> SelectorRelationRule {
        SelectorRelationRule {
            kind: kind.to_string(),
            to: to.to_string(),
            selector_match_labels_field: match_labels_field.map(String::from),
            selector_match_expressions_field: match_expressions_field.map(String::from),
        }
    }

    fn create_label_selector(
        match_labels: Option<BTreeMap<String, String>>,
        match_expressions: Option<Vec<LabelSelectorRequirement>>,
    ) -> LabelSelector {
        LabelSelector {
            match_labels,
            match_expressions,
        }
    }

    fn create_labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn test_manager_creation() {
        let rules = vec![
            create_test_rule("NetworkPolicy", "Pod", Some("spec.podSelector"), None),
            create_test_rule("Service", "Pod", Some("spec.selector"), None),
        ];

        let manager = SelectorRelationsManager::new(rules);
        assert_eq!(manager.rules.len(), 2);
        assert_eq!(manager.rules[0].kind, "networkpolicy");
        assert_eq!(manager.rules[1].kind, "service");
    }

    #[test]
    fn test_case_insensitive_kind_matching() {
        let rules = vec![
            create_test_rule("NETWORKPOLICY", "pod", Some("spec.podSelector"), None),
            create_test_rule("service", "POD", Some("spec.selector"), None),
        ];

        let manager = SelectorRelationsManager::new(rules);
        assert_eq!(manager.rules[0].kind, "networkpolicy");
        assert_eq!(manager.rules[0].to, "pod");
        assert_eq!(manager.rules[1].kind, "service");
        assert_eq!(manager.rules[1].to, "pod");
    }

    #[test]
    fn test_selector_matches_with_match_labels() {
        let manager = SelectorRelationsManager::new(vec![]);

        let selector = create_label_selector(
            Some(create_labels(&[("app", "nginx"), ("env", "prod")])),
            None,
        );

        // Exact match
        let labels = create_labels(&[("app", "nginx"), ("env", "prod"), ("version", "1.0")]);
        assert!(manager.selector_matches(&selector, &labels));

        // Missing label
        let labels = create_labels(&[("app", "nginx")]);
        assert!(!manager.selector_matches(&selector, &labels));

        // Wrong value
        let labels = create_labels(&[("app", "nginx"), ("env", "dev")]);
        assert!(!manager.selector_matches(&selector, &labels));
    }

    #[test]
    fn test_selector_matches_with_empty_selector() {
        let manager = SelectorRelationsManager::new(vec![]);

        let selector = create_label_selector(None, None);
        let labels = create_labels(&[("app", "nginx")]);

        // Empty selector matches everything
        assert!(manager.selector_matches(&selector, &labels));
    }

    #[test]
    fn test_expression_matches_in_operator() {
        let manager = SelectorRelationsManager::new(vec![]);

        let expr = LabelSelectorRequirement {
            key: "env".to_string(),
            operator: "In".to_string(),
            values: Some(vec!["dev".to_string(), "staging".to_string()]),
        };

        // Match
        let labels = create_labels(&[("env", "dev")]);
        assert!(manager.expression_matches(&expr, &labels));

        // No match
        let labels = create_labels(&[("env", "prod")]);
        assert!(!manager.expression_matches(&expr, &labels));

        // Missing label
        let labels = create_labels(&[("app", "nginx")]);
        assert!(!manager.expression_matches(&expr, &labels));
    }

    #[test]
    fn test_expression_matches_notin_operator() {
        let manager = SelectorRelationsManager::new(vec![]);

        let expr = LabelSelectorRequirement {
            key: "env".to_string(),
            operator: "NotIn".to_string(),
            values: Some(vec!["prod".to_string()]),
        };

        // Match (value not in list)
        let labels = create_labels(&[("env", "dev")]);
        assert!(manager.expression_matches(&expr, &labels));

        // No match (value in list)
        let labels = create_labels(&[("env", "prod")]);
        assert!(!manager.expression_matches(&expr, &labels));

        // Match (label doesn't exist)
        let labels = create_labels(&[("app", "nginx")]);
        assert!(manager.expression_matches(&expr, &labels));
    }

    #[test]
    fn test_expression_matches_exists_operator() {
        let manager = SelectorRelationsManager::new(vec![]);

        let expr = LabelSelectorRequirement {
            key: "app".to_string(),
            operator: "Exists".to_string(),
            values: None,
        };

        // Match (label exists)
        let labels = create_labels(&[("app", "nginx")]);
        assert!(manager.expression_matches(&expr, &labels));

        // No match (label doesn't exist)
        let labels = create_labels(&[("env", "prod")]);
        assert!(!manager.expression_matches(&expr, &labels));
    }

    #[test]
    fn test_expression_matches_doesnotexist_operator() {
        let manager = SelectorRelationsManager::new(vec![]);

        let expr = LabelSelectorRequirement {
            key: "deprecated".to_string(),
            operator: "DoesNotExist".to_string(),
            values: None,
        };

        // Match (label doesn't exist)
        let labels = create_labels(&[("app", "nginx")]);
        assert!(manager.expression_matches(&expr, &labels));

        // No match (label exists)
        let labels = create_labels(&[("deprecated", "true")]);
        assert!(!manager.expression_matches(&expr, &labels));
    }

    #[test]
    fn test_selector_matches_combined() {
        let manager = SelectorRelationsManager::new(vec![]);

        let selector = create_label_selector(
            Some(create_labels(&[("app", "nginx")])),
            Some(vec![LabelSelectorRequirement {
                key: "env".to_string(),
                operator: "In".to_string(),
                values: Some(vec!["dev".to_string(), "staging".to_string()]),
            }]),
        );

        // Both match
        let labels = create_labels(&[("app", "nginx"), ("env", "dev")]);
        assert!(manager.selector_matches(&selector, &labels));

        // matchLabels fails
        let labels = create_labels(&[("app", "apache"), ("env", "dev")]);
        assert!(!manager.selector_matches(&selector, &labels));

        // matchExpressions fails
        let labels = create_labels(&[("app", "nginx"), ("env", "prod")]);
        assert!(!manager.selector_matches(&selector, &labels));
    }

    #[test]
    fn test_expression_matches_unknown_operator() {
        let manager = SelectorRelationsManager::new(vec![]);

        let expr = LabelSelectorRequirement {
            key: "app".to_string(),
            operator: "UnknownOperator".to_string(),
            values: None,
        };

        let labels = create_labels(&[("app", "nginx")]);
        assert!(!manager.expression_matches(&expr, &labels));
    }

    #[test]
    fn test_empty_rules_list() {
        let manager = SelectorRelationsManager::new(vec![]);
        assert_eq!(manager.rules.len(), 0);
    }

    #[test]
    fn test_multiple_match_expressions() {
        let manager = SelectorRelationsManager::new(vec![]);

        let selector = create_label_selector(
            None,
            Some(vec![
                LabelSelectorRequirement {
                    key: "tier".to_string(),
                    operator: "In".to_string(),
                    values: Some(vec!["frontend".to_string(), "backend".to_string()]),
                },
                LabelSelectorRequirement {
                    key: "deprecated".to_string(),
                    operator: "DoesNotExist".to_string(),
                    values: None,
                },
            ]),
        );

        // Both expressions match
        let labels = create_labels(&[("tier", "frontend"), ("app", "web")]);
        assert!(manager.selector_matches(&selector, &labels));

        // First matches, second fails
        let labels = create_labels(&[("tier", "frontend"), ("deprecated", "true")]);
        assert!(!manager.selector_matches(&selector, &labels));

        // First fails, second matches
        let labels = create_labels(&[("tier", "database"), ("app", "web")]);
        assert!(!manager.selector_matches(&selector, &labels));
    }

    #[test]
    fn test_generic_field_path_extraction_with_deployment() {
        use serde_json::json;

        let manager = SelectorRelationsManager::new(vec![]);

        // Create a deployment-like JSON structure with custom field paths
        let deployment_json = json!({
            "metadata": {
                "name": "test-deployment",
                "namespace": "default"
            },
            "spec": {
                "selector": {
                    "matchLabels": {
                        "app": "nginx",
                        "tier": "frontend"
                    }
                }
            }
        });

        // Extract selector using custom field path
        let rule = NormalizedRule {
            kind: "deployment".to_string(),
            to: "pod".to_string(),
            selector_match_labels_field: Some("spec.selector.matchLabels".to_string()),
            selector_match_expressions_field: None,
        };

        let selector = manager.extract_selector_generic(&deployment_json, &rule);
        assert!(selector.is_some());

        let selector = selector.unwrap();
        assert!(selector.match_labels.is_some());

        let match_labels = selector.match_labels.unwrap();
        assert_eq!(match_labels.get("app"), Some(&"nginx".to_string()));
        assert_eq!(match_labels.get("tier"), Some(&"frontend".to_string()));
    }

    #[test]
    fn test_generic_field_path_extraction_with_match_expressions() {
        use serde_json::json;

        let manager = SelectorRelationsManager::new(vec![]);

        // Create a JSON structure with matchExpressions
        let resource_json = json!({
            "spec": {
                "podSelector": {
                    "matchLabels": {
                        "app": "web"
                    },
                    "matchExpressions": [
                        {
                            "key": "environment",
                            "operator": "In",
                            "values": ["prod", "staging"]
                        }
                    ]
                }
            }
        });

        // Extract selector using custom field paths for both matchLabels and matchExpressions
        let rule = NormalizedRule {
            kind: "networkpolicy".to_string(),
            to: "pod".to_string(),
            selector_match_labels_field: Some("spec.podSelector.matchLabels".to_string()),
            selector_match_expressions_field: Some("spec.podSelector.matchExpressions".to_string()),
        };

        let selector = manager.extract_selector_generic(&resource_json, &rule);
        assert!(selector.is_some());

        let selector = selector.unwrap();

        // Verify matchLabels
        assert!(selector.match_labels.is_some());
        let match_labels = selector.match_labels.unwrap();
        assert_eq!(match_labels.get("app"), Some(&"web".to_string()));

        // Verify matchExpressions
        assert!(selector.match_expressions.is_some());
        let match_expressions = selector.match_expressions.unwrap();
        assert_eq!(match_expressions.len(), 1);
        assert_eq!(match_expressions[0].key, "environment");
        assert_eq!(match_expressions[0].operator, "In");
        assert_eq!(
            match_expressions[0].values,
            Some(vec!["prod".to_string(), "staging".to_string()])
        );
    }

    #[test]
    fn test_generic_field_path_extraction_with_nested_path() {
        use serde_json::json;

        let manager = SelectorRelationsManager::new(vec![]);

        // Create a JSON structure with deeply nested selector (like CronJob)
        let cronjob_json = json!({
            "spec": {
                "jobTemplate": {
                    "spec": {
                        "selector": {
                            "matchLabels": {
                                "controller": "cronjob",
                                "job": "backup"
                            }
                        }
                    }
                }
            }
        });

        // Extract selector using deeply nested field path
        let rule = NormalizedRule {
            kind: "cronjob".to_string(),
            to: "pod".to_string(),
            selector_match_labels_field: Some(
                "spec.jobTemplate.spec.selector.matchLabels".to_string(),
            ),
            selector_match_expressions_field: None,
        };

        let selector = manager.extract_selector_generic(&cronjob_json, &rule);
        assert!(selector.is_some());

        let selector = selector.unwrap();
        assert!(selector.match_labels.is_some());

        let match_labels = selector.match_labels.unwrap();
        assert_eq!(match_labels.get("controller"), Some(&"cronjob".to_string()));
        assert_eq!(match_labels.get("job"), Some(&"backup".to_string()));
    }

    #[test]
    fn test_generic_field_path_extraction_returns_none_for_invalid_path() {
        use serde_json::json;

        let manager = SelectorRelationsManager::new(vec![]);

        let resource_json = json!({
            "spec": {
                "selector": {
                    "matchLabels": {
                        "app": "test"
                    }
                }
            }
        });

        // Try to extract with an invalid field path
        let rule = NormalizedRule {
            kind: "test".to_string(),
            to: "pod".to_string(),
            selector_match_labels_field: Some("spec.nonexistent.matchLabels".to_string()),
            selector_match_expressions_field: None,
        };

        let selector = manager.extract_selector_generic(&resource_json, &rule);
        assert!(selector.is_none());
    }

    #[test]
    fn test_generic_field_path_extraction_returns_none_for_empty_selector() {
        use serde_json::json;

        let manager = SelectorRelationsManager::new(vec![]);

        let resource_json = json!({
            "spec": {
                "selector": {
                    "matchLabels": {}
                }
            }
        });

        // Extract selector with empty matchLabels
        let rule = NormalizedRule {
            kind: "test".to_string(),
            to: "pod".to_string(),
            selector_match_labels_field: Some("spec.selector.matchLabels".to_string()),
            selector_match_expressions_field: None,
        };

        let selector = manager.extract_selector_generic(&resource_json, &rule);
        // Should return None because the selector has no actual content
        assert!(selector.is_none());
    }
}
