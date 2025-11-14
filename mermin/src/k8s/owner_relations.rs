// owner_relations.rs - Owner reference walking and filtering
//
// This module provides functionality for walking Kubernetes owner references
// and filtering which owner kinds appear in flow metadata based on configuration.

use std::collections::HashSet;

use k8s_openapi::{
    api::{
        apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet},
        batch::v1::{CronJob, Job},
        core::v1::Pod,
    },
    apimachinery::pkg::apis::meta::v1::OwnerReference,
};
use kube::{Resource, ResourceExt};
use serde::{Deserialize, Serialize};
use tracing::{debug, trace, warn};

use crate::k8s::attributor::{K8sObjectMeta, ResourceStore, WorkloadOwner};

/// Configuration for K8s owner reference walking
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct OwnerRelationsRules {
    /// Maximum depth to walk owner references
    pub max_depth: usize,
    /// Include only these owner kinds in flow metadata (case insensitive)
    /// Empty list means include all kinds
    pub include_kinds: Vec<String>,
    /// Exclude these owner kinds from flow metadata (case insensitive)
    /// Exclusions take precedence over inclusions
    pub exclude_kinds: Vec<String>,
}

impl Default for OwnerRelationsRules {
    fn default() -> Self {
        Self {
            max_depth: 5,
            include_kinds: Vec::new(),
            exclude_kinds: Vec::new(),
        }
    }
}

/// Manages owner reference walking and filtering based on configuration.
///
/// This type is thread-safe (`Send + Sync`) and can be shared across tasks.
/// All state is immutable after construction.
pub struct OwnerRelationsManager {
    max_depth: usize,
    include_kinds: HashSet<String>,
    exclude_kinds: HashSet<String>,
}

/// Maximum number of owners to collect to prevent resource exhaustion
const MAX_OWNERS: usize = 32;

impl OwnerRelationsManager {
    /// Creates a new OwnerRelationsManager from configuration
    ///
    /// All kind names are normalized to lowercase for case-insensitive matching.
    ///
    /// # Examples
    ///
    /// ```
    /// use mermin::k8s::owner_relations::{OwnerRelationsManager, OwnerRelationsOptions};
    ///
    /// // Create a manager that only includes Deployment owners, up to 3 levels deep
    /// let config = OwnerRelationsOptions {
    ///     max_depth: 3,
    ///     include_kinds: vec!["Deployment".to_string()],
    ///     exclude_kinds: vec![],
    /// };
    /// let manager = OwnerRelationsManager::new(config);
    ///
    /// // Use with defaults
    /// let manager = OwnerRelationsManager::new(OwnerRelationsOptions::default());
    /// ```
    pub fn new(config: OwnerRelationsRules) -> Self {
        let include_kinds = config
            .include_kinds
            .iter()
            .map(|k| k.to_lowercase())
            .collect();

        let exclude_kinds = config
            .exclude_kinds
            .iter()
            .map(|k| k.to_lowercase())
            .collect();

        Self {
            max_depth: config.max_depth,
            include_kinds,
            exclude_kinds,
        }
    }

    /// Walks the owner reference chain and returns all owners up to max_depth,
    /// filtered according to include/exclude rules.
    ///
    /// Returns the filtered list of WorkloadOwners that should be included in
    /// flow metadata. Returns None if no owners are found or all are filtered out.
    #[must_use]
    pub fn get_owners(&self, pod: &Pod, store: &ResourceStore) -> Option<Vec<WorkloadOwner>> {
        let pod_name = pod.name_any();
        let owner_refs = pod.owner_references();

        trace!(
            event.name = "k8s.get_owners.start",
            k8s.pod.name = %pod_name,
            k8s.owner_refs.count = owner_refs.len(),
            "starting owner chain walk"
        );

        let all_owners = self.walk_owner_chain(pod, store);

        trace!(
            event.name = "k8s.get_owners.walked",
            k8s.pod.name = %pod_name,
            k8s.owners.collected = all_owners.len(),
            "completed owner chain walk"
        );

        if all_owners.is_empty() {
            trace!(
                event.name = "k8s.get_owners.empty",
                k8s.pod.name = %pod_name,
                "no owners found in chain"
            );
            return None;
        }

        let filtered = self.filter_owners(all_owners);

        trace!(
            event.name = "k8s.get_owners.filtered",
            k8s.pod.name = %pod_name,
            k8s.owners.filtered = filtered.len(),
            "completed owner filtering"
        );

        if filtered.is_empty() {
            None
        } else {
            Some(filtered)
        }
    }

    /// Walks the owner reference chain up to max_depth, collecting all owners encountered.
    ///
    /// # Behavior
    /// - If `max_depth` is 0, returns an empty vector (no owners walked)
    /// - Stops early if no more owner references are found
    /// - Stops if MAX_OWNERS limit is reached to prevent resource exhaustion
    fn walk_owner_chain(&self, pod: &Pod, store: &ResourceStore) -> Vec<WorkloadOwner> {
        let mut all_owners = Vec::with_capacity(self.max_depth.min(8));
        let mut current_owners = pod.owner_references().to_vec();
        let mut namespace = pod.namespace().unwrap_or_default();
        let mut depth = 0;

        while !current_owners.is_empty() && depth < self.max_depth && all_owners.len() < MAX_OWNERS
        {
            depth += 1;

            // Process all owners at this level
            let mut next_level_owners = Vec::new();

            for owner_ref in current_owners {
                if let Some((owner, next_owners_opt)) =
                    self.lookup_owner(&owner_ref, &namespace, store)
                {
                    all_owners.push(owner.clone());

                    // Update namespace if this owner has one
                    if let Some(ns) = self.get_owner_namespace(&owner) {
                        namespace = ns;
                    }

                    // Queue up the next level of owners
                    if let Some(next_owners) = next_owners_opt {
                        next_level_owners.extend(next_owners);
                    }
                } else {
                    debug!(
                        event.name = "k8s.owner_ref_missing",
                        k8s.owner.name = %owner_ref.name,
                        k8s.owner.kind = %owner_ref.kind,
                        k8s.namespace = %namespace,
                        "failed to find owner reference in local store"
                    );
                }
            }

            current_owners = next_level_owners;
        }

        if all_owners.len() >= MAX_OWNERS {
            warn!(
                event.name = "k8s.owner_chain_truncated",
                k8s.owner.count = all_owners.len(),
                k8s.owner.max = MAX_OWNERS,
                "owner chain truncated at maximum owner count for safety"
            );
        }

        all_owners
    }

    /// Filters the list of owners based on include/exclude rules.
    ///
    /// Logic:
    /// - If exclude_kinds contains the kind, exclude it (highest priority)
    /// - If include_kinds is non-empty and doesn't contain the kind, exclude it
    /// - Otherwise, include it
    fn filter_owners(&self, owners: Vec<WorkloadOwner>) -> Vec<WorkloadOwner> {
        owners
            .into_iter()
            .filter(|owner| self.should_include_owner(owner))
            .collect()
    }

    /// Determines if an owner should be included based on the configuration rules.
    fn should_include_owner(&self, owner: &WorkloadOwner) -> bool {
        let kind = match owner {
            WorkloadOwner::ReplicaSet(_) => "replicaset",
            WorkloadOwner::Deployment(_) => "deployment",
            WorkloadOwner::StatefulSet(_) => "statefulset",
            WorkloadOwner::DaemonSet(_) => "daemonset",
            WorkloadOwner::Job(_) => "job",
            WorkloadOwner::CronJob(_) => "cronjob",
        };

        // Exclude takes precedence
        if self.exclude_kinds.contains(kind) {
            return false;
        }

        // If include_kinds is empty, include all (that aren't excluded)
        if self.include_kinds.is_empty() {
            return true;
        }

        // Otherwise, only include if in the include list
        self.include_kinds.contains(kind)
    }

    /// Looks up a single owner reference in the resource store.
    fn lookup_owner(
        &self,
        owner_ref: &OwnerReference,
        namespace: &str,
        store: &ResourceStore,
    ) -> Option<(WorkloadOwner, Option<Vec<OwnerReference>>)> {
        let name = &owner_ref.name;
        let kind = &owner_ref.kind;

        trace!(
            event.name = "k8s.lookup_owner.start",
            k8s.owner.name = %name,
            k8s.owner.kind = %kind,
            k8s.namespace = %namespace,
            "looking up owner in resource store"
        );

        macro_rules! find_in_store {
            ($store_type:ty, $variant:ident) => {{
                let resources = store.get_by_namespace::<$store_type>(namespace);
                let resource_count = resources.len();
                debug!(
                    event.name = "k8s.lookup_owner.store_check",
                    k8s.owner.kind = %kind,
                    k8s.namespace = %namespace,
                    k8s.resources.count = resource_count,
                    "checking resource store"
                );

                resources
                    .iter()
                    .find(|obj| obj.name_any() == *name)
                    .map(|obj| {
                        let meta = K8sObjectMeta::from(obj.as_ref());
                        let next_owners = obj.meta().owner_references.clone();
                        let next_refs_count = next_owners.as_ref().map(|v| v.len()).unwrap_or(0);
                        trace!(
                            event.name = "k8s.lookup_owner.found",
                            k8s.owner.name = %name,
                            k8s.owner.kind = %kind,
                            k8s.owner.next_refs = next_refs_count,
                            "found owner in store"
                        );
                        (WorkloadOwner::$variant(meta), next_owners)
                    })
            }};
        }

        let result = match owner_ref.kind.as_str() {
            "ReplicaSet" => find_in_store!(ReplicaSet, ReplicaSet),
            "Deployment" => find_in_store!(Deployment, Deployment),
            "StatefulSet" => find_in_store!(StatefulSet, StatefulSet),
            "DaemonSet" => find_in_store!(DaemonSet, DaemonSet),
            "Job" => find_in_store!(Job, Job),
            "CronJob" => find_in_store!(CronJob, CronJob),
            _ => {
                debug!(
                    event.name = "k8s.unsupported_owner_kind",
                    k8s.owner.kind = %owner_ref.kind,
                    "owner lookup for this resource kind is not implemented"
                );
                None
            }
        };

        if result.is_none() {
            trace!(
                event.name = "k8s.lookup_owner.not_found",
                k8s.owner.name = %name,
                k8s.owner.kind = %kind,
                k8s.namespace = %namespace,
                "owner not found in resource store"
            );
        }

        result
    }

    /// Gets the namespace from a WorkloadOwner.
    fn get_owner_namespace(&self, owner: &WorkloadOwner) -> Option<String> {
        match owner {
            WorkloadOwner::Deployment(m) => m.namespace.clone(),
            WorkloadOwner::ReplicaSet(m) => m.namespace.clone(),
            WorkloadOwner::StatefulSet(m) => m.namespace.clone(),
            WorkloadOwner::DaemonSet(m) => m.namespace.clone(),
            WorkloadOwner::Job(m) => m.namespace.clone(),
            WorkloadOwner::CronJob(m) => m.namespace.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config(
        max_depth: usize,
        include_kinds: Vec<&str>,
        exclude_kinds: Vec<&str>,
    ) -> OwnerRelationsRules {
        OwnerRelationsRules {
            max_depth,
            include_kinds: include_kinds.iter().map(|s| s.to_string()).collect(),
            exclude_kinds: exclude_kinds.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn create_test_owner(kind: &str) -> WorkloadOwner {
        let meta = K8sObjectMeta {
            kind: kind.to_string(),
            name: format!("test-{}", kind.to_lowercase()),
            uid: Some("test-uid".to_string()),
            namespace: Some("default".to_string()),
            labels: None,
            annotations: None,
        };

        match kind {
            "ReplicaSet" => WorkloadOwner::ReplicaSet(meta),
            "Deployment" => WorkloadOwner::Deployment(meta),
            "StatefulSet" => WorkloadOwner::StatefulSet(meta),
            "DaemonSet" => WorkloadOwner::DaemonSet(meta),
            "Job" => WorkloadOwner::Job(meta),
            "CronJob" => WorkloadOwner::CronJob(meta),
            _ => panic!("Unsupported kind: {}", kind),
        }
    }

    #[test]
    fn test_filter_with_empty_include_list() {
        let config = create_test_config(5, vec![], vec![]);
        let manager = OwnerRelationsManager::new(config);

        let owners = vec![
            create_test_owner("ReplicaSet"),
            create_test_owner("Deployment"),
            create_test_owner("Job"),
        ];

        let filtered = manager.filter_owners(owners.clone());
        assert_eq!(
            filtered.len(),
            3,
            "All owners should be included when include_kinds is empty"
        );
    }

    #[test]
    fn test_filter_with_include_list() {
        let config = create_test_config(5, vec!["Deployment", "Job"], vec![]);
        let manager = OwnerRelationsManager::new(config);

        let owners = vec![
            create_test_owner("ReplicaSet"),
            create_test_owner("Deployment"),
            create_test_owner("Job"),
        ];

        let filtered = manager.filter_owners(owners);
        assert_eq!(
            filtered.len(),
            2,
            "Only Deployment and Job should be included"
        );

        // Verify the correct owners are present
        let has_deployment = filtered
            .iter()
            .any(|o| matches!(o, WorkloadOwner::Deployment(_)));
        let has_job = filtered.iter().any(|o| matches!(o, WorkloadOwner::Job(_)));
        let has_replicaset = filtered
            .iter()
            .any(|o| matches!(o, WorkloadOwner::ReplicaSet(_)));

        assert!(has_deployment, "Deployment should be included");
        assert!(has_job, "Job should be included");
        assert!(!has_replicaset, "ReplicaSet should not be included");
    }

    #[test]
    fn test_filter_with_exclude_list() {
        let config = create_test_config(5, vec![], vec!["ReplicaSet"]);
        let manager = OwnerRelationsManager::new(config);

        let owners = vec![
            create_test_owner("ReplicaSet"),
            create_test_owner("Deployment"),
            create_test_owner("Job"),
        ];

        let filtered = manager.filter_owners(owners);
        assert_eq!(filtered.len(), 2, "ReplicaSet should be excluded");

        let has_replicaset = filtered
            .iter()
            .any(|o| matches!(o, WorkloadOwner::ReplicaSet(_)));
        assert!(!has_replicaset, "ReplicaSet should be excluded");
    }

    #[test]
    fn test_exclude_takes_precedence_over_include() {
        let config = create_test_config(5, vec!["Deployment", "Job"], vec!["Deployment"]);
        let manager = OwnerRelationsManager::new(config);

        let owners = vec![create_test_owner("Deployment"), create_test_owner("Job")];

        let filtered = manager.filter_owners(owners);
        assert_eq!(filtered.len(), 1, "Only Job should be included");

        let has_deployment = filtered
            .iter()
            .any(|o| matches!(o, WorkloadOwner::Deployment(_)));
        let has_job = filtered.iter().any(|o| matches!(o, WorkloadOwner::Job(_)));

        assert!(
            !has_deployment,
            "Deployment should be excluded (exclude takes precedence)"
        );
        assert!(has_job, "Job should be included");
    }

    #[test]
    fn test_case_insensitive_matching() {
        // Test that kind matching is case-insensitive
        let config = create_test_config(5, vec!["DEPLOYMENT", "job"], vec!["ReplicaSet"]);
        let manager = OwnerRelationsManager::new(config);

        let owners = vec![
            create_test_owner("ReplicaSet"),
            create_test_owner("Deployment"),
            create_test_owner("Job"),
        ];

        let filtered = manager.filter_owners(owners);
        assert_eq!(filtered.len(), 2, "Case-insensitive matching should work");

        let has_deployment = filtered
            .iter()
            .any(|o| matches!(o, WorkloadOwner::Deployment(_)));
        let has_job = filtered.iter().any(|o| matches!(o, WorkloadOwner::Job(_)));
        let has_replicaset = filtered
            .iter()
            .any(|o| matches!(o, WorkloadOwner::ReplicaSet(_)));

        assert!(has_deployment, "Deployment should match DEPLOYMENT");
        assert!(has_job, "Job should match job");
        assert!(!has_replicaset, "ReplicaSet should be excluded");
    }

    #[test]
    fn test_max_depth_configuration() {
        let config = create_test_config(3, vec![], vec![]);
        let manager = OwnerRelationsManager::new(config);
        assert_eq!(manager.max_depth, 3, "max_depth should be set from config");
    }

    #[test]
    fn test_default_config_values() {
        let config = OwnerRelationsRules::default();
        assert_eq!(config.max_depth, 5, "Default max_depth should be 5");
        assert!(
            config.include_kinds.is_empty(),
            "Default include_kinds should be empty"
        );
        assert!(
            config.exclude_kinds.is_empty(),
            "Default exclude_kinds should be empty"
        );
    }

    #[test]
    fn test_all_owner_types() {
        let config = create_test_config(5, vec![], vec![]);
        let manager = OwnerRelationsManager::new(config);

        let owners = vec![
            create_test_owner("ReplicaSet"),
            create_test_owner("Deployment"),
            create_test_owner("StatefulSet"),
            create_test_owner("DaemonSet"),
            create_test_owner("Job"),
            create_test_owner("CronJob"),
        ];

        let filtered = manager.filter_owners(owners.clone());
        assert_eq!(filtered.len(), 6, "All owner types should be supported");
    }

    #[test]
    fn test_mixed_include_and_exclude() {
        // Test various combinations of include and exclude
        let config = create_test_config(
            5,
            vec!["Deployment", "StatefulSet", "Job"],
            vec!["StatefulSet"],
        );
        let manager = OwnerRelationsManager::new(config);

        let owners = vec![
            create_test_owner("ReplicaSet"),
            create_test_owner("Deployment"),
            create_test_owner("StatefulSet"),
            create_test_owner("Job"),
        ];

        let filtered = manager.filter_owners(owners);
        assert_eq!(
            filtered.len(),
            2,
            "Should have Deployment and Job (StatefulSet excluded, ReplicaSet not in include)"
        );

        let has_deployment = filtered
            .iter()
            .any(|o| matches!(o, WorkloadOwner::Deployment(_)));
        let has_job = filtered.iter().any(|o| matches!(o, WorkloadOwner::Job(_)));
        let has_statefulset = filtered
            .iter()
            .any(|o| matches!(o, WorkloadOwner::StatefulSet(_)));
        let has_replicaset = filtered
            .iter()
            .any(|o| matches!(o, WorkloadOwner::ReplicaSet(_)));

        assert!(has_deployment, "Deployment should be included");
        assert!(has_job, "Job should be included");
        assert!(!has_statefulset, "StatefulSet should be excluded");
        assert!(
            !has_replicaset,
            "ReplicaSet should not be included (not in include list)"
        );
    }

    #[test]
    fn test_empty_owner_list() {
        let config = create_test_config(5, vec![], vec![]);
        let manager = OwnerRelationsManager::new(config);

        let owners = vec![];
        let filtered = manager.filter_owners(owners);
        assert_eq!(filtered.len(), 0, "Empty list should remain empty");
    }

    #[test]
    fn test_all_owners_filtered_out() {
        let config = create_test_config(5, vec!["Deployment"], vec![]);
        let manager = OwnerRelationsManager::new(config);

        let owners = vec![create_test_owner("ReplicaSet"), create_test_owner("Job")];

        let filtered = manager.filter_owners(owners);
        assert_eq!(
            filtered.len(),
            0,
            "All owners should be filtered out when none match include list"
        );
    }

    #[test]
    fn test_max_depth_zero() {
        // Test that max_depth of 0 is respected (though unusual)
        let config = create_test_config(0, vec![], vec![]);
        let manager = OwnerRelationsManager::new(config);
        assert_eq!(manager.max_depth, 0, "max_depth of 0 should be allowed");

        // Note: With max_depth = 0, walk_owner_chain would return an empty vector
        // because the while loop condition `depth < self.max_depth` would be false
        // from the start (0 < 0 is false). This is the expected behavior.
    }

    #[test]
    fn test_max_depth_large_value() {
        // Test that large max_depth values are accepted
        let config = create_test_config(100, vec![], vec![]);
        let manager = OwnerRelationsManager::new(config);
        assert_eq!(manager.max_depth, 100, "Large max_depth should be allowed");
    }

    #[test]
    fn test_include_kinds_normalization() {
        // Verify that include_kinds are normalized to lowercase
        let config = create_test_config(5, vec!["DEPLOYMENT", "Job", "StatefulSet"], vec![]);
        let manager = OwnerRelationsManager::new(config);

        assert!(
            manager.include_kinds.contains("deployment"),
            "DEPLOYMENT should be normalized to deployment"
        );
        assert!(
            manager.include_kinds.contains("job"),
            "Job should be normalized to job"
        );
        assert!(
            manager.include_kinds.contains("statefulset"),
            "StatefulSet should be normalized to statefulset"
        );
    }

    #[test]
    fn test_exclude_kinds_normalization() {
        // Verify that exclude_kinds are normalized to lowercase
        let config = create_test_config(5, vec![], vec!["REPLICASET", "DaemonSet"]);
        let manager = OwnerRelationsManager::new(config);

        assert!(
            manager.exclude_kinds.contains("replicaset"),
            "REPLICASET should be normalized to replicaset"
        );
        assert!(
            manager.exclude_kinds.contains("daemonset"),
            "DaemonSet should be normalized to daemonset"
        );
    }

    #[test]
    fn test_should_include_owner_with_various_kinds() {
        let config = create_test_config(5, vec!["Deployment"], vec!["Job"]);
        let manager = OwnerRelationsManager::new(config);

        // Deployment is in include list
        assert!(
            manager.should_include_owner(&create_test_owner("Deployment")),
            "Deployment should be included"
        );

        // Job is explicitly excluded
        assert!(
            !manager.should_include_owner(&create_test_owner("Job")),
            "Job should be excluded"
        );

        // ReplicaSet is not in include list and not excluded
        assert!(
            !manager.should_include_owner(&create_test_owner("ReplicaSet")),
            "ReplicaSet should not be included (not in include list)"
        );
    }

    #[test]
    fn test_max_owners_constant() {
        // Verify the MAX_OWNERS constant is set to the expected value
        assert_eq!(
            MAX_OWNERS, 32,
            "MAX_OWNERS should be 32 to prevent resource exhaustion"
        );
    }

    #[test]
    fn test_default_config_includes_all_owner_types() {
        // This is critical: the default configuration should NOT filter out any owners
        // This test would have caught the config file bug where include_kinds=["Service"]
        // was filtering out DaemonSets
        let config = OwnerRelationsRules::default();
        let manager = OwnerRelationsManager::new(config);

        // Create all supported owner types
        let owners = vec![
            create_test_owner("DaemonSet"),
            create_test_owner("Deployment"),
            create_test_owner("ReplicaSet"),
            create_test_owner("StatefulSet"),
            create_test_owner("Job"),
            create_test_owner("CronJob"),
        ];

        let filtered = manager.filter_owners(owners);

        assert_eq!(
            filtered.len(),
            6,
            "Default configuration should include all owner types (empty include_kinds = include all)"
        );

        // Verify all types are present
        assert!(
            filtered
                .iter()
                .any(|o| matches!(o, WorkloadOwner::DaemonSet(_)))
        );
        assert!(
            filtered
                .iter()
                .any(|o| matches!(o, WorkloadOwner::Deployment(_)))
        );
        assert!(
            filtered
                .iter()
                .any(|o| matches!(o, WorkloadOwner::ReplicaSet(_)))
        );
        assert!(
            filtered
                .iter()
                .any(|o| matches!(o, WorkloadOwner::StatefulSet(_)))
        );
        assert!(filtered.iter().any(|o| matches!(o, WorkloadOwner::Job(_))));
        assert!(
            filtered
                .iter()
                .any(|o| matches!(o, WorkloadOwner::CronJob(_)))
        );
    }

    #[test]
    fn test_filtering_behavior_matches_docs() {
        // Test that verifies the documented filtering behavior:
        // "Empty include_kinds list means include all kinds"

        let config = OwnerRelationsRules {
            max_depth: 5,
            include_kinds: vec![], // Empty = include all
            exclude_kinds: vec![],
        };
        let manager = OwnerRelationsManager::new(config);

        let owners = vec![
            create_test_owner("DaemonSet"),
            create_test_owner("Deployment"),
        ];

        let filtered = manager.filter_owners(owners);
        assert_eq!(
            filtered.len(),
            2,
            "Empty include_kinds should include all owners"
        );
    }
}
