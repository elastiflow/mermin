# Custom Resource Definition (CRD) Support for K8s Relations

## Overview

This document outlines the design for extending Mermin's Kubernetes resource relations to support Custom Resource Definitions (CRDs). This includes both **selector-based relations** and **owner reference relations**. Unlike built-in Kubernetes resources, CRDs are dynamically defined and can have arbitrary schemas, making them significantly more complex to support.

## Current State

### Selector Relations

Mermin supports selector-based relations for the following built-in Kubernetes resources:

- **Network Resources**: NetworkPolicy, Service
- **Workload Controllers**: Deployment, ReplicaSet, StatefulSet, DaemonSet, Job, CronJob

These resources are statically compiled into the codebase using `k8s-openapi` types, with hardcoded knowledge of where selectors exist in their schemas (e.g., `spec.selector`, `spec.podSelector`).

### Owner Relations

Mermin supports owner reference walking for the following built-in workload controllers:

- **Workload Controllers**: Deployment, ReplicaSet, StatefulSet, DaemonSet, Job, CronJob

Owner relations work by:

1. Reading `metadata.ownerReferences` from a Pod
2. Looking up the owner resource in the `ResourceStore`
3. Recursively walking up the ownership chain
4. Filtering based on configured `include_kinds` and `exclude_kinds`

**Example ownership chains:**

- `Pod ← ReplicaSet ← Deployment`
- `Pod ← Job ← CronJob`
- `Pod ← StatefulSet`

CRDs are **currently not supported** in owner relations, even though they may appear in `ownerReferences`.

### Selector Relations vs Owner Relations

Understanding when to use each relation type:

| Feature                      | Selector Relations                               | Owner Relations                                  |
|------------------------------|--------------------------------------------------|--------------------------------------------------|
| **Mechanism**                | Match pod labels against resource selectors      | Walk `metadata.ownerReferences` chain            |
| **Direction**                | Resource → Pod (top-down)                        | Pod → Owner (bottom-up)                          |
| **Use Case**                 | Network policies, services, non-owning resources | Deployment hierarchy, operator-managed resources |
| **Cardinality**              | One-to-many (one policy selects many pods)       | Many-to-one (many pods share one owner)          |
| **Configuration Complexity** | Requires field paths to selectors                | Only requires resource kinds                     |
| **Example (Built-in)**       | NetworkPolicy selects Pods via podSelector       | Pod owned by ReplicaSet owned by Deployment      |
| **Example (CRD)**            | Istio VirtualService selects Pods                | ArgoCD Application owns Deployment               |

**When to use Selector Relations:**

- Network policy enforcement tracking
- Service mesh configuration
- Custom ingress/gateway associations
- Any resource that "selects" pods but doesn't own them

**When to use Owner Relations:**

- Tracking deployment hierarchy
- GitOps application tracking
- Progressive delivery tracking
- Operator-managed resource chains

**Can use both:**

- Knative Services (selectors for routing + ownership hierarchy)
- Custom operators that both own and select resources

## Challenges with CRD Support

### 1. Dynamic Schema

- CRDs are defined at runtime via CustomResourceDefinition manifests
- Schema is not known at compile time
- Each CRD can have selectors at arbitrary field paths
- No standard location for selectors like built-in resources

### 2. Type Safety

- Current implementation uses strongly-typed `k8s-openapi` structs
- CRDs require working with untyped JSON/YAML structures
- Need to balance type safety with flexibility

### 3. Discovery & Registration

- System must discover available CRDs in the cluster
- Users must specify which CRDs to track and where their selectors are
- Configuration complexity increases significantly

### 4. Resource Storage & Caching

- Current `ResourceStore` uses generic type parameters with `kube::Resource` trait
- CRDs would require dynamic typing or trait objects
- Reflectors and watchers need to be created dynamically

### 5. Performance & Memory

- Watching many CRDs can significantly increase memory usage
- Need to allow selective CRD watching to avoid resource exhaustion

### 6. Owner Reference Ambiguity (Owner Relations)

- `ownerReferences` only contain `apiVersion` and `kind`, not explicit CRD registration
- Need to parse `apiVersion` to extract group and version
- Multiple CRD versions may exist (v1alpha1, v1beta1, v1) with different schemas
- Owner chain depth can be arbitrary with CRDs (e.g., `Pod ← CustomResource1 ← CustomResource2 ← CustomResource3`)

### 7. Attribute Namespace Collision (Owner Relations)

- Built-in resources use predictable attribute names: `k8s.deployment.name`, `k8s.job.name`
- CRDs may have conflicting kind names across different API groups
- Need strategy to avoid collision: `k8s.myoperator.io.myresource.name` vs `k8s.myresource.name`

## Proposed Solution

### Phase 1: Generic JSON-based CRD Support

#### Configuration Extension for Selector Relations

Extend `SelectorRelationRule` to support CRDs with explicit field paths:

```hcl
selector_relations = [
  # Existing built-in resource
  {
    kind                             = "NetworkPolicy"
    to                               = "Pod"
    selector_match_labels_field      = "spec.podSelector.matchLabels"
    selector_match_expressions_field = "spec.podSelector.matchExpressions"
  },

  # Custom CRD example: Istio VirtualService
  {
    kind                             = "VirtualService"
    api_version                      = "networking.istio.io/v1beta1"  # NEW
    to                               = "Pod"
    selector_match_labels_field      = "spec.workloadSelector.labels"
    custom_resource                  = true  # NEW: marks as CRD
  },

  # Custom CRD example: Cilium CiliumNetworkPolicy
  {
    kind                             = "CiliumNetworkPolicy"
    api_version                      = "cilium.io/v2"
    to                               = "Pod"
    selector_match_labels_field      = "spec.endpointSelector.matchLabels"
    selector_match_expressions_field = "spec.endpointSelector.matchExpressions"
    custom_resource                  = true
  }
]
```

#### New Configuration Fields

```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SelectorRelationRule {
    /// The kind of resource
    pub kind: String,

    /// API version (required for CRDs, optional for built-in resources)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_version: Option<String>,

    /// The kind of resource to match against
    pub to: String,

    /// JSON path to the matchLabels field
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector_match_labels_field: Option<String>,

    /// JSON path to the matchExpressions field
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector_match_expressions_field: Option<String>,

    /// Marks this as a custom resource (CRD)
    #[serde(default)]
    pub custom_resource: bool,
}
```

#### Configuration Extension for Owner Relations

Extend `OwnerRelationsOptions` to support CRDs in ownership chains:

```hcl
discovery {
  informer {
    k8s {
      owner_relations {
        max_depth = 5

        # Built-in resources
        include_kinds = [
          "Deployment", "ReplicaSet", "StatefulSet",
          "DaemonSet", "Job", "CronJob"
        ]

        # NEW: Custom resources that participate in ownership chains
        custom_owner_kinds = [
          {
            kind        = "ArgoCD"
            api_version = "argoproj.io/v1alpha1"
            # Attribute name for flow metadata (defaults to lowercased kind)
            attribute_name = "argocd"  # Results in k8s.argocd.name
          },
          {
            kind        = "Rollout"
            api_version = "argoproj.io/v1alpha1"
            attribute_name = "rollout"  # Results in k8s.rollout.name
          },
          {
            kind        = "Application"
            api_version = "app.k8s.io/v1beta1"
            # Include API group in attribute to avoid collisions
            attribute_name = "app.k8s.io.application"  # Results in k8s.app.k8s.io.application.name
          }
        ]
      }
    }
  }
}
```

#### New Configuration Structures for Owner Relations

```rust
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct OwnerRelationsOptions {
    /// Maximum depth to walk up the ownership chain
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,

    /// Built-in resource kinds to include (existing field)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_kinds: Vec<String>,

    /// Built-in resource kinds to exclude (existing field)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_kinds: Vec<String>,

    /// NEW: Custom resources that can appear in owner chains
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_owner_kinds: Vec<CustomOwnerKind>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CustomOwnerKind {
    /// The kind of custom resource
    pub kind: String,

    /// API version (e.g., "argoproj.io/v1alpha1")
    pub api_version: String,

    /// Attribute name for flow metadata (optional, defaults to lowercased kind)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute_name: Option<String>,
}
```

#### ResourceStore Extension

Create a new `DynamicResourceStore` for CRDs:

```rust
pub struct ResourceStore {
    // Existing typed stores
    pub pods: reflector::Store<Pod>,
    pub services: reflector::Store<Service>,
    // ... other built-in types

    // NEW: Dynamic stores for CRDs
    pub custom_resources: DynamicResourceStore,
}

pub struct DynamicResourceStore {
    /// Map from (api_version, kind) to dynamic resource store
    stores: Arc<RwLock<HashMap<(String, String), reflector::Store<DynamicObject>>>>,
}

impl DynamicResourceStore {
    pub async fn add_resource_type(
        &mut self,
        client: Client,
        api_version: &str,
        kind: &str,
    ) -> Result<(), K8sError> {
        let api_resource = ApiResource {
            group: parse_group(api_version),
            version: parse_version(api_version),
            kind: kind.to_string(),
            plural: kind.to_lowercase() + "s", // TODO: proper pluralization
        };

        let api: Api<DynamicObject> = Api::all_with(client, &api_resource);
        let (store, writer) = reflector::store();

        tokio::spawn(async move {
            reflector(writer, watcher(api, Config::default()))
                .applied_objects()
                .try_for_each(|_| async { Ok(()) })
                .await
        });

        self.stores.write().unwrap().insert(
            (api_version.to_string(), kind.to_string()),
            store
        );

        Ok(())
    }

    pub fn get(&self, api_version: &str, kind: &str) -> Vec<DynamicObject> {
        self.stores
            .read()
            .unwrap()
            .get(&(api_version.to_string(), kind.to_string()))
            .map(|store| store.state())
            .unwrap_or_default()
    }
}
```

#### Selector Extraction for CRDs

Implement generic field path extraction:

```rust
impl SelectorRelationsManager {
    fn extract_selector_from_custom_resource(
        &self,
        obj: &DynamicObject,
        rule: &NormalizedRule,
    ) -> Option<LabelSelector> {
        let data = obj.data.as_object()?;

        let mut selector = LabelSelector::default();

        // Extract matchLabels if field path is specified
        if let Some(labels_path) = &rule.selector_match_labels_field {
            if let Some(labels) = self.extract_json_field(data, labels_path) {
                if let Some(labels_map) = labels.as_object() {
                    selector.match_labels = Some(
                        labels_map
                            .iter()
                            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                            .collect()
                    );
                }
            }
        }

        // Extract matchExpressions if field path is specified
        if let Some(expr_path) = &rule.selector_match_expressions_field {
            if let Some(expressions) = self.extract_json_field(data, expr_path) {
                if let Some(expr_array) = expressions.as_array() {
                    selector.match_expressions = Some(
                        expr_array
                            .iter()
                            .filter_map(|e| self.parse_match_expression(e))
                            .collect()
                    );
                }
            }
        }

        Some(selector)
    }

    fn extract_json_field<'a>(
        &self,
        obj: &'a serde_json::Map<String, serde_json::Value>,
        path: &str,
    ) -> Option<&'a serde_json::Value> {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current: &serde_json::Value = &serde_json::Value::Object(obj.clone());

        for part in parts {
            current = current.get(part)?;
        }

        Some(current)
    }

    fn parse_match_expression(
        &self,
        value: &serde_json::Value,
    ) -> Option<LabelSelectorRequirement> {
        let obj = value.as_object()?;

        Some(LabelSelectorRequirement {
            key: obj.get("key")?.as_str()?.to_string(),
            operator: obj.get("operator")?.as_str()?.to_string(),
            values: obj.get("values")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()),
        })
    }
}
```

#### Owner Relations Implementation for CRDs

Extend `OwnerRelationsManager` to handle CRD owners:

```rust
impl OwnerRelationsManager {
    pub fn new(options: OwnerRelationsOptions) -> Self {
        // Existing normalization for built-in kinds
        let include_kinds: HashSet<String> = options
            .include_kinds
            .iter()
            .map(|k| k.to_lowercase())
            .collect();

        let exclude_kinds: HashSet<String> = options
            .exclude_kinds
            .iter()
            .map(|k| k.to_lowercase())
            .collect();

        // NEW: Build lookup map for custom owners
        // Map from (api_version, kind) -> attribute_name
        let custom_owners: HashMap<(String, String), String> = options
            .custom_owner_kinds
            .iter()
            .map(|co| {
                let key = (co.api_version.clone(), co.kind.to_lowercase());
                let attribute = co.attribute_name
                    .clone()
                    .unwrap_or_else(|| co.kind.to_lowercase());
                (key, attribute)
            })
            .collect();

        Self {
            max_depth: options.max_depth,
            include_kinds,
            exclude_kinds,
            custom_owners,  // NEW field
        }
    }

    /// Looks up a single owner reference (extended to support CRDs)
    fn lookup_owner(
        &self,
        owner_ref: &OwnerReference,
        namespace: &str,
        store: &ResourceStore,
    ) -> Option<(WorkloadOwner, Option<Vec<OwnerReference>>)> {
        let name = &owner_ref.name;
        let kind = &owner_ref.kind;
        let api_version = &owner_ref.api_version;

        // Try built-in resources first (existing logic)
        let result = match kind.to_lowercase().as_str() {
            "replicaset" => find_in_store!(ReplicaSet, ReplicaSet),
            "deployment" => find_in_store!(Deployment, Deployment),
            "statefulset" => find_in_store!(StatefulSet, StatefulSet),
            "daemonset" => find_in_store!(DaemonSet, DaemonSet),
            "job" => find_in_store!(Job, Job),
            "cronjob" => find_in_store!(CronJob, CronJob),
            _ => None,
        };

        if result.is_some() {
            return result;
        }

        // NEW: Try custom resources
        let lookup_key = (api_version.clone(), kind.to_lowercase());
        if let Some(attribute_name) = self.custom_owners.get(&lookup_key) {
            return self.lookup_custom_owner(
                name,
                api_version,
                kind,
                attribute_name,
                namespace,
                store,
            );
        }

        None
    }

    /// Looks up a custom resource owner from the dynamic store
    fn lookup_custom_owner(
        &self,
        name: &str,
        api_version: &str,
        kind: &str,
        attribute_name: &str,
        namespace: &str,
        store: &ResourceStore,
    ) -> Option<(WorkloadOwner, Option<Vec<OwnerReference>>)> {
        let resources = store.custom_resources.get(api_version, kind);

        resources
            .iter()
            .find(|obj| {
                obj.metadata.name.as_ref() == Some(&name.to_string())
                    && obj.metadata.namespace.as_ref() == Some(&namespace.to_string())
            })
            .map(|obj| {
                let meta = K8sObjectMeta {
                    name: obj.metadata.name.clone().unwrap_or_default(),
                    kind: kind.to_string(),
                    uid: obj.metadata.uid.clone(),
                    namespace: obj.metadata.namespace.clone(),
                    labels: obj.metadata.labels.clone(),
                    annotations: obj.metadata.annotations.clone(),
                };

                let next_owners = obj.metadata.owner_references.clone();

                // Use the configured attribute name for this CRD
                let owner = WorkloadOwner::Custom {
                    meta,
                    attribute_name: attribute_name.to_string(),
                };

                (owner, next_owners)
            })
    }
}
```

#### Extended WorkloadOwner Enum

Add support for custom resources:

```rust
#[derive(Debug, Clone)]
pub enum WorkloadOwner {
    // Built-in resources
    ReplicaSet(K8sObjectMeta),
    Deployment(K8sObjectMeta),
    StatefulSet(K8sObjectMeta),
    DaemonSet(K8sObjectMeta),
    Job(K8sObjectMeta),
    CronJob(K8sObjectMeta),

    // NEW: Generic custom resource
    Custom {
        meta: K8sObjectMeta,
        attribute_name: String,  // e.g., "argocd", "app.k8s.io.application"
    },
}
```

#### Flow Attribute Population for CRD Owners

Extend `parser.rs` to handle custom owners:

```rust
impl SpanDecorator {
    fn populate_workload_attributes(
        &self,
        flow_span: &mut FlowSpan,
        owner: &WorkloadOwner,
        is_source: bool,
    ) {
        match owner {
            // Existing built-in types
            WorkloadOwner::Deployment(meta) => {
                self.set_k8s_attr(flow_span, "deployment.name", &meta.name, is_source);
            }
            WorkloadOwner::ReplicaSet(meta) => {
                self.set_k8s_attr(flow_span, "replicaset.name", &meta.name, is_source);
            }
            // ... other built-in types ...

            // NEW: Custom resource
            WorkloadOwner::Custom { meta, attribute_name } => {
                // Use the configured attribute name
                let attr_key = format!("{}.name", attribute_name);
                self.set_k8s_attr(flow_span, &attr_key, &meta.name, is_source);

                trace!(
                    event.name = "k8s.custom_owner.attribute_set",
                    k8s.resource.kind = %meta.kind,
                    k8s.resource.name = %meta.name,
                    k8s.attribute_name = %attribute_name,
                    "set custom resource owner attribute"
                );
            }
        }
    }
}
```

### Phase 2: CRD Auto-Discovery (Future Enhancement)

In a future iteration, we could implement automatic CRD discovery:

1. Watch CustomResourceDefinition resources
2. Parse OpenAPIv3 schemas to identify selector fields
3. Auto-generate configuration based on common patterns
4. Allow opt-in/opt-out of discovered CRDs

```hcl
discovery {
  informer {
    k8s {
      # Auto-discover CRDs with selector fields
      auto_discover_crds = true

      # Whitelist/blacklist patterns
      crd_discovery {
        include_groups = ["istio.io", "cilium.io"]
        exclude_groups = ["internal.mycompany.com"]

        # Automatic field detection
        # Look for fields matching these patterns
        selector_field_patterns = [
          "*.selector.matchLabels",
          "*.podSelector.matchLabels",
          "*.endpointSelector.matchLabels",
          "*.workloadSelector.labels"
        ]
      }
    }
  }
}
```

## Implementation Roadmap

### Milestone 1: Foundation (2-3 weeks)

**Selector Relations:**

- [ ] Extend `SelectorRelationRule` configuration struct
- [ ] Implement `DynamicResourceStore` for CRDs
- [ ] Add configuration parsing and validation
- [ ] Unit tests for configuration parsing

**Owner Relations:**

- [ ] Extend `OwnerRelationsOptions` with `custom_owner_kinds`
- [ ] Add `CustomOwnerKind` configuration struct
- [ ] Extend `WorkloadOwner` enum with `Custom` variant
- [ ] Update configuration parsing and validation

### Milestone 2: Core CRD Support (3-4 weeks)

**Selector Relations:**

- [ ] Implement dynamic reflector creation for CRDs
- [ ] Implement generic JSON field path extraction
- [ ] Integrate CRD matching into `SelectorRelationsManager`
- [ ] Add CRD metadata to flow attributes via `populate_selector_relation_attributes()`
- [ ] Integration tests with sample CRDs (Istio, Cilium)

**Owner Relations:**

- [ ] Extend `OwnerRelationsManager` to lookup CRD owners
- [ ] Implement `lookup_custom_owner()` method
- [ ] Build custom owners lookup map in manager constructor
- [ ] Add CRD owner attributes to flow spans in `populate_workload_attributes()`
- [ ] Integration tests with ownership chains (ArgoCD, Argo Rollouts)

### Milestone 3: Production Readiness (2-3 weeks)

- [ ] Performance testing and optimization (both relation types)
- [ ] Memory usage analysis with multiple CRDs
- [ ] Error handling and recovery for missing CRDs
- [ ] Documentation and examples for common platforms
- [ ] Operator validation in real clusters
- [ ] Handle edge cases: circular ownership, deep chains, missing references

### Milestone 4: Auto-Discovery (4-6 weeks, optional)

- [ ] CRD watch and schema parsing
- [ ] Pattern-based selector field detection
- [ ] Dynamic configuration updates
- [ ] Advanced testing with diverse CRDs

## Risks & Mitigations

| Risk                                                                     | Mitigation                                                                |
|--------------------------------------------------------------------------|---------------------------------------------------------------------------|
| **Memory exhaustion from watching too many CRDs**                        | Require explicit opt-in per CRD; provide memory usage warnings            |
| **Invalid field paths causing runtime errors** (Selector Relations)      | Comprehensive validation on startup; graceful error handling              |
| **CRD schema changes breaking selector extraction** (Selector Relations) | Version field paths per API version; emit warnings on extraction failures |
| **Attribute name collisions** (Owner Relations)                          | Require explicit `attribute_name` config; validate uniqueness on startup  |
| **Circular ownership chains** (Owner Relations)                          | Track visited resources in ownership walk; enforce `max_depth` limit      |
| **Missing CRD in ownership chain** (Owner Relations)                     | Gracefully stop chain walk; log missing resource at debug level           |
| **Performance degradation with many CRDs** (Both)                        | Benchmarking; lazy loading; caching strategies; selective watching        |
| **Complex configuration increases user error** (Both)                    | Provide pre-built examples for common CRDs (Istio, Cilium, Argo, Knative) |

## Example Use Cases

### Use Case 1: Istio VirtualService

Match pods selected by Istio VirtualService resources:

```hcl
selector_relations = [
  {
    kind                        = "VirtualService"
    api_version                 = "networking.istio.io/v1beta1"
    to                          = "Pod"
    selector_match_labels_field = "spec.workloadSelector.labels"
    custom_resource             = true
  }
]
```

Result: Flows will have `k8s.virtualservice.name` attribute.

### Use Case 2: Cilium CiliumNetworkPolicy

Match pods selected by Cilium network policies:

```hcl
selector_relations = [
  {
    kind                             = "CiliumNetworkPolicy"
    api_version                      = "cilium.io/v2"
    to                               = "Pod"
    selector_match_labels_field      = "spec.endpointSelector.matchLabels"
    selector_match_expressions_field = "spec.endpointSelector.matchExpressions"
    custom_resource                  = true
  }
]
```

Result: Flows will have `k8s.ciliumnetworkpolicy.name` attribute.

### Use Case 3: Custom Application CRD

Match pods selected by a custom application deployment CRD:

```hcl
selector_relations = [
  {
    kind                        = "AppDeployment"
    api_version                 = "apps.mycompany.io/v1"
    to                          = "Pod"
    selector_match_labels_field = "spec.template.selector"
    custom_resource             = true
  }
]
```

Result: Flows will have `k8s.appdeployment.name` attribute.

---

### Use Case 4: Argo Rollouts (Owner Relations)

Track pods managed by Argo Rollouts progressive delivery:

```hcl
owner_relations {
  max_depth = 5
  include_kinds = ["Deployment", "ReplicaSet", "StatefulSet"]

  custom_owner_kinds = [
    {
      kind        = "Rollout"
      api_version = "argoproj.io/v1alpha1"
      attribute_name = "rollout"
    }
  ]
}
```

**Ownership chain**: `Pod ← ReplicaSet ← Rollout`

**Result**: Flows will have:

- `k8s.pod.name`
- `k8s.replicaset.name`
- `k8s.rollout.name` (custom CRD)

### Use Case 5: ArgoCD Applications (Owner Relations)

Track pods deployed by ArgoCD applications:

```hcl
owner_relations {
  max_depth = 5
  include_kinds = ["Deployment", "ReplicaSet", "StatefulSet"]

  custom_owner_kinds = [
    {
      kind        = "Application"
      api_version = "argoproj.io/v1alpha1"
      attribute_name = "argocd.application"
    }
  ]
}
```

**Ownership chain**: `Pod ← ReplicaSet ← Deployment ← Application`

**Result**: Flows will have:

- `k8s.pod.name`
- `k8s.replicaset.name`
- `k8s.deployment.name`
- `k8s.argocd.application.name` (custom CRD)

### Use Case 6: Knative Services (Owner & Selector Relations)

Track serverless workloads with both owner and selector relations:

```hcl
owner_relations {
  max_depth = 5
  custom_owner_kinds = [
    {
      kind        = "Configuration"
      api_version = "serving.knative.dev/v1"
      attribute_name = "knative.configuration"
    },
    {
      kind        = "Revision"
      api_version = "serving.knative.dev/v1"
      attribute_name = "knative.revision"
    }
  ]
}

selector_relations = [
  {
    kind                        = "Service"
    api_version                 = "serving.knative.dev/v1"
    to                          = "Pod"
    selector_match_labels_field = "spec.template.metadata.labels"
    custom_resource             = true
  }
]
```

**Ownership chain**: `Pod ← ReplicaSet ← Revision ← Configuration`

**Selector match**: Knative Service → Pod (via labels)

**Result**: Comprehensive tracking of serverless workloads with both ownership and selector-based metadata.

### Use Case 7: Operator-Managed Workloads

Track pods managed by custom operators:

```hcl
owner_relations {
  max_depth = 6
  custom_owner_kinds = [
    {
      kind        = "PostgresCluster"
      api_version = "postgres-operator.crunchydata.com/v1beta1"
      # Use full group name to avoid collisions
      attribute_name = "postgres-operator.postgrescluster"
    },
    {
      kind        = "RedisCluster"
      api_version = "redis.redis.opstreelabs.in/v1beta1"
      attribute_name = "redis.opstreelabs.rediscluster"
    }
  ]
}
```

**Ownership chains**:

- `Pod ← StatefulSet ← PostgresCluster`
- `Pod ← StatefulSet ← RedisCluster`

**Result**: Attribute names are scoped to avoid collisions between different operators.

## Open Questions

1. **Pluralization**: How do we handle resource name pluralization for dynamic APIs?
   - Use `kube::discovery::ApiResource` with known plurals?
   - Require users to specify plural form in config?

2. **Namespace Scoping**: Should CRD watching be cluster-scoped or namespace-scoped?
   - Default to cluster-scoped like built-in resources?
   - Allow per-CRD configuration?

3. **Attribute Naming**: How should CRD attributes be named in flows?
   - Use `k8s.<lowercased-kind>.name`?
   - Include API group: `k8s.<group>.<kind>.name`?
   - Make it configurable?

4. **Version Conflicts**: How do we handle multiple versions of the same CRD?
   - Require explicit API version in config?
   - Use preferred version from CRD definition?

5. **Selector Validation**: Should we validate that specified field paths exist?
   - Fail fast on startup if invalid?
   - Warn and continue, logging errors at runtime?

6. **Owner Relations Filtering** (Owner Relations): How should `include_kinds`/`exclude_kinds` interact with CRDs?
   - Apply same filtering rules to CRDs?
   - Require explicit opt-in via `custom_owner_kinds`?
   - Default: CRDs in `custom_owner_kinds` are always included unless globally disabled

7. **Mixed Ownership Chains** (Owner Relations): How do we handle chains mixing built-in and CRDs?
   - Example: `Pod ← ReplicaSet ← Deployment ← ArgoCD Application`
   - Should filtering apply independently at each level?
   - Should we support filtering "after CRD" vs "before CRD"?

8. **CRD Version Migration** (Both): How do we handle CRD version upgrades?
   - User upgrades Istio from v1alpha1 to v1beta1
   - Old config with v1alpha1 stops matching
   - Should we support version wildcards or prefer explicit versions?

## Security Considerations

1. **RBAC Requirements**: Mermin will need RBAC permissions to list/watch CRDs
2. **Resource Limits**: Consider adding resource limits to prevent DoS from malicious CRDs
3. **Field Path Validation**: Sanitize user-provided field paths to prevent injection attacks
4. **API Server Load**: Watching many CRDs increases load on the API server

## Conclusion

Supporting CRDs in both selector relations and owner relations is a valuable feature that would enable Mermin to work with extended Kubernetes ecosystems (Istio, Cilium, ArgoCD, Argo Rollouts, Knative, and custom operators). However, it introduces significant complexity due to the dynamic nature of CRDs.

### Key Benefits

**Selector Relations:**

- Track network policies and services from service meshes (Istio, Linkerd)
- Support CNI-specific policies (Cilium, Calico)
- Enable custom application-level selectors

**Owner Relations:**

- Track GitOps deployments (ArgoCD Applications)
- Support progressive delivery (Argo Rollouts)
- Enable serverless workloads (Knative)
- Track operator-managed stateful workloads (PostgreSQL, Redis operators)

### Implementation Strategy

The phased approach outlined here allows us to:

1. **Phase 1**: Start with explicit, user-configured CRD support for both relation types
   - Lower complexity, predictable behavior
   - Users explicitly opt-in to specific CRDs
   - Easier to debug and validate
2. **Phase 2**: Gather real-world usage patterns and feedback
   - Identify common CRDs and patterns
   - Collect performance metrics
   - Refine configuration model
3. **Phase 3**: Optionally add auto-discovery (based on actual needs)
   - Automatic detection of common CRDs
   - Reduced configuration burden
   - Intelligent defaults

### Unified Architecture

Both selector and owner relations share the same underlying `DynamicResourceStore`, which:

- Reduces code duplication
- Ensures consistent CRD watching behavior
- Simplifies configuration (one place to register CRDs)
- Enables CRDs to participate in both relation types simultaneously

**Recommendation**: Begin with Phase 1 implementation after validating the design with key users who have specific CRD use cases. Priority should be given to widely-used platforms like ArgoCD, Argo Rollouts, and Istio.
