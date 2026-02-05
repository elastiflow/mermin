# Configure Selector Relations of Kubernetes Resources

**Block:** `discovery.informer.k8s`

Selector relations enable matching Kubernetes resources based on label selectors (e.g. NetworkPolicy → Pod or Service → Pod).
Mermin extracts these selectors, finds matching resources, and uses the resulting relations to enrich flow metadata.
The resulting attributes (e.g. `source.k8s.networkpolicy.name`, `destination.k8s.service.name`) appear on flow spans when the corresponding [Flow Attributes](attributes.md) associations are enabled (e.g. `networkpolicy`, `service`).

You can configure:

- **Selector-to-target mapping**: which resource kind contains the selector (`kind`) and which kind to match against (`to`; currently only Pod)
- **Selector field paths**: JSONPath-style paths to `matchLabels` and optional `matchExpressions` on the source resource

The resource kinds you use in `selector_relations` (e.g. NetworkPolicy, Service, Deployment) must be watched by the Kubernetes informer;
see [**Kubernetes Informer Discovery**](reference/kubernetes-informer-discovery.md) for `selectors` and namespace filtering.

## Configuration

A full configuration example can be found in the [Default Configuration](./default/config.hcl).

### `selector_relations` attribute

`selector_relations` is optional and lives inside `discovery.informer.k8s`. If omitted or empty, no selector-based relations are used. When present, it is a list of relation rules; each rule is an object with the attributes described below.

```hcl
discovery "informer" "k8s" {
  selector_relations = [
    {
      kind = "NetworkPolicy"
      to = "Pod"
      selector_match_labels_field      = "spec.podSelector.matchLabels"
      selector_match_expressions_field = "spec.podSelector.matchExpressions"
    },
    {
      kind                        = "Service"
      to                          = "Pod"
      selector_match_labels_field = "spec.selector"
    },
  ]
}
```

## Object Types

### Selector Relation Object

Each element in `selector_relations` is an object with these attributes:

- `kind` attribute

  From Kubernetes resource kind that contains the selector. Case insensitive. Supported kinds: NetworkPolicy, Service, Deployment, ReplicaSet, StatefulSet, DaemonSet, Job, CronJob.

  **Type:** String

  **Default:** None (required)

  **Example:** NetworkPolicy → Pod relation

  ```hcl
  {
    kind = "NetworkPolicy"
    to   = "Pod"
    selector_match_labels_field      = "spec.podSelector.matchLabels"
    selector_match_expressions_field = "spec.podSelector.matchExpressions"
  }
  ```

- `to` attribute

  Target resource kind to match against. Case insensitive. Currently only **Pod** is supported.

  **Type:** String

  **Default:** None (required)

  **Example:** Match selector to Pods

  ```hcl
  {
    kind = "Service"
    to   = "Pod"
    selector_match_labels_field = "spec.selector"
  }
  ```

- `selector_match_labels_field` attribute

  JSONPath-style path to the label set used for matching. May point to a `matchLabels` object (e.g. `spec.podSelector.matchLabels`) or to a flat key-value map (e.g. Service's `spec.selector`). Required for the relation to work.

  **Type:** String

  **Default:** None (required)

  **Examples:**

  - NetworkPolicy podSelector labels

    ```hcl
    selector_match_labels_field = "spec.podSelector.matchLabels"
    ```

  - Service selector (flat map, no nested matchLabels)

    ```hcl
    selector_match_labels_field = "spec.selector"
    ```

- `selector_match_expressions_field` attribute

  JSONPath-style path to the `matchExpressions` field on the from resource. Omit for resources that only use a flat selector (e.g. Service).

  **Type:** String (optional)

  **Default:** Omitted (no matchExpressions used)

  **Example:** NetworkPolicy podSelector matchExpressions

  ```hcl
  {
    kind = "NetworkPolicy"
    to   = "Pod"
    selector_match_labels_field      = "spec.podSelector.matchLabels"
    selector_match_expressions_field = "spec.podSelector.matchExpressions"
  }
  ```

## Common Configurations

### NetworkPolicy → Pod

**Example:** Extract podSelector from NetworkPolicy and attach NetworkPolicy metadata to matching Pod flows

```hcl
{
  kind = "NetworkPolicy"
  to = "Pod"
  selector_match_labels_field      = "spec.podSelector.matchLabels"
  selector_match_expressions_field = "spec.podSelector.matchExpressions"
}
```

### Service → Pod

**Example:** Extract spec.selector from Service and attach Service metadata to matching Pod flows

```hcl
{
  kind = "Service"
  to = "Pod"
  selector_match_labels_field = "spec.selector"
}
```

### Workload controllers → Pod

Deployment, ReplicaSet, StatefulSet, DaemonSet, and Job use `spec.selector` with optional `matchExpressions`.

**Example:** Deployment → Pod

```hcl
{
  kind = "Deployment"
  to   = "Pod"
  selector_match_labels_field      = "spec.selector.matchLabels"
  selector_match_expressions_field = "spec.selector.matchExpressions"
}
```

### CronJob → Pod

CronJob’s selector lives on the job template.

**Example:** CronJob → Pod

```hcl
{
  kind = "CronJob"
  to   = "Pod"
  selector_match_labels_field      = "spec.jobTemplate.spec.selector.matchLabels"
  selector_match_expressions_field = "spec.jobTemplate.spec.selector.matchExpressions"
}
```

## Next Steps

- [**Flow Attributes**](attributes.md): Enable associations (e.g. `networkpolicy`, `service`) so selector-based metadata appears on flows
- [**Kubernetes Informer Discovery**](reference/kubernetes-informer-discovery.md): Configure resource watching and selectors so the kinds used in selector_relations are available
- [**Owner Relations**](owner-relations.md): Configure owner reference walking
- [**Configuration Examples**](examples.md): See complete configurations
