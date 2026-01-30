# Selector Relations

Selector relations enable matching Kubernetes resources based on label selectors, such as NetworkPolicy → Pod or Service → Pod associations.

## Overview

Many Kubernetes resources use selectors to target other resources. Mermin can extract these selectors and find matching resources to enrich flow metadata. The resulting relations are used for flow and span enrichment; enable the corresponding associations in [Flow Attributes](attributes.md) (e.g. `networkpolicy`, `service`) to see this metadata on flows.

## Configuration

`selector_relations` is optional. If omitted or empty, no selector-based relations are used. When present, it is a list of relation rules inside `discovery "informer" "k8s"`.

```hcl
discovery "informer" "k8s" {
  selector_relations = [
    {
      kind = "NetworkPolicy"
      to = "Pod"
      selector_match_labels_field = "spec.podSelector.matchLabels"
      selector_match_expressions_field = "spec.podSelector.matchExpressions"
    },
    {
      kind = "Service"
      to = "Pod"
      selector_match_labels_field = "spec.selector"
    },
  ]
}
```

Each entry in `selector_relations` is an object with the following options.

## Configuration Options

### `kind`

**Type:** String (case insensitive)

Source resource kind containing the selector.

**Supported:** NetworkPolicy, Service, Deployment, ReplicaSet, StatefulSet, DaemonSet, Job, CronJob

### `to`

**Type:** String (case insensitive)

Target resource kind to match against. Currently only **Pod** is supported.

### `selector_match_labels_field`

**Type:** String (optional)

JSON path to the label set used for matching. May point to a `matchLabels` object (e.g. `spec.podSelector.matchLabels`) or to a flat key-value map (e.g. Service’s `spec.selector`, which has no nested `matchLabels`).

**Example:** `"spec.podSelector.matchLabels"` or `"spec.selector"`

### `selector_match_expressions_field`

**Type:** String (optional)

JSON path to `matchExpressions` field in source resource.

**Example:** `"spec.podSelector.matchExpressions"`

## Common Configurations

### NetworkPolicy → Pod

```hcl
{
  kind = "NetworkPolicy"
  to = "Pod"
  selector_match_labels_field = "spec.podSelector.matchLabels"
  selector_match_expressions_field = "spec.podSelector.matchExpressions"
}
```

### Service → Pod

```hcl
{
  kind = "Service"
  to = "Pod"
  selector_match_labels_field = "spec.selector"
}
```

### Workload Controllers → Pod

Deployment, ReplicaSet, StatefulSet, DaemonSet, and Job use `spec.selector` with optional `matchExpressions`:

```hcl
{
  kind = "Deployment"
  to = "Pod"
  selector_match_labels_field   = "spec.selector.matchLabels"
  selector_match_expressions_field = "spec.selector.matchExpressions"
}
```

### CronJob → Pod

CronJob’s selector lives on the job template:

```hcl
{
  kind = "CronJob"
  to = "Pod"
  selector_match_labels_field   = "spec.jobTemplate.spec.selector.matchLabels"
  selector_match_expressions_field = "spec.jobTemplate.spec.selector.matchExpressions"
}
```

## Complete Example

```hcl
discovery "informer" "k8s" {
  selector_relations = [
    # NetworkPolicy selection
    {
      kind = "NetworkPolicy"
      to = "Pod"
      selector_match_labels_field = "spec.podSelector.matchLabels"
      selector_match_expressions_field = "spec.podSelector.matchExpressions"
    },

    # Service selection
    {
      kind = "Service"
      to = "Pod"
      selector_match_labels_field = "spec.selector"
    },

    # Workload controller (Deployment); ReplicaSet, StatefulSet, DaemonSet, Job use spec.selector; CronJob uses spec.jobTemplate.spec.selector (see above)
    {
      kind = "Deployment"
      to = "Pod"
      selector_match_labels_field   = "spec.selector.matchLabels"
      selector_match_expressions_field = "spec.selector.matchExpressions"
    },
  ]
}
```

## Next Steps

* [**Flow Attributes**](attributes.md): Configure metadata extraction and enable associations (e.g. `networkpolicy`, `service`) so selector-based metadata appears on flows
* [**Owner Relations**](owner-relations.md): Configure owner reference walking
