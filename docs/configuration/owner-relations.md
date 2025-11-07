---
hidden: true
---

# Owner Relations

Owner relations control how Mermin walks Kubernetes owner references to enrich flows with workload controller metadata (Deployment, StatefulSet, etc.).

## Overview

Kubernetes resources have owner references forming a chain: Pod → ReplicaSet → Deployment → ... Mermin can walk this chain and attach metadata from owners to network flows.

## Configuration

```hcl
discovery "informer" "k8s" {
  owner_relations = {
    max_depth = 5
    include_kinds = []
    exclude_kinds = []
  }
}
```

## Configuration Options

### `max_depth`

**Type:** Integer **Default:** `5`

Maximum depth to walk owner reference chain.

**Example:**

```hcl
owner_relations = {
  max_depth = 5  # Pod → RS → Deploy → ... (up to 5 levels)
}
```

### `include_kinds`

**Type:** Array of strings **Default:** `[]` (include all)

Only include these owner kinds in flow metadata. Empty array means include all.

**Valid kinds:** Deployment, ReplicaSet, StatefulSet, DaemonSet, Job, CronJob

**Example:**

```hcl
owner_relations = {
  include_kinds = ["Deployment", "StatefulSet"]
}
```

### `exclude_kinds`

**Type:** Array of strings **Default:** `[]` (exclude none)

Exclude these owner kinds from flow metadata. Takes precedence over `include_kinds`.

**Example:**

```hcl
owner_relations = {
  exclude_kinds = ["ReplicaSet"]
}
```

## How It Works

**Example chain:** Pod `nginx-abc123` → ReplicaSet `nginx-xyz` → Deployment `nginx`

**Without owner relations:**

* Flow shows only: Pod name, namespace, labels

**With owner relations:**

* Flow shows: Pod + ReplicaSet + Deployment metadata

## Complete Example

```hcl
discovery "informer" "k8s" {
  owner_relations = {
    # Walk up to 5 levels
    max_depth = 5

    # Include all owner types (default)
    include_kinds = []

    # Optionally exclude specific types
    exclude_kinds = []
  }
}
```

## Next Steps

* [**Selector Relations**](selector-relations.md): Configure selector-based matching
* [**Flow Attributes**](attributes.md): Configure metadata extraction
