# Owner Relations

Owner relations control how Mermin walks Kubernetes owner references to enrich flows with workload controller metadata (Deployment, StatefulSet, etc.). Mermin accepts HCL or YAML for the config file; the examples below use HCL (see [Configuration Overview](configuration.md#file-format) for format details).

## Overview

Kubernetes resources have owner references forming a chain: Pod → ReplicaSet → Deployment → ... Mermin can walk this chain and attach metadata from owners to network flows. Owner relations apply when Kubernetes discovery is enabled (`discovery "informer" "k8s"`).

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

Only include these owner kinds in flow metadata. Empty array means include all. Kind names are case-insensitive (e.g. `Deployment` and `deployment` are equivalent).

**Valid kinds:** Deployment, ReplicaSet, StatefulSet, DaemonSet, Job, CronJob

**Example:**

```hcl
owner_relations = {
  include_kinds = ["Deployment", "StatefulSet"]
}
```

### `exclude_kinds`

**Type:** Array of strings **Default:** `[]` (exclude none)

Exclude these owner kinds from flow metadata. Takes precedence over `include_kinds`. Kind names are case-insensitive.

**Example:**

```hcl
owner_relations = {
  exclude_kinds = ["ReplicaSet"]
}
```

### Default behavior

If you omit the `owner_relations` block, Mermin uses default settings: `max_depth = 5`, `include_kinds = []` (include all kinds), `exclude_kinds = []`. Owner walking is enabled and all supported owner kinds are included in flow metadata.

To disable owner walking (no owner metadata on flows), set `max_depth = 0`:

```hcl
discovery "informer" "k8s" {
  owner_relations = {
    max_depth = 0
  }
}
```

## How It Works

**Example chain:** Pod `nginx-abc123` → ReplicaSet `nginx-xyz` → Deployment `nginx`

**Without owner relations (or max_depth = 0):**

* Flow shows only: Pod name, namespace, labels

**With owner relations (default or custom):**

* Flow shows: Pod + ReplicaSet + Deployment metadata (up to `max_depth` levels, filtered by include/exclude)

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
