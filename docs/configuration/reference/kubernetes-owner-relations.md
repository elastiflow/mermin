# Configure Owner Relations of Kubernetes Resources

**Block:** `discovery.informer.k8s.owner_relations`

Owner relations control how Mermin walks Kubernetes owner references to enrich flows with workload controller metadata (Deployment, StatefulSet, etc.).
Mermin accepts HCL or YAML for the config file; the examples below use HCL (see [Configuration Overview](../overview.md#file-format) for format details).

Kubernetes resources have owner references forming a chain: Pod → ReplicaSet → Deployment → ... Mermin can walk this chain and attach metadata from owners to network flows.
Owner relations apply when Kubernetes discovery is enabled (`discovery "informer" "k8s"`).

## Configuration

A full configuration example may be found in the [Default Configuration](../default/config.hcl).

### `discovery.informer.k8s.owner_relations` block

Configuration object for Kubernetes owner reference walking and filtering.

- `max_depth` attribute

  Maximum depth to walk owner reference chain. Set to `0` to disable owner walking entirely.

  **Type:** Integer

  **Default:** `5`

  **Valid Range:** `0` to `100` (practical limit)

  **Examples:**

  - Walk up to 5 levels (default):

    ```hcl
    owner_relations = {
      max_depth = 5  # Pod → RS → Deploy → ... (up to 5 levels)
    }
    ```

  - Disable owner walking:

    ```hcl
    discovery "informer" "k8s" {
      owner_relations = {
        max_depth = 0
      }
    }
    ```

- `include_kinds` attribute

  Only include these owner kinds in flow metadata. Empty array means include all supported kinds. Kind names are case-insensitive (e.g., `Deployment` and `deployment` are equivalent).

  **Type:** Array of strings

  **Default:** `[]` (include all)

  **Valid Kinds:** `Deployment`, `ReplicaSet`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`

  **Examples:**

  - Include only Deployment and StatefulSet owners:

    ```hcl
    owner_relations = {
      include_kinds = ["Deployment", "StatefulSet"]
    }
    ```

  - Include only Job and CronJob owners:

    ```hcl
    owner_relations = {
      include_kinds = ["Job", "CronJob"]
    }
    ```

- `exclude_kinds` attribute

  Exclude these owner kinds from flow metadata. Takes precedence over `include_kinds`. Kind names are case-insensitive.

  **Type:** Array of strings

  **Default:** `[]` (exclude none)

  **Valid Kinds:** `Deployment`, `ReplicaSet`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`

  **Examples:**

  - Exclude ReplicaSet (commonly used to skip intermediate owner):

    ```hcl
    owner_relations = {
      exclude_kinds = ["ReplicaSet"]
    }
    ```

  - Exclude multiple kinds:

    ```hcl
    owner_relations = {
      exclude_kinds = ["ReplicaSet", "Job"]
    }
    ```

## Filter Priority

When both `include_kinds` and `exclude_kinds` are specified:

1. **Exclude takes precedence**: If a kind is in `exclude_kinds`, it is excluded regardless of `include_kinds`
2. **Then include is applied**: If `include_kinds` is non-empty, only those kinds are included
3. **Empty include means all**: If `include_kinds` is empty, all kinds (except excluded) are included

**Example:** Include Deployment and Job, but exclude Deployment (result: only Job)

```hcl
owner_relations = {
  include_kinds = ["Deployment", "Job"]
  exclude_kinds = ["Deployment"]
}
```

## How It Works

**Example chain:** Pod `nginx-abc123` → ReplicaSet `nginx-xyz` → Deployment `nginx`

**Without owner relations (or max_depth = 0):**

- Flow shows only: Pod name, namespace, labels

**With owner relations (default or custom):**

- Flow shows: Pod + ReplicaSet + Deployment metadata (up to `max_depth` levels, filtered by include/exclude)

## Next Steps

{% tabs %}
{% tab title="Configure Metadata" %}
1. [**Configure Selector Matching**](kubernetes-selector-relations.md): Match Services and NetworkPolicies
2. [**Extract Flow Attributes**](flow-span-kubernetes-attribution.md): Choose which metadata appears on flows
{% endtab %}

{% tab title="Examples" %}
1. [**Review Complete Configurations**](../examples.md): Production-ready examples
{% endtab %}
{% endtabs %}

### Need Help?

- [**Troubleshoot Missing Metadata**](../../troubleshooting/troubleshooting.md): Diagnose enrichment issues
- [**GitHub Discussions**](https://github.com/elastiflow/mermin/discussions): Ask about owner relation configuration
