# Configure Kubernetes Informer Discovery

**Block:** `discovery.informer.k8s`

This page documents how to configure Mermin's Kubernetes informers, which watch and cache Kubernetes resources for flow
metadata enrichment.

Mermin uses Kubernetes informers to maintain an in-memory cache of cluster resources. This enables enriching network
flows with Kubernetes metadata like pod names, labels, services, and owner references without querying the API server
for every flow.

## Configuration

A full configuration example can be found in the [Default Configuration](../default/config.hcl).

### `discovery.informer.k8s` block

- `kubeconfig_path` attribute

  Path to kubeconfig file for API server connection. When empty, uses in-cluster config. Non-default value may be used for:

  - Testing locally outside cluster
  - Using specific service account
  - Multi-cluster scenarios

  **Type:** String

  **Default:** `""` (uses in-cluster config)

  **Example:** Use specific kubeconfig

  ```hcl
  discovery "informer" "k8s" {
    kubeconfig_path = "/etc/mermin/kubeconfig"
  }
  ```

- `informers_sync_timeout` attribute

  Timeout for initial informer synchronization. Why it matters:

  - Maximum time to wait for informers to complete initial sync
  - Mermin won't be ready until sync completes
  - Large clusters may need longer timeout

  **Type:** Duration

  **Default:** `"30s"`

  **Example:** For large clusters (10,000+ pods)

  ```hcl
  discovery "informer" "k8s" {
    informers_sync_timeout = "120s"
  }
  ```

- `selectors` attribute

  Include/Exclude resources from the Kubernetes Informer using the resource labels and [label selectors](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/).

  **Type:** List of [selectors](#selector)

  **Default:**

  ```hcl
  [
    { kind = "Service" }, { kind = "Endpoint" }, { kind = "EndpointSlice" }, { kind = "Gateway" }, { kind = "Ingress" },
    { kind = "Pod" }, { kind = "ReplicaSet" }, { kind = "Deployment" }, { kind = "Daemonset" }, { kind = "StatefulSet" },
    { kind = "Job" }, { kind = "CronJob" }, { kind = "NetworkPolicy" },
  ]
  ```

  **Examples:**

  - Exclude Gateways in the `loggers` namespace

    ```hcl
    namespaces = ["loggers"]
    kind       = "Gateway"
    include    = false
    ```

  - Only include pods with label `operated-prometheus = "true"` AND label `env` in `["dev", "stage"]`

    ```hcl
    kind = "Pod"

    match_labels = {
      operated-prometheus = "true"
    }

    match_expressions = [{
      key      = "env"
      operator = "In"
      values   = ["dev", "stage"]
    }]
    ```

## Object Types

### Selector

Selector is used to match a Kubernetes resource using labels and expressions.

- `kind` attribute

  Defines a Kubernetes Kind to apply the selector to, such as `Pod`, `Service`, `Job`, etc. Case insensitive, `"Pod"`, `"pod"`, and `"POD"` are equivalent.

  **Type:** String

  **Default:** `""`

- `include` attribute

  Defines an action to perform, e.g. include or exclude matching resources.

  **Type:** Boolean

  **Default:** `true`

- `namespaces` attribute

  Defines a filter based on the Kubernetes namespace name.

  **Type:** List of Strings

  **Default:** `[]` (empty list, match all namespaces)

- `match_labels` attribute

  Kubernetes label selector ([ref](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#equality-based-requirement)).
  Each key represents a label, each value represents a label value. If label and label value is equal to the ones in the Kubernetes resource, the resource is included.

  **Type:** Map of Strings

  **Default:** `{}` (empty map, do not apply label matching, e.g. match all)

  **Example:** Include resources that belong to production environment (label `env: prod` is present in the resource)

  ```hcl
  match_labels = {
    operated-prometheus = "true"
  }
  ```

- `match_expressions` attribute

  [Kubernetes set-based label selector](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#set-based-requirement).

  **Type:** List of [match expressions](#match-expression)

  **Default:** `[]` (empty list, do not apply label matching, e.g. match all)

  **Example:** Include resources that belong to development and production environment (label `env: prod` or `env: dev` is present in the resource)

  ```hcl
  match_expressions = [{
    key      = "env"
    operator = "In"
    values   = ["dev", "stage"]
  }]
  ```

### Match Expression

[Kubernetes set-based label selector](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#set-based-requirement).

- `key` attribute

  Label key to match against.

  **Type:** String

  **Default:** `""`

- `operator` attribute

  Operator to apply, case insensitive.

  **Type:** String

  **Default:** `"In"`

  **Supported Values:** `In`, `NotIn`, `Exists`, `DoesNotExist`

- `values` attribute

  List of label values to apply the `operator` to.

  **Type:** List of Strings

  **Default:** `[]`

## Supported Resource Kinds

Mermin supports watching these Kubernetes resources:

| Kind            | Purpose                             |
|-----------------|-------------------------------------|
| `Pod`           | Primary source for flow attribution |
| `Service`       | Service endpoints and selectors     |
| `Endpoint`      | (Deprecated) Service endpoints      |
| `EndpointSlice` | Modern service endpoints            |
| `ReplicaSet`    | Owner reference walking             |
| `Deployment`    | Owner reference walking             |
| `DaemonSet`     | Owner reference walking             |
| `StatefulSet`   | Owner reference walking             |
| `Job`           | Owner reference walking             |
| `CronJob`       | Owner reference walking             |
| `NetworkPolicy` | Network policy association          |
| `Ingress`       | Ingress controller flows            |
| `Gateway`       | Gateway API flows                   |

## Performance Considerations

### Memory Usage

Memory usage scales with number of watched resources:

- **Estimate:** ~1 KB per resource
- **10,000 pods:** ~10 MB
- **100,000 pods:** ~100 MB

### API Server Load

Informers use Kubernetes watch API:

- Initial LIST operation per resource type
- WATCH for ongoing updates

**Reduce load:**

- Use namespace filtering
- Use label selectors

### Sync Time

Initial sync time depends on:

- Cluster size
- Number of resource types
- API server performance
- Network latency

You may need to tweak the `informers_sync_timeout` attribute.

## Troubleshooting

### Informer Sync Timeout

**Symptoms:** e.g. `kubernetes cache sync timed out after 30s - increase informers_sync_timeout if needed`

**Solutions:**

1. Increase `informers_sync_timeout`
2. Check API server responsiveness
3. Verify RBAC permissions
4. Reduce watched resource types

### Missing Metadata

**Symptoms:** Flows missing pod/service names

**Solutions:**

1. Verify resource kinds are in selectors
2. Check namespace filters
3. Verify label selectors
4. Review logs for sync errors

### High Memory Usage

**Symptoms:** Mermin using excessive memory

**Solutions:**

1. Add namespace filtering
2. Add label selectors
3. Remove unnecessary resource types
4. Check for resource leaks

### Best Practices

1. **Watch only needed resources**: Reduces memory and API load
2. **Use namespace filtering**: For multi-tenant clusters
3. **Monitor sync status**: Check logs and metrics
4. **Test selector changes**: Validate in non-production first
5. **Document selectors**: Comment why specific filters are used

## Next Steps

{% tabs %}
{% tab title="Configure Metadata" %}
1. [**Configure Owner Relations**](kubernetes-owner-relations.md): Walk owner references (Pod → Deployment)
2. [**Configure Selector Matching**](kubernetes-selector-relations.md): Match Services and NetworkPolicies
3. [**Extract Flow Attributes**](flow-span-kubernetes-attribution.md): Choose which metadata appears on flows
{% endtab %}

{% tab title="Troubleshoot" %}
1. [**Debug Missing Metadata**](../../troubleshooting/troubleshooting.md): Diagnose enrichment issues
2. [**Verify RBAC Permissions**](../../troubleshooting/deployment-issues.md#kubernetes-rbac-issues): Ensure Mermin can read resources
{% endtab %}
{% endtabs %}

### Need Help?

- [**GitHub Discussions**](https://github.com/elastiflow/mermin/discussions): Ask about metadata enrichment
