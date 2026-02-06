# Configure Kubernetes Attribution of Flow Spans

**Block:** `attributes.source.k8s`/`attributes.destination.k8s`

Flow attributes define which Kubernetes metadata to extract and how to associate it with network flows.

The feature allows:

- **Pod associations** capture container networking (IPs, ports, protocols) including both pod and host networking
- **Service associations** cover all service types (ClusterIP, LoadBalancer, ExternalIP) with port and protocol matching
- **Node associations** match node IP addresses for host networking scenarios

The configuration has two main components:

1. **Extract**: Which metadata fields to extract from Kubernetes resources
2. **Association**: How to map flow attributes (IPs, ports) to Kubernetes object fields

## Source vs Destination

Configure attributes for both flow directions:

```hcl
# Source IP/port matching
attributes "source" "k8s" {
  extract { ... }
  association { ... }
}

# Destination IP/port matching
attributes "destination" "k8s" {
  extract { ... }
  association { ... }
}
```

## Configuration

A full configuration example can be found in the [Default Configuration](../default/config.hcl).

### `attributes.source.k8s.extract` block

Defines which metadata to extract from the Kubernetes resources.

- `metadata` attribute

  List of JSONPath-style paths to extract from Kubernetes resources. Paths are evaluated against the resource object (Pod, Service, Node, etc.).

  **Type:** List of strings

  **Default:** `["[*].metadata.namespace", "[*].metadata.name", "[*].metadata.uid"]`

  **Example:** Extract all resource names but namespace only for the Pods

  ```hcl
  extract {
    metadata = [
      "[*].metadata.name",
      "pod.metadata.namespace",
    ]
  }
  ```

### `attributes.source.k8s.extract.label` block

The label block configures how to extract Kubernetes labels to Otel attributes, can be defined multiple times to extract multiple labels.

{% hint style="warning" %}
Currently, this features is not supported.
{% endhint %}

**Type:** [Metadata extraction object](#metadata-extraction-object)

**Default:** `{}` (no labels are extracted by default)

**Example:** Extract all Service labels with `kubernetes.io/` prefix to Otel attribute named after label suffix without any value modifications

```hcl
label {
  from            = "service"
  key_regex       = "kubernetes.io/(.*)"
  value_regex     = "(.*)"
  attribute       = "$1"
  attribute_value = "$1"
}
```

### `attributes.source.k8s.extract.annotation` block

The label block configures how to extract Kubernetes annotations to Otel attributes, can be defined multiple times to extract multiple labels.

{% hint style="warning" %}
Currently, this features is not supported.
{% endhint %}

**Type:** [Metadata extraction object](#metadata-extraction-object)

**Default** `{}` (no annotations are extracted by default)

**Example:** Extract all Pod annotations with `kubernetes.io/` prefix to Otel attribute named after annotation suffix without any value modifications

```hcl
annotation {
  from            = "pod"
  key_regex       = "kubernetes.io/(.*)"
  value_regex     = "(.*)"
  attribute       = "$1"
  attribute_value = "$1"
}
```

### `attributes.source.k8s.association` block

Defines how to associate flow fields (e.g. `source.ip`, `source.port`) to Kubernetes object fields for matching. The `to` paths are JSONPath-style paths over the resource (Pod, Service, Node, etc.).

Each key in the map identifies the Kubernetes kind (`pod`, `service`, `node`, etc.)

**Type:** Map

**Default:** Please see the [default configuration](../default/config.hcl) for the default for each Kubernetes kind.

**Example:** Simplify flow `source.ip` matching to the pod

```hcl
attributes "source" "k8s" {
  association {
    pod = {
      sources = [
        {
          from = "source.ip"
          to = ["status.podIP"]
        }
      ]
    }
  }
}
```

- `sources` attribute

  Defines how to associate flow fields (e.g. `source.ip`, `source.port`) to Kubernetes object fields for matching. The `to` paths are JSONPath-style paths over the resource (Pod, Service, Node, etc.).

  **Type:** List of [association objects](#association-object)

  **Default:** Please see the [default configuration](../default/config.hcl) for the default for each Kubernetes kind.

  **Example:** Map `source.ip` from the flow record to the Pod IP

  ```hcl
  pod = {
    sources = [
      {
        from = "source.ip"
        to   = ["status.podIP", "status.podIPs[*]", "status.hostIP", "status.hostIPs[*]"]
      }
    ]
  }
  ```

### Disable Default Attributes

If you need to disable the automatic attributes configuration, override it with an empty configuration:

```hcl
attributes "source" "k8s" {}
attributes "destination" "k8s" {}
```

## Object Type

### Metadata Extraction Object

Defines how to extract Kubernetes labels and annotations to Otel attributes

- `from` attribute

  Kubernetes kind to extract keys from

  **Type:** String

  **Default:** `""`

- `key` attribute

  Key to extract, mutually exclusive with `key_regex`

  **Type:** String

  **Default:** `""`

- `key_regex` attribute

  [Rust regular expressions](https://docs.rs/regex/latest/regex/) to match keys against, mutually exclusive with `key`. Regex capture groups are available.

  **Type:** String

  **Default:** `null`

- `value_regex` attribute

  [Rust regular expressions](https://docs.rs/regex/latest/regex/) to match values against. Regex capture groups are available.
  If undefined, whole value is extracted.

  **Type:** String

  **Default:** `null`

- `attribute` attribute

  Otel attribute to which the resulting value is written in a replace action, supports regex backreferences with `key_regex`.

  **Type:** String

  **Default:** `""`

- `attribute_value` attribute

  Otel attribute value to set, supports regex backreferences with `value_regex`. If undefined, full extracted value is used if undefined.

  **Type:** String

  **Default:** `null`

### Association Object

Defines how to associate flow fields (e.g. `source.ip`, `source.port`) to Kubernetes object fields for matching. The `to` paths are JSONPath-style paths over the resource (Pod, Service, Node, etc.).

- `from` attribute

  Flow field (attribute) name to use for the mapping

  **Type:** String

  **Default:** Please see the [default configuration](../default/config.hcl) for the default for each Kubernetes kind.

- `to` attribute

  JSONPath-style paths over the resource to match with `from` value

  **Type:** List of strings

  **Default:** Please see the [default configuration](../default/config.hcl) for the default for each Kubernetes kind.

## Troubleshooting

### Kubernetes Metadata Is Not Properly Mapped

**Symptoms:** You don't see Kubernetes resources attributes mapped to the flow spans.

Any explicit `attributes` configuration completely replaces the defaults for that direction and provider.
If you only configure one direction (e.g. only `attributes "source" "k8s"`), the other direction gets no attribution unless you add it explicitly.

**Solutions:**

1. Deploy Mermin without any `attributes` configuration
2. Generate network traffic in your cluster
3. Check that flow spans include Kubernetes metadata like:
    - `source.k8s.pod.name`, `source.k8s.service.name`, `source.k8s.namespace.name`
    - `destination.k8s.pod.name`, `destination.k8s.service.name`, `destination.k8s.namespace.name` (and other `destination.*` equivalents)

## Next Steps

- [**Kubernetes Informers**](kubernetes-informer-discovery.md): Configure resource watching
- [**Owner Relations**](kubernetes-owner-relations.md): Add owner metadata
- [**Configuration Examples**](../examples.md): See complete configurations
