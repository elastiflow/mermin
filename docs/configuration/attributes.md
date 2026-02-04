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

A full configuration example can be found in the [Default Configuration](./default/config.hcl).

### `extract` block

Defines which metadata to extract from the Kubernetes resources.

- `metadata` attribute - list of strings, default `["[*].metadata.namespace", "[*].metadata.name", "[*].metadata.uid"]`.  

  List of JSONPath-style paths to extract from Kubernetes resources. Paths are evaluated against the resource object (Pod, Service, Node, etc.).

  **Example:** Extract all resource names but namespace only for the Pods

  ```hcl
  extract {
    metadata = [
      "[*].metadata.name",
      "pod.metadata.namespace",
    ]
  }
  ```

- `label` block - [metadata extraction object](#metadata-extraction-object), `{}` (no labels are extracted by default).  

  The label block configures how to extract Kubernetes labels to Otel attributes, can be defined multiple times to extract multiple labels.
  _Not implemented_

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

- `annotation` block - [metadata extraction object](#metadata-extraction-object), `{}` (no annotations are extracted by default).  

  The label block configures how to extract Kubernetes annotations to Otel attributes, can be defined multiple times to extract multiple labels.
  _Not implemented_

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

### `association` block

Defines how to associate flow fields (e.g. `source.ip`, `source.port`) to Kubernetes object fields for matching. The `to` paths are JSONPath-style paths over the resource (Pod, Service, Node, etc.).

Each key in the map identifies the Kubernetes kind (`pod`, `service`, `node`, etc.)

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

- `sources` attribute - list of [association objects](#association-object), please see the [default configuration](./default/config.hcl) for the default for each Kubernetes kind.  

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

## Object types

### Metadata extraction object

Defines how to extract Kubernetes labels to Otel attributes

- `from` attribute - string, default `""`.  

  Kubernetes kind to extract labels from

- `key_regex` attribute - string, default `""`.  

  [Rust regular expressions](https://docs.rs/regex/latest/regex/) to match label keys against. Regex capture groups are available.

- `value_regex` attribute - string, default `""`.  

  [Rust regular expressions](https://docs.rs/regex/latest/regex/) to match label values against. Regex capture groups are available.

- `attribute` attribute - string, default `""`.  

  Otel attribute to which the resulting value is written in a replace action. Regex capture groups are available.

- `attribute_value` attribute - string, default `""`.  

  Otel attribute value to set. Regex capture groups are available.

### Association object

Defines how to associate flow fields (e.g. `source.ip`, `source.port`) to Kubernetes object fields for matching. The `to` paths are JSONPath-style paths over the resource (Pod, Service, Node, etc.).

- `from` attribute - string.  

  Flow field (attribute) name to use for the mapping

- `to` attribute - list of strings.  

  JSONPath-style paths over the resource to match with `from` value

## Troubleshooting

### Kubernetes Metadata is not properly mapped

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

- [**Kubernetes Informers**](discovery-kubernetes-informer.md): Configure resource watching
- [**Owner Relations**](owner-relations.md): Add owner metadata
- [**Configuration Examples**](examples.md): See complete configurations
