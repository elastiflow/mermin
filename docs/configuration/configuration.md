---
hidden: true
---

# Configuration Overview

Mermin uses HCL (HashiCorp Configuration Language) as its primary configuration format, providing a human-readable and flexible way to configure all aspects of the observability agent.

## Configuration File Format

Mermin supports two configuration formats:

### HCL (Recommended)

HCL is the recommended format, offering:

* Clear, readable syntax
* Built-in support for expressions and functions
* Native block and attribute structure
* Better error messages

**Example HCL configuration:**

```hcl
log_level = "info"

discovery "instrument" {
  interfaces = ["eth*", "ens*"]
}

export "traces" {
  otlp = {
    endpoint = "http://otel-collector:4317"
    protocol = "grpc"
  }
}
```

### YAML (Supported)

YAML is also supported through conversion. To use YAML:

```bash
# Convert HCL to YAML using fmtconvert
fmtconvert -from hcl -to yaml config.hcl > config.yaml
```

However, HCL is recommended for direct use with Mermin.

## Configuration Precedence

Mermin loads configuration in the following order (later sources override earlier):

1. **Built-in Defaults**: Sensible defaults for all options
2. **Configuration File**: HCL or YAML file specified via `--config`
3. **Environment Variables**: Only for global options (see below)
4. **Command-Line Arguments**: Only for global options (see below)

{% hint style="info" %}
Only global options can be set via environment variables and CLI flags. All other configuration must be in the configuration file.
{% endhint %}

### Example Precedence

```hcl
# config.hcl (base configuration)
log_level = "info"
```

```bash
# Override via environment variable
export MERMIN_LOG_LEVEL=debug

# Or override via CLI flag
mermin --log-level=debug --config=config.hcl
```

Result: `log_level` will be `debug`.

## Configuration File Location

Specify the configuration file using:

### Command-Line Flag

```bash
mermin --config /path/to/config.hcl
```

### Environment Variable

```bash
export MERMIN_CONFIG_PATH=/path/to/config.hcl
mermin
```

### Kubernetes ConfigMap

```bash
kubectl create configmap mermin-config --from-file=config.hcl
```

Then mount in pod and reference:

```yaml
volumeMounts:
  - name: config
    mountPath: /etc/mermin

command: ["mermin", "--config", "/etc/mermin/config.hcl"]
```

## Auto-Reload Feature

Mermin can automatically reload configuration when the file changes:

```hcl
auto_reload = true
```

Or via environment/CLI:

```bash
mermin --auto-reload --config=config.hcl
# or
export MERMIN_CONFIG_AUTO_RELOAD=true
```

When enabled:

* Mermin watches the config file for changes
* Automatically reloads and applies new configuration
* No restart required
* Minimal disruption (brief pause in flow capture during reload)

{% hint style="warning" %}
Some changes may require a restart even with auto-reload enabled, such as interface selection changes or RBAC permission changes.
{% endhint %}

## Configuration Structure

Mermin configuration is organized into logical sections:

### Global Options

Top-level settings that affect overall behavior:

```hcl
log_level = "info"
auto_reload = false
shutdown_timeout = "5s"

pipeline {
  flow_producer {
    worker_queue_capacity = 2048
    workers: 4
  }
}
```

See [Global Options](global-options.md) for details.

### API and Metrics

Health check and metrics endpoints:

```hcl
api {
  enabled = true
  listen_address = "0.0.0.0"
  port = 8080
}

metrics {
  enabled = true
  listen_address = "0.0.0.0"
  port = 10250

  # Debug metrics (optional) - see warning below
  debug_metrics_enabled = false
  stale_metric_ttl = "5m"
}
```

{% hint style="warning" %}
**Debug Metrics Warning**: Setting `debug_metrics_enabled = true` enables high-cardinality metrics with per-resource labels. This can cause significant memory growth in production. Only enable for debugging. See [Metrics Configuration](metrics.md) for details.
{% endhint %}

See [API](api.md) and [Metrics](metrics.md) for details.

### Parser Configuration

eBPF packet parsing options:

```hcl
parser {
  geneve_port = 6081
  vxlan_port = 4789
  wireguard_port = 51820
}
```

See [Parser Configuration](parser.md) for details.

### Discovery

Network interface and Kubernetes resource discovery:

```hcl
discovery "instrument" {
  interfaces = ["eth*", "ens*"]
}

discovery "informer" "k8s" {
  # K8s API connection configuration
  informers_sync_timeout = "30s"

  selectors = [
    { kind = "Pod" },
    { kind = "Service" }
  ]
}
```

See [Network Interface Discovery](discovery-instrument.md) and [Kubernetes Informers](discovery-kubernetes-informer.md).

### Kubernetes Relations

Configure how flows are enriched with Kubernetes metadata:

```hcl
discovery "informer" "k8s" {
  owner_relations = {
    max_depth = 5
    include_kinds = []
    exclude_kinds = []
  }

  selector_relations = [
    {
      kind = "Service"
      to = "Pod"
      selector_match_labels_field = "spec.selector"
    }
  ]
}
```

See [Owner Relations](owner-relations.md) and [Selector Relations](selector-relations.md).

### Flow Attributes

Define which Kubernetes metadata to extract and associate with flows:

```hcl
attributes "source" "k8s" {
  extract {
    metadata = [
      "[*].metadata.name",
      "[*].metadata.namespace"
    ]
  }

  association {
    pod = {
      sources = [
        { from = "flow", name = "source.ip", to = ["status.podIP"] }
      ]
    }
  }
}
```

See [Flow Attributes](attributes.md) for details.

### Filtering

Filter flows before export:

```hcl
filter "source" {
  address = { match = "10.0.0.0/8", not_match = "" }
  port = { match = "80,443", not_match = "" }
}

filter "network" {
  transport = { match = "tcp", not_match = "" }
}
```

See [Flow Filtering](filtering.md) for details.

### Span Options

Configure flow span generation and timeouts:

```hcl
span {
  max_record_interval = "60s"
  generic_timeout = "30s"
  icmp_timeout = "10s"
  tcp_timeout = "20s"
  tcp_fin_timeout = "5s"
  tcp_rst_timeout = "5s"
  udp_timeout = "60s"
  community_id_seed = 0
}
```

See [Flow Span Options](span.md) for details.

### Export Configuration

Configure OTLP and stdout exporters:

```hcl
export "traces" {
  stdout = "text_indent"

  otlp = {
    endpoint = "http://otel-collector:4317"
    protocol = "grpc"
    timeout = "10s"
    max_batch_size = 512
    max_batch_interval = "5s"

    auth = {
      basic = {
        user = "username"
        pass = "password"
      }
    }

    tls = {
      insecure_skip_verify = false
      ca_cert = "/etc/certs/ca.crt"
    }
  }
}
```

See [OTLP Exporter](export-otlp.md) and [Stdout Exporter](export-stdout.md).

### Internal Tracing

Configure Mermin's own telemetry:

```hcl
internal "traces" {
  span_fmt = "full"

  stdout = {
    format = "text_indent"
  }

  otlp = {
    endpoint = "http://otel-collector:4317"
    protocol = "grpc"
  }
}
```

See [Internal Tracing](internal-tracing.md) for details.

## Validation

Mermin validates configuration on startup and reports errors:

```bash
mermin --config=config.hcl
# Error: invalid configuration: unknown field "invalid_field" at line 10
```

To test configuration without running:

```bash
# Validate only (upcoming feature)
mermin --config=config.hcl --validate
```

## Configuration Examples

See [Configuration Examples](examples.md) for complete, real-world configurations:

* Production-ready configuration
* Development/testing configuration
* CNI-specific configurations
* High-throughput configuration
* Security-hardened configuration

## Configuration Reference

Detailed documentation for each configuration section:

| Section                                         | Description                          |
| ----------------------------------------------- | ------------------------------------ |
| [Global Options](global-options.md)             | Top-level settings and CLI flags     |
| [API](api.md) and [Metrics](metrics.md)         | Health checks and Prometheus metrics |
| [Parser](parser.md)                             | eBPF packet parsing options          |
| [Network Interfaces](discovery-instrument.md)   | Interface discovery patterns         |
| [Kubernetes Informers](discovery-kubernetes-informer.md) | K8s resource watching                |
| [Owner Relations](owner-relations.md)           | Owner reference walking              |
| [Selector Relations](selector-relations.md)     | Label selector matching              |
| [Flow Attributes](attributes.md)                | Metadata extraction and association  |
| [Filtering](filtering.md)                       | Flow filtering rules                 |
| [Span Options](span.md)                 | Flow generation and timeouts         |
| [OTLP Exporter](export-otlp.md)                 | OpenTelemetry Protocol export        |
| [Stdout Exporter](export-stdout.md)             | Console output for debugging         |
| [Internal Tracing](internal-tracing.md)         | Mermin self-monitoring               |

## Best Practices

1. **Start with minimal configuration**: Add complexity as needed
2. **Use comments**: Document why specific settings are chosen
3. **Version control**: Track configuration changes in Git
4. **Test in non-production**: Validate changes before production deployment
5. **Monitor metrics**: Ensure configuration performs as expected
6. **Use auto-reload**: For easier configuration iteration
7. **Keep secrets separate**: Use environment variables or Kubernetes secrets for sensitive data

## Next Steps

* [**Global Options**](global-options.md): Configure top-level settings
* [**Network Interface Discovery**](discovery-instrument.md): Choose which interfaces to monitor
* [**OTLP Exporter**](export-otlp.md): Configure flow export to your backend
* [**Configuration Examples**](examples.md): See complete working configurations
