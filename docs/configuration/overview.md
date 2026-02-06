# Configuration Overview

Configure Mermin with HCL (HashiCorp Configuration Language) or YAML. This page describes the config file format, precedence, and structure. Section-specific options are documented in the linked pages.

## File Format

Mermin accepts HCL (recommended) or YAML. Supported file extensions: `.hcl`, `.yaml`, `.yml`. Use an `.hcl` file for clear syntax and good error messages.
To use YAML, convert from HCL with the [fmtconvert](https://github.com/genelet/determined/tree/main/cmd/fmtconvert) tool (`go install github.com/genelet/determined/cmd/fmtconvert@latest`) and pass the result to `--config`:

```bash
fmtconvert -from hcl -to yaml config.hcl > config.yaml
mermin --config config.yaml
```

## Precedence

Configuration is merged in this order (later overrides earlier):

1. Built-in defaults
2. Config file (path from `--config` or `MERMIN_CONFIG_PATH`)
3. Environment variables (global options only)
4. Command-line flags (global options only)

Only these global options can be set via environment variables or CLI: config path (`MERMIN_CONFIG_PATH`, `--config`), `log_level` (`MERMIN_LOG_LEVEL`, `--log-level`), and `auto_reload` (`MERMIN_CONFIG_AUTO_RELOAD`, `--auto-reload`).
Options like `shutdown_timeout` and everything under `pipeline`, `api`, `export`, etc. are config-file only.

Example: with `log_level = "info"` in the file, `export MERMIN_LOG_LEVEL=debug` or `mermin --log-level=debug --config=config.hcl` yields `log_level` = `debug`.

## Config File Location

A config file is optional. Omit `--config` and `MERMIN_CONFIG_PATH` to use built-in defaults. To use a file:

- **CLI:** `mermin --config /path/to/config.hcl`
- **Env:** `MERMIN_CONFIG_PATH=/path/to/config.hcl`
- **Kubernetes:** Create a ConfigMap from the file, mount it in the pod, and pass the path to `mermin --config`.

The file must exist and have a supported extension. Subcommands (e.g. `mermin diagnose bpf`) do not load the main config. Use `mermin --help` or `mermin diagnose --help` for usage.

## Auto-Reload

When `auto_reload = true` (or `--auto-reload` / `MERMIN_CONFIG_AUTO_RELOAD=true`), Mermin watches the config file and reloads on change without restart.
Flow capture may pause briefly during reload. Some changes (e.g. interface selection or RBAC) still require a full restart.

## Minimal configuration

Without a config file, Mermin uses built-in defaults and does not configure an exporter—flow data is not sent anywhere. To send flow traces to an OTLP endpoint with default settings, create a config file that sets only the export block:

```hcl
export "traces" {
  otlp = {
    endpoint = "http://otel-collector:4317"
    protocol = "grpc"
  }
}
```

Omit other blocks (discovery, pipeline, api, etc.) to use built-in defaults. Run with `mermin --config config.hcl`. For more complete examples, see [Configuration Examples](examples.md).

## Configuration Structure

### Global options

Top-level settings. See [Global Options](reference/README.md#configure-global-agent-options).

```hcl
log_level       = "info"
log_color       = false
auto_reload     = false
shutdown_timeout = "5s"

pipeline {
  flow_capture {
    flow_stats_capacity   = 100000
    flow_events_capacity  = 1024
  }
  flow_producer {
    workers                   = 4
    worker_queue_capacity      = 2048
    flow_store_poll_interval   = "5s"
    flow_span_queue_capacity  = 16384
  }
  k8s_decorator {
    threads                        = 4
    decorated_span_queue_capacity  = 32768
  }
}
```

### HTTP server and metrics

Health HTTP server and internal Prometheus metrics. See Internal [Server](reference/internal-server.md) and [Metrics](reference/internal-prometheus-metrics.md).

```hcl
internal "server" {
  enabled         = true
  listen_address  = "0.0.0.0"
  port            = 8080
}

internal "metrics" {
  enabled               = true
  listen_address        = "0.0.0.0"
  port                  = 10250
  debug_metrics_enabled = false
  stale_metric_ttl      = "5m"
  # histogram_buckets { ... }  # optional overrides
}
```

Setting `internal.metrics.debug_metrics_enabled = true` enables high-cardinality metrics and can increase memory use; enable only for debugging.

### Parser

eBPF packet parsing. See [Network Packet Parser](reference/network-packet-parser.md).

```hcl
parser {
  geneve_port   = 6081
  vxlan_port    = 4789
  wireguard_port = 51820
}
```

### Discovery

Interfaces and Kubernetes discovery. See [Network Interface Discovery](reference/network-interface-discovery.md) and [Kubernetes Informers](reference/kubernetes-informer-discovery.md).
If you omit `interfaces`, built-in defaults target CNI interfaces (e.g. `veth*`, `tunl*`, `vxlan*`, `cali*`, `cilium_*`). The example below overrides with physical interfaces:

```hcl
discovery "instrument" {
  interfaces                = ["eth*", "ens*"]  # override; defaults are CNI-oriented
  auto_discover_interfaces  = true
  tc_priority               = 1
  tcx_order                 = "first"  # or "last"
}

discovery "informer" "k8s" {
  kubeconfig_path       = ""
  informers_sync_timeout = "30s"
  selectors              = [{ kind = "Pod" }, { kind = "Service" }]
  # owner_relations { ... }
  # selector_relations = [ ... ]
}
```

### Kubernetes relations

Owner and selector relations for flow enrichment. See [Owner Relations](reference/kubernetes-owner-relations.md) and [Selector Relations](reference/kubernetes-selector-relations.md).

### Flow attributes

Which Kubernetes metadata to extract and how to associate it with flows. See [Flow Attributes](reference/flow-span-kubernetes-attribution.md). If you omit the `attributes` block, default Kubernetes attribution is applied.
An empty `attributes {}` block disables attribution.

### Filtering

Filter flows by address, port, transport, type, interface, and other dimensions. See [Flow Filtering](reference/flow-span-filters.md). Each filter block has a label (e.g. `"source"`); inside it you can set `match` and `not_match` for:

- `address`, `port`, `transport`, `type`
- `interface_name`, `interface_index`, `interface_mac`
- `connection_state`
- `ip_dscp_name`, `ip_ecn_name`, `ip_ttl`, `ip_flow_label`
- `icmp_type_name`, `icmp_code_name`
- `tcp_flags_tags`

Example:

```hcl
filter "source" {
  address   = { match = ["10.0.0.0/8"] }
  port      = { match = ["80", "443"] }
  transport = { match = ["tcp"] }
}
```

### Span options

Flow span generation, timeouts, Community ID, trace correlation, and hostname resolution. See [Flow Span Options](reference/flow-span-producer.md). All options are config-file only.

```hcl
span {
  max_record_interval        = "60s"
  generic_timeout            = "30s"
  icmp_timeout               = "10s"
  tcp_timeout                = "20s"
  tcp_fin_timeout            = "5s"
  tcp_rst_timeout            = "5s"
  udp_timeout                = "60s"
  community_id_seed          = 0
  trace_id_timeout           = "24h"
  enable_hostname_resolution  = true
  hostname_resolve_timeout   = "100ms"
}
```

### Export

Trace export to OTLP and/or stdout. See [OTLP Exporter](reference/opentelemetry-otlp-exporter.md) and [Console Exporter](reference/opentelemetry-console-exporter.md).

```hcl
export "traces" {
  stdout = "text_indent"

  otlp = {
    endpoint              = "http://otel-collector:4317"
    protocol              = "grpc"
    timeout               = "10s"
    max_batch_size        = 512
    max_batch_interval    = "5s"
    max_queue_size        = 2048
    max_concurrent_exports = 1
    max_export_timeout    = "30s"
    headers               = { "x-custom" = "value" }
    auth = {
      basic = { user = "username", pass = "password" }
    }
    tls = {
      insecure_skip_verify = false
      ca_cert              = "/etc/certs/ca.crt"
      client_cert          = "/etc/certs/client.crt"
      client_key           = "/etc/certs/client.key"
    }
  }
}
```

### Internal tracing

Mermin's own telemetry. See [Internal Tracing](reference/internal-tracing.md).

```hcl
internal "traces" {
  span_fmt = "full"
  stdout   = { format = "text_indent" }
  otlp     = { endpoint = "http://otel-collector:4317", protocol = "grpc" }
}
```

## Validation

Configuration is validated on startup. Invalid config (unknown field, invalid value, missing file, or unsupported extension) causes Mermin to exit with a non-zero exit code and print the error to stderr.
Fix the file and restart (or rely on auto-reload after fixing). In Kubernetes, Mermin logs a memory warning if estimated pipeline usage exceeds 80% of the container limit; see [Pipeline](reference/flow-processing-pipeline.md) and [Troubleshooting](../troubleshooting/troubleshooting.md).

## HCL functions

HCL config files (not YAML) support the `env` function to read environment variables—useful for secrets or environment-specific values without hardcoding. The function evaluates when the config loads and again on reload.

- `env("VAR_NAME")`
  Returns the value of the environment variable, or an empty string if unset. Mermin logs a warning when the variable is not set.

- `env("VAR_NAME", "default")`
  Returns the variable value if set, otherwise the second argument. Mermin logs a warning when the variable is not set and the default is used.

You can use `env` anywhere a string is accepted (e.g. `log_level`, `api.listen_address`, `export "traces" { otlp = { endpoint = ... } }`, `auth.basic.pass`).
You can use it in lists (e.g. `discovery "instrument" { interfaces = [env("IFACE")] }`) and in string interpolation (e.g. `"prefix-${env("VAR")}-suffix"`). Examples that match the behavior tested in the codebase:

```hcl
# Top-level with default
log_level = env("MERMIN_LOG_LEVEL", "info")

# OTLP endpoint and auth (strings)
export "traces" {
  otlp = {
    endpoint = env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
    auth = {
      basic = {
        user = "mermin"
        pass = env("OTLP_PASSWORD")
      }
    }
  }
}

# HTTP server listen address with interpolation
internal "server" {
  listen_address = "prefix-${env("SERVER_HOST")}-suffix"
  port = 8080
}
```

YAML configs do not support `env`; use HCL if you need it, or inject values before conversion.

## Examples and reference

- [Configuration Examples](examples.md): full example configs (production, development, CNI, high-throughput, security).
- Section reference:

| Section                                                                           | Description                                          |
|-----------------------------------------------------------------------------------|------------------------------------------------------|
| [Global Options](reference/README.md#configure-global-agent-options)              | Configure Global Agent Options                       |
| [Internal Server](reference/internal-server.md)                                   | Configure Internal Server                            |
| [Internal Prometheus Metrics](reference/internal-prometheus-metrics.md)           | Configure Internal Prometheus Metrics                |
| [Network Packet Parser](reference/network-packet-parser.md)                       | Configure Parsing of Network Packets                 |
| [Network Interface Discovery](reference/network-interface-discovery.md)           | Configure Discovery of Network Interfaces            |
| [Kubernetes Informer Discovery](reference/kubernetes-informer-discovery.md)       | Configure Discovery of Kubernetes Informer           |
| [Kubernetes Owner Relations](reference/kubernetes-owner-relations.md)             | Configure Owner Relations of Kubernetes Resources    |
| [Kubernetes Selector Relations](reference/kubernetes-selector-relations.md)       | Configure Selector Relations of Kubernetes Resources |
| [Flow Span Kubernetes Attribution](reference/flow-span-kubernetes-attribution.md) | Configure Kubernetes Attribution of Flow Spans       |
| [Flow Span Filters](reference/flow-span-filters.md)                               | Configure Filtering of Flow Spans                    |
| [Flow Span Producer](reference/flow-span-producer.md)                             | Configure Producing of Flow Spans                    |
| [OpenTelemetry OTLP Exporter](reference/opentelemetry-otlp-exporter.md)           | Configure OpenTelemetry OTLP Exporter                |
| [OpenTelemetry Console Exporter](reference/opentelemetry-console-exporter.md)     | Configure OpenTelemetry Console Exporter             |
| [Internal Tracing](reference/internal-tracing.md)                                 | Configure Internal Tracing Exporter                  |
| [Flow Processing Pipeline](reference/flow-processing-pipeline.md)                 | Configure Flow Processing Pipeline                   |

## Best practices

1. Start minimal; add options as needed.
2. Comment non-obvious choices.
3. Keep config in version control.
4. Test changes outside production.
5. Use metrics to confirm behavior.
6. Prefer auto-reload for iterative tuning.
7. Keep secrets in env vars or Kubernetes secrets, not in the config file.

## Next steps

- [Global Options](reference/README.md#configure-global-agent-options): top-level and CLI
- [Network Interface Discovery](reference/network-interface-discovery.md): which interfaces to monitor
- [OTLP Exporter](reference/opentelemetry-otlp-exporter.md): send flows to your backend
- [Configuration Examples](examples.md): full sample configs
