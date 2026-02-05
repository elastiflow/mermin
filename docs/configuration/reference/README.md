---
layout:
  width: default
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
  metadata:
    visible: true
---

<!-- markdownlint-disable MD025 -->
# Configuration Reference

This section provides detailed reference documentation for all Mermin configuration options, from network interface discovery to export settings.

## How Configuration Works

Mermin uses a layered configuration approach:

1. **Configuration File (HCL/YAML)**: The primary method for detailed configuration.
2. **Environment Variables**: Override global options at runtime.
3. **Command-Line Flags**: Override global options at runtime.

Global options (documented below) are the only settings configurable via all three methods. All other configuration blocks require a configuration file.

---

## Configure Global Agent Options

Global options are top-level configuration settings that control Mermin's overall behavior. These are the only options that can be configured via CLI flags or environment variables in addition to the configuration file.

### Configuration Methods

#### Configuration File (HCL)

```hcl
# config.hcl
log_level = "info"
auto_reload = true
shutdown_timeout = "10s"
```

#### Command-Line Flags

```bash
mermin \
  --config=/etc/mermin/config.hcl \
  --log-level=debug \
  --auto-reload
```

#### Environment Variables

```bash
export MERMIN_CONFIG_PATH=/etc/mermin/config.hcl
export MERMIN_LOG_LEVEL=debug
export MERMIN_CONFIG_AUTO_RELOAD=true
mermin
```

### Configuration Options

#### `config` / `MERMIN_CONFIG_PATH`

**Type:** String (file path) **Default:** None (optional) **CLI Flag:** `--config` **Environment:** `MERMIN_CONFIG_PATH`

Path to the HCL or YAML configuration file. Omit to use built-in defaults.

**Example:**

```bash
mermin --config=/etc/mermin/config.hcl
# or
export MERMIN_CONFIG_PATH=/etc/mermin/config.hcl
```

#### `auto_reload` / `MERMIN_CONFIG_AUTO_RELOAD`

{% hint style="warning" %}
Currently, this features is not supported.
{% endhint %}

**Type:** Boolean **Default:** `false` **CLI Flag:** `--auto-reload` **Environment:** `MERMIN_CONFIG_AUTO_RELOAD`

Automatically reload configuration when the file changes. When enabled, Mermin watches the config file and reloads it without requiring a restart.

**HCL:**

```hcl
auto_reload = true
```

**CLI:**

```bash
mermin --auto-reload --config=config.hcl
```

**Environment:**

```bash
export MERMIN_CONFIG_AUTO_RELOAD=true
```

**Behavior:**

- File is monitored for changes using filesystem watches
- Configuration is reloaded atomically
- Brief pause in flow capture during reload (\~100ms)
- Invalid configuration prevents reload (old config remains active)
- Logs indicate successful/failed reload attempts

**Use Cases:**

- Development and testing: Iterate quickly without restarts
- Production: Update configuration without downtime
- Debugging: Temporarily change log levels or filters

{% hint style="warning" %}
Some configuration changes may require a full restart, such as changing monitored network interfaces or modifying RBAC permissions.
{% endhint %}

#### `log_level` / `MERMIN_LOG_LEVEL`

**Type:** String (enum) **Default:** `info` **CLI Flag:** `--log-level` **Environment:** `MERMIN_LOG_LEVEL`

Sets the logging verbosity level.

**Valid Values:**

- `trace`: Most verbose, includes all debug information
- `debug`: Detailed debugging information
- `info`: General informational messages (default)
- `warn`: Warning messages only
- `error`: Error messages only

**HCL:**

```hcl
log_level = "debug"
```

**CLI:**

```bash
mermin --log-level=trace --config=config.hcl
```

**Environment:**

```bash
export MERMIN_LOG_LEVEL=warn
```

**Recommendations:**

- **Production:** `info` or `warn` to reduce log volume
- **Debugging:** `debug` for detailed troubleshooting
- **Development:** `trace` for comprehensive visibility

#### `shutdown_timeout`

**Type:** Duration **Default:** `5s` **CLI Flag:** Not available **Environment:** Not available

Maximum time to wait for graceful shutdown before forcing termination.

**HCL:**

```hcl
shutdown_timeout = "10s"
```

**Behavior:** During shutdown, Mermin:

1. Stops accepting new packets
2. Waits for in-flight flows to export (up to `shutdown_timeout`)
3. Closes OTLP connections gracefully
4. Forces shutdown if timeout is exceeded

**Recommendations:**

- **Production:** `10s` to ensure flows are exported
- **Development:** `5s` (default) is usually sufficient
- **High-throughput:** Increase to `30s` or more

**Related Settings:**

- `export.otlp.max_export_timeout`: Should be less than `shutdown_timeout`

### Monitoring Shutdown Behavior

Mermin provides metrics to monitor shutdown behavior:

#### Shutdown Metrics

- `shutdown_duration_seconds`: Histogram of actual shutdown durations
- `shutdown_timeouts_total`: Count of shutdowns that exceeded timeout
- `shutdown_flows_total{status="preserved"}`: Flows successfully exported during shutdown
- `shutdown_flows_total{status="lost"}`: Flows lost due to shutdown timeout

### Next Steps

- Internal [**Server**](internal-server.md) and [**Metrics**](../metrics.md): Configure health checks and monitoring
- [**Network Interface Discovery**](network-interface-discovery.md): Select which interfaces to monitor
- [**Flow Span Options**](../span.md): Configure flow generation and timeouts
- [**Configuration Examples**](../examples.md): See complete configurations
