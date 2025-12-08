---
hidden: true
---

# Pipeline Tuning Options

The `pipeline` block provides advanced configuration for flow processing pipeline optimization, including base channel sizing, worker threading, Kubernetes decoration, backpressure management, and buffer multipliers.

## Overview

**HCL:**

```hcl
pipeline {
  # Base ring buffer capacity (default: 8192, good for typical enterprise)
  ring_buffer_capacity = 8192

  # Number of parallel flow workers (default: 4, suitable for most deployments)
  worker_count = 4

  # Worker polling interval (default: 5s)
  worker_poll_interval = "5s"

  # Kubernetes decorator threading (default: 4 for typical enterprise)
  k8s_decorator_threads = 4

  # Channel multipliers
  flow_span_channel_multiplier = 2.0
  decorated_span_channel_multiplier = 4.0

  # Adaptive sampling under load (not yet implemented)
  sampling_enabled = true
  sampling_min_rate = 0.1
  backpressure_warning_threshold = 0.01
}
```
