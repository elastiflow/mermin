---
hidden: true
---

# Flow Span Options

This page documents the `span` configuration block, which controls how Mermin generates flow records (spans) from captured network packets.

## Overview

Mermin aggregates network packets into bidirectional Flows Trace Spans. The span configuration determines:

* How long flows remain active before being exported
* When inactive flows are considered complete
* Protocol-specific timeout behavior
* Community ID generation for a Flow Trace correlation

## Configuration

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

## Configuration Options

### `max_record_interval`

**Type:** Duration **Default:** `60s`

Maximum interval between flow records for an active flow.

**Description:**

* Limits how long an active flow continues without exporting a record
* Applies to all flows regardless of protocol
* Even if packets continue flowing, a record is exported at this interval
* Prevents indefinitely long flows that never close

**Example:**

```hcl
span {
  max_record_interval = "60s"  # Export at least every 60 seconds
}
```

**Use Cases:**

* **Short intervals (10s-30s)**: Real-time monitoring, quick detection
* **Medium intervals (60s-120s)**: Standard observability (default)
* **Long intervals (300s+)**: Reduced data volume, long-running connections

**Trade-offs:**

* **Shorter**: More granular data, higher export rate, more storage
* **Longer**: Less data volume, longer detection time, lower costs

### `generic_timeout`

**Type:** Duration **Default:** `30s`

General timeout for flows without specific protocol timeouts.

**Description:**

* Used for protocols without specific timeout configuration
* Applied after no activity for the specified duration
* Flows with packet count > 0 are exported on timeout
* Flows with packet count = 0 are silently dropped

**Example:**

```hcl
span {
  generic_timeout = "30s"  # 30 second inactivity timeout
}
```

**Applies to:**

* GRE, ESP, AH, and other IP protocols
* Unknown or unclassified traffic
* Protocols without dedicated timeout options

### `icmp_timeout`

**Type:** Duration **Default:** `10s`

Timeout for ICMP flows (ping, traceroute, etc.).

**Description:**

* ICMP is typically request-response
* Short timeout appropriate for transient ICMP traffic
* Exports flow after 10 seconds of inactivity

**Example:**

```hcl
span {
  icmp_timeout = "10s"  # ICMP timeout
}
```

**Common ICMP Types:**

* Echo Request/Reply (ping)
* Destination Unreachable
* Time Exceeded (traceroute)
* Redirect

**Tuning:**

* **Shorter (5s)**: For networks with rapid ICMP bursts
* **Longer (20s)**: For environments with slow ICMP responses

### `tcp_timeout`

**Type:** Duration **Default:** `20s`

Timeout for general TCP flows without specific termination signals.

**Description:**

* Applied to established TCP connections
* Used when connection doesn't have FIN or RST flags
* Shorter than UDP due to TCP's connection-oriented nature

**Example:**

```hcl
span {
  tcp_timeout = "20s"  # TCP inactivity timeout
}
```

**When Applied:**

* Established TCP connections
* No FIN or RST flags observed
* No packets for specified duration

**Relationship to TCP States:**

* **ESTABLISHED**: Uses `tcp_timeout`
* **FIN\_WAIT**: Uses `tcp_fin_timeout`
* **CLOSE\_WAIT**: Uses `tcp_fin_timeout`
* **RESET**: Uses `tcp_rst_timeout`

### `tcp_fin_timeout`

**Type:** Duration **Default:** `5s`

Timeout for TCP flows after FIN flag is observed.

**Description:**

* FIN flag indicates graceful connection close
* Short timeout to quickly export closing connections
* Allows time for final ACKs to be captured

**Example:**

```hcl
span {
  tcp_fin_timeout = "5s"  # Quick close after FIN
}
```

**TCP Close Sequence:**

1. Client sends FIN
2. Server sends ACK
3. Server sends FIN
4. Client sends ACK
5. **Mermin waits `tcp_fin_timeout` then exports flow**

**Tuning:**

* **Shorter (2s)**: Faster export, may miss final packets
* **Longer (10s)**: More complete flows, slower export

### `tcp_rst_timeout`

**Type:** Duration **Default:** `5s`

Timeout for TCP flows after RST flag is observed.

**Description:**

* RST flag indicates abrupt connection termination
* Short timeout for quick export of failed connections
* Useful for detecting connection failures

**Example:**

```hcl
span {
  tcp_rst_timeout = "5s"  # Quick export after RST
}
```

**RST Scenarios:**

* Connection refused (port not listening)
* Connection aborted by application
* Firewall dropping connection
* TCP errors or violations

**Use Cases:**

* Security monitoring (port scans)
* Application debugging (connection failures)
* Network troubleshooting

### `udp_timeout`

**Type:** Duration **Default:** `60s`

Timeout for UDP flows.

**Description:**

* UDP is connectionless, no explicit close
* Longer timeout accommodates sporadic UDP traffic
* Balances between timely export and flow completeness

**Example:**

```hcl
span {
  udp_timeout = "60s"  # UDP inactivity timeout
}
```

**Common UDP Protocols:**

* DNS (port 53)
* DHCP (ports 67, 68)
* SNMP (port 161)
* Syslog (port 514)
* Streaming media
* Gaming protocols

**Tuning:**

* **Shorter (30s)**: For bursty UDP traffic (DNS, DHCP)
* **Longer (120s+)**: For streaming or persistent UDP (VoIP, gaming)

### `community_id_seed`

**Type:** Integer (uint16) **Default:** `0`

Seed value for Community ID hash generation.

**Description:**

* [Community ID](https://github.com/corelight/community-id-spec) is a standard flow fingerprinting method
* Generates deterministic hash from flow 5-tuple
* Allows correlation across different monitoring systems
* Seed value should be consistent across your infrastructure

**Example:**

```hcl
span {
  community_id_seed = 0  # Standard seed
}
```

**Community ID Format:**

```
1:hash_value
```

Example: `1:LQU9qZlK+B5F3KDmev6m5PMibrg=`

**Use Cases:**

* Correlating flows across multiple Mermin agents
* Deduplicating flows from multiple capture points
* Matching flows with other systems using Community ID

**Seed Selection:**

* **0 (default)**: Standard, interoperable with other tools
* **Custom**: Use if you need different hashing for security/privacy

## Flow Generation Logic

### Flow Record Generation

Mermin creates a flow record when:

1. **Max Interval Reached**: Active flow hits `max_record_interval`
2. **Timeout Expired**: No activity for protocol-specific timeout
3. **Connection Close**: TCP FIN or RST observed (after respective timeout)

### Flow State Machine

```
Packet Received
    ↓
Flow Exists? ──No──→ Create New Flow
    ↓ Yes
Update Flow State
    ↓
Check Conditions:
    - Max interval reached?
    - Timeout expired?
    - TCP FIN/RST seen + timeout?
    ↓
Export Flow Record
    ↓
Remove from Flow Table
```

## Tuning Guidelines

### Low-Latency Configuration

For real-time monitoring with low latency:

```hcl
span {
  max_record_interval = "10s"  # Frequent exports
  generic_timeout = "10s"
  icmp_timeout = "5s"
  tcp_timeout = "10s"
  tcp_fin_timeout = "2s"
  tcp_rst_timeout = "2s"
  udp_timeout = "20s"
}
```

**Benefits:**

* Rapid flow detection
* Real-time visibility
* Quick anomaly detection

**Trade-offs:**

* Higher export rate
* More OTLP traffic
* More storage required
* Higher CPU usage

### High-Throughput Configuration

For environments with very high traffic volume:

```hcl
span {
  max_record_interval = "120s"  # Longer intervals
  generic_timeout = "60s"
  icmp_timeout = "20s"
  tcp_timeout = "40s"
  tcp_fin_timeout = "10s"
  tcp_rst_timeout = "10s"
  udp_timeout = "120s"
}
```

**Benefits:**

* Reduced export rate
* Lower storage requirements
* Less OTLP bandwidth
* Lower CPU usage

**Trade-offs:**

* Slower detection
* Less granular data
* Longer memory retention

### Memory-Constrained Configuration

For nodes with limited memory:

```hcl
span {
  max_record_interval = "30s"   # Quick exports
  generic_timeout = "15s"        # Aggressive timeouts
  icmp_timeout = "5s"
  tcp_timeout = "15s"
  tcp_fin_timeout = "5s"
  tcp_rst_timeout = "5s"
  udp_timeout = "30s"
}
```

**Benefits:**

* Smaller flow table
* Lower memory usage
* Faster flow turnover

**Trade-offs:**

* May fragment long flows
* Slightly higher export rate

## Monitoring Flow Table

Monitor flow table size with metrics:

```prometheus
# Current active flows
mermin_flow_spans_active_total

# Flow creation rate
rate(mermin_flow_spans_created_total[5m])

# eBPF map utilization
mermin_ebpf_map_utilization_ratio{map="FLOW_STATS"}
```

**Healthy indicators:**

* Flow table size stable
* Flow duration aligns with timeouts
* No unbounded growth

**Warning signs:**

* Flow table continuously growing
* Very long average flow durations
* Memory usage increasing

**Solutions:**

* Decrease timeout values
* Decrease `max_record_interval`
* Add flow filters to reduce tracked flows

## Protocol-Specific Examples

### DNS (UDP)

DNS is typically request-response with short duration:

```hcl
span {
  udp_timeout = "10s"  # Short timeout for DNS
}
```

### HTTP/HTTPS (TCP)

Web traffic with varying connection durations:

```hcl
span {
  max_record_interval = "60s"  # Export long connections periodically
  tcp_timeout = "20s"           # Reasonable inactivity timeout
  tcp_fin_timeout = "5s"        # Quick close detection
}
```

### Streaming (UDP)

Long-lived streaming connections:

```hcl
span {
  max_record_interval = "300s"  # Allow long streams
  udp_timeout = "120s"          # Long inactivity allowance
}
```

### SSH (TCP)

Interactive sessions with sporadic activity:

```hcl
span {
  max_record_interval = "600s"  # Very long sessions
  tcp_timeout = "300s"          # Long idle time
}
```

## Complete Configuration Example

```hcl
# Flow span generation configuration
span {
  # Maximum time between records for active flows
  max_record_interval = "60s"

  # Default timeout for unspecified protocols
  generic_timeout = "30s"

  # Protocol-specific timeouts
  icmp_timeout = "10s"       # ICMP (ping, etc.)
  tcp_timeout = "20s"        # TCP established connections
  tcp_fin_timeout = "5s"     # TCP graceful close
  tcp_rst_timeout = "5s"     # TCP abrupt close
  udp_timeout = "60s"        # UDP flows

  # Community ID for flow correlation
  community_id_seed = 0
}
```

## Best Practices

1. **Start with defaults**: Default values suit most environments
2. **Monitor metrics**: Observe flow behavior before tuning
3. **Adjust incrementally**: Change one timeout at a time
4. **Document rationale**: Note why specific values were chosen
5. **Consider protocol mix**: Tune based on predominant protocols
6. **Balance objectives**: Trade off latency, accuracy, and resources
7. **Test changes**: Validate in non-production first

## Next Steps

* [**Flow Filtering**](filtering.md): Filter flows before export
* [**OTLP Exporter**](export-otlp.md): Configure export batching and intervals
* [**Global Options**](global-options.md): Tune packet processing workers
* [**Troubleshooting Performance**](../troubleshooting/performance.md): Optimize for your environment
