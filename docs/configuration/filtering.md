---
hidden: true
---

# Flow Filtering

Flow filtering allows you to include or exclude network flows based on various criteria before they are exported, reducing data volume and focusing on relevant traffic.

## Overview

Mermin supports filtering flows by:

* Source/destination IP addresses and ports
* Network protocols and interface names
* TCP flags, ICMP types
* Connection states

Filters use glob patterns aligned with OpenTelemetry Binary Instrumentation (OBI) conventions.

## Configuration

```hcl
filter "source" {
  address = {
    match = "10.0.0.0/8"
    not_match = "10.1.0.0/16"
  }
  port = {
    match = "80,443,8080-8090"
    not_match = ""
  }
}

filter "destination" {
  address = {
    match = ""
    not_match = "169.254.0.0/16"  # Exclude link-local
  }
  port = {
    match = ""
    not_match = ""
  }
}

filter "network" {
  transport = {
    match = "tcp,udp"
    not_match = ""
  }
  type = {
    match = "ipv4"
    not_match = ""
  }
  interface_name = {
    match = "eth*"
    not_match = ""
  }
}

filter "flow" {
  connection_state = {
    match = "established"
    not_match = ""
  }
  tcp_flags = {
    match = "SYN,ACK"
    not_match = "RST"
  }
}
```

## Filter Syntax

### Match Patterns

* **`match`**: Include flows matching this pattern (empty = match all)
* **`not_match`**: Exclude flows matching this pattern (takes precedence)

### Glob Patterns

**IP addresses and CIDRs:**

* `10.0.0.0/8`: CIDR notation
* `192.168.1.*`: Glob wildcard
* `10.0.0.1,10.0.0.2`: Comma-separated list

**Ports:**

* `80`: Single port
* `80,443,8080`: Multiple ports
* `8000-8999`: Port range

**Protocols:**

* `tcp,udp`: Protocol names
* `established,close_wait`: Connection states

## Source and Destination Filters

### `address`

Filter by IP address.

**Examples:**

```hcl
filter "source" {
  address = {
    match = "10.0.0.0/8"          # Only RFC1918
    not_match = "10.0.0.0/24"      # Exclude subnet
  }
}
```

### `port`

Filter by port number.

**Examples:**

```hcl
filter "source" {
  port = {
    match = "1024-65535"  # Only ephemeral ports
    not_match = ""
  }
}
```

## Network Filters

### `transport`

Filter by transport protocol.

**Values:** `tcp`, `udp`, `icmp`, `icmpv6`

### `type`

Filter by IP version.

**Values:** `ipv4`, `ipv6`

### `interface_name`

Filter by network interface.

**Example:**

```hcl
filter "network" {
  interface_name = {
    match = "eth*"
    not_match = "docker*"
  }
}
```

## Flow Filters

### `connection_state`

Filter by TCP connection state.

**Values:** `established`, `syn_sent`, `syn_received`, `fin_wait`, `close_wait`, `closing`, `last_ack`, `time_wait`, `closed`

### `tcp_flags`

Filter by TCP flags.

**Values:** `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`

### Other Flow Attributes

* `ip_dscp_name`: DSCP value
* `ip_ecn_name`: ECN value
* `ip_ttl`: TTL value
* `icmp_type_name`: ICMP type
* `icmp_code_name`: ICMP code

## Common Filtering Scenarios

### HTTP/HTTPS Only

```hcl
filter "destination" {
  port = {
    match = "80,443"
    not_match = ""
  }
}
```

### Exclude Internal Traffic

```hcl
filter "source" {
  address = {
    match = ""
    not_match = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
  }
}
```

### TCP Only, Established Connections

```hcl
filter "network" {
  transport = {
    match = "tcp"
    not_match = ""
  }
}

filter "flow" {
  connection_state = {
    match = "established"
    not_match = ""
  }
}
```

## Complete Example

```hcl
# Source filters
filter "source" {
  address = { match = "", not_match = "" }
  port = { match = "", not_match = "" }
}

# Destination filters
filter "destination" {
  address = { match = "", not_match = "" }
  port = { match = "80,443", not_match = "" }  # HTTP/HTTPS only
}

# Network filters
filter "network" {
  transport = { match = "tcp,udp", not_match = "icmp" }
  type = { match = "ipv4", not_match = "" }
  interface_name = { match = "", not_match = "" }
}

# Flow filters
filter "flow" {
  connection_state = { match = "", not_match = "" }
  tcp_flags = { match = "", not_match = "" }
}
```

## Best Practices

1. **Start permissive**: Begin with no filters, add as needed
2. **Monitor impact**: Check flow reduction with metrics
3. **Test incrementally**: Add one filter at a time
4. **Document rationale**: Comment why filters are applied
5. **Use `not_match` carefully**: Exclusions can hide important traffic

## Next Steps

* [**Configuration Examples**](examples.md): See complete filter configurations
* [**Flow Span Options**](span-options.md): Configure flow generation
* [**OTLP Export**](export-otlp.md): Configure export options
