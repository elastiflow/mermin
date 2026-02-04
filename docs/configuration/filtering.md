# Configure Filtering of Flow Spans

**Block:** `filter.source`/`filter.destination`/`filter.network`/`filter.flow`

Flow filtering allows you to include or exclude network flows based on various criteria. This reduces data volume and focuses on relevant traffic.

Mermin supports filtering flows by:

- Source/destination IP addresses and ports
- Network protocols and interface names
- TCP flags, ICMP types
- Connection states

{% hint style="info" %}
Filter option names are derived directly from FlowSpan attribute names defined in the semantic conventions and can be referenced easily in the [attributes reference](../spec/attribute-reference.md).
The attribute's dot notation is converted to underscores (e.g., `flow.tcp.flags.tags` becomes `tcp_flags_tags`). This 1:1 mapping ensures consistency and makes it easy to identify which attribute each filter targets.
{% endhint %}

## Configuration

A full configuration example can be found in the [Default Configuration](./default/config.hcl).

### `filter.source` and `filter.destination` filters block

The filters apply to the `source`/`destination` combination of the `address` and `port` in the flow span.
Filter is applied at the "Flow Producer" stage ([architecture](../getting-started/agent-architecture.md#components)), which can help reduce resource usage in subsequent stages.

- `address` attribute - [pattern matcher object](#pattern-matcher-object), default `{}`.

  Filter by IP address. Supported values in patterns: IP or CIDR notation (`10.0.0.0/8`, `10.0.0.1`)

  **Example:** Include only [RFC1918](https://datatracker.ietf.org/doc/html/rfc1918), but exclude `10.0.0.0/24`, and `10.0.2.1`

  ```hcl
  filter "source" {
    address = {
      match     = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
      not_match = ["10.0.0.0/24", "10.0.2.1"]
    }
  }
  ```

- `port` attribute - [pattern matcher object](#pattern-matcher-object), default `{}`.

  Filter by port. Supported values in patterns: Port or port range as a string (`443`, `8000-9000`)

  **Examples:**

  - Include flows with only `443` (HTTPS) destination port

    ```hcl
    filter "destination" {
      port = {
        match = ["443"]
      }
    }
    ```

  - Include flows with only [Linux ephemeral](https://www.kernel.org/doc/html/latest//networking/ip-sysctl.html#ip-variables) source ports

    ```hcl
    filter "source" {
      port = {
        match = ["32000-60999"]
      }
    }
    ```

#### Notes

The result of the `filter.source`/`filter.destination` inclusion/exclusion is combined with an "AND" condition, meaning it is very easy to accidentally exclude flows you want to observe. For example:

- Matching only private subnets will filter out any flow originating from public subnets.
  The configuration:

  ```hcl
  filter "source" {
    address = {
      match = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    }
  }
  ```

  Flows:

  ```json
  [
    {...,"source.address": "10.0.0.2", "destination.address": "10.0.0.3", ...}, // included
    {...,"source.address": "10.0.0.3", "destination.address": "10.0.0.2", ...}, // included
    {...,"source.address": "10.0.0.2", "destination.address": "92.1.1.1", ...}, // included
    {..., "source.address": "92.1.1.1", "destination.address": "10.0.0.2", ...}, // EXCLUDED
    ...
  ]
  ```

- Matching the same port in the `source` and `destination` filters will filter out almost all flows.
  Although, theoretically, source and destination ports can be the same (e.g., old DNS servers), it is relatively uncommon to see the same source and destination port.
    The configuration:

  ```hcl
  filter "source" {
    port = {
      match = ["53", "443"]
    }
  }

  filter "destination" {
    port = {
      match = ["53", "443"]
    }
  }
  ```

  Flows:

  ```json
  [
    {...,"source.port": "33868", "destination.port": "443", ...}, // excluded
    {...,"source.port": "443", "destination.port": "33868", ...}, // excluded
    {...,"source.port": "53", "destination.port": "53", ...}, // included (uncommon)
    {...,"source.port": "53", "destination.port": "53", ...}, // included (uncommon)
    ...
  ]
  ```

### `filter.network` filter block

The filter applies to various network attributes in the flow span, such as transport protocol, interface, and others.
Filter is applied at the "Flow Producer" stage ([architecture](../getting-started/agent-architecture.md#components)), which can help reduce resource usage in subsequent stages.

- `transport` attribute - [pattern matcher object](#pattern-matcher-object), default `{}`.

  Filter by transport protocol.
  Supported values in patterns: `tcp`, `udp`, `icmp`, `icmpv6` (supports [globs](https://docs.rs/globset/latest/globset/#syntax))

  **Examples:**

  - Include only TCP and UDP traffic:

    ```hcl
    filter "network" {
      transport = {
        match = ["tcp", "udp"]
      }
    }
    ```

  - Exclude ICMP:

    ```hcl
    filter "network" {
      transport = {
        not_match = ["icmp"]
      }
    }
    ```

- `type` attribute - [pattern matcher object](#pattern-matcher-object), default `{}`.

  Filter by IP version.
  Supported values in patterns: `ipv4`, `ipv6` (supports [globs](https://docs.rs/globset/latest/globset/#syntax))

  **Examples:**

  - Include only IPv4 traffic:

    ```hcl
    filter "network" {
      type = {
        match = ["ipv4"]
      }
    }
    ```

- `interface_name` attribute - [pattern matcher object](#pattern-matcher-object), default `{}`.

  Filter by network interface name.
  Supported values in patterns: Any valid interface name (supports [globs](https://docs.rs/globset/latest/globset/#syntax))

  **Examples:**

  - Include only interfaces matching `eth*` or `enp*` (`eth0`, `eth1`, `enp0s3`, `enp8s0f0`):

    ```hcl
    filter "network" {
      interface_name = {
        match = ["eth*", "enp*"]
      }
    }
    ```

- Exclude interfaces matching `docker*` (`docker0`, `docker1`, `docker-wec2323`):

  ```hcl
  filter "network" {
    interface_name = {
      not_match = ["docker*"]
    }
  }
  ```

- `interface_index` attribute - [pattern matcher object](#pattern-matcher-object), default `{}`.

  Filter by network interface index.
  Supported values in patterns: Any valid interface index or interface index range as a string (`0`, `1-27`)

  **Examples:**

  - Exclude only interface index 2:

    ```hcl
    filter "network" {
      interface_index = {
        not_match = ["2"]
      }
    }
    ```

  - Include only interfaces `1` to `27` and `30`:

    ```hcl
    filter "network" {
      interface_index = {
        match = ["1-27", "30"]
      }
    }
    ```

- `interface_mac` attribute - [pattern matcher object](#pattern-matcher-object), default `{}`.

  Filter by network interface MAC address.
  Supported values in patterns: Any valid MAC address (supports [globs](https://docs.rs/globset/latest/globset/#syntax))

  **Examples:**

  - Exclude a specific MAC address:

    ```hcl
    filter "network" {
      interface_mac = {
        not_match = ["00:11:22:33:44:55"]
      }
    }
    ```

### `filter.flow` filter block

The filter applies to various flow attributes in the flow span, such as connection state, TCP flags and others.
Filter is applied at the "Flow Producer" stage ([architecture](../getting-started/agent-architecture.md#components)), which can help reduce resource usage in subsequent stages.

- `connection_state` - [pattern matcher object](#pattern-matcher-object), default `{}`.


  Filter by TCP connection state.
  Supported values in patterns: `established`, `syn_sent`, `syn_received`, `fin_wait`, `close_wait`, `closing`, `last_ack`, `time_wait`, `closed` (supports [globs](https://docs.rs/globset/latest/globset/#syntax))

**Examples:**

- Include only established connections:

  ```hcl
  filter "flow" {
    connection_state = {
      match = ["established"]
    }
  }
  ```

- `tcp_flags_tags` - [pattern matcher object](#pattern-matcher-object), default `{}`.

  Filter by TCP flags.
  Supported values in patterns: `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG` (supports [globs](https://docs.rs/globset/latest/globset/#syntax)), _case insensitive_.

  **Examples:**

  - Include only flows with SYN flag:

    ```hcl
    filter "flow" {
      tcp_flags_tags = {
        match = ["SYN"]
      }
    }
    ```

- `ip_dscp_name` - [pattern matcher object](#pattern-matcher-object), default `{}`.

  Filter flows based on the DSCP ([Differentiated Services Code Point](https://en.wikipedia.org/wiki/Differentiated_services#Configuration_guidelines)) names.
  Supported values in patterns: Any valid DSCP name (supports [globs](https://docs.rs/globset/latest/globset/#syntax))

  **Examples:**

  - Include only low-latency data (`AF21`)

    ```hcl
    filter "flow" {
      ip_dscp_name = { match = ["AF21"] }
    }
    ```

  - Exclude multimedia conferencing (`AF41`, `AF42`, `AF43`)

    ```hcl
    filter "flow" {
      ip_dscp_name = { match = ["AF4{1,2,3}"] }
    }
    ```

- `ip_ecn_name` - [pattern matcher object](#pattern-matcher-object), default `{}`.

  Filter flows based on ECN ([Explicit Congestion Notification](https://en.wikipedia.org/wiki/Explicit_congestion_notification)) values.
  Supported values in patterns: Any valid ECN value (supports [globs](https://docs.rs/globset/latest/globset/#syntax))

  **Examples:**

  - Include only ECN-capable transport (`ECT0`, `ECT1`)

    ```hcl
    filter "flow" {
      ip_ecn_name = { match = ["ECT?"] }
    }
    ```

  - Exclude congestion encountered (`CE`)

    ```hcl
    filter "flow" {
      ip_ecn_name = { not_match = ["CE"] }
    }
    ```

- `ip_ttl` - [pattern matcher object](#pattern-matcher-object), default `{}`.

  Filter flows based on the IP TTL ([Time To Live](https://en.wikipedia.org/wiki/Time_to_live)) values.
  Supported values in patterns: Any valid TTL or TTL range as a string (`1`, `64-184`)

  **Examples:**

  - Include only packets with the TTL `1` and `64` to `128`

    ```hcl
    filter "flow" {
      ip_ttl = { match = ["1", "64-184"] }
    }
    ```

  - Exclude packets with the TTL `64`

    ```hcl
    filter "flow" {
      ip_ttl = { not_match = ["64"] }
    }
    ```

- `ip_flow_label` - [pattern matcher object](#pattern-matcher-object), default `{}`.

  Filter flows based on IPv6 [flow labels](https://www.rfc-editor.org/rfc/rfc6437.html).
  Supported values in patterns: Any valid flow label or label range (`2145`, `12345-12545`)

  **Examples:**

  - Include only flows with label 12345

    ```hcl
    filter "flow" {
      ip_flow_label = { match = ["12345"] }
    }
    ```

  - Exclude flows with labels in a range

    ```hcl
    filter "flow" {
      ip_flow_label = { not_match = ["12345-12545"] }
    }
    ```

- `icmp_type_name` - [pattern matcher object](#pattern-matcher-object), default `{}`.

  Filter flows based on [ICMP type](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml) names (converted to a [snake case](https://en.wikipedia.org/wiki/Snake_case)).
  Supported values in patterns: Any valid ICMP type name (supports [globs](https://docs.rs/globset/latest/globset/#syntax))

  **Examples:**

  - Include only echo requests

    ```hcl
    filter "flow" {
      icmp_type_name = { match = ["echo_request"] }
    }
    ```

  - Exclude destination unreachable

    ```hcl
    filter "flow" {
      icmp_type_name = { not_match = ["destination_unreachable"] }
    }
    ```

- `icmp_code_name` - [pattern matcher object](#pattern-matcher-object), default `{}`.

  Filter flows based on [ICMP codes](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml).
  Supported values in patterns: Any valid ICMP code or code range as a string (`13`, `0-8`)

  **Examples:**

  - Include codes from `0` to `8` and `13`

    ```hcl
    filter "flow" {
      icmp_code_name = { match = ["0-8", "13"] }
    }
    ```

  - Exclude code `3`

    ```hcl
    filter "flow" {
      icmp_code_name = { not_match = ["3"] }
    }
    ```

## Object types

### Pattern matcher object

- `match` attribute - list of strings, default `[]` (empty list, include all).

  Include flows matching the pattern
- `not_match` attribute - list of strings, default `[]` (empty list, exclude none).

  Exclude flows matching the pattern

#### Matcher value types

Although matcher patterns are strings only, there are multiple types that are supported:

- **IP addresses and CIDRs**, used in the `address` arguments, for example:
  - `10.0.0.0/8`: CIDR notation, matches the subnet
  - `10.0.0.1`: IP address, equals the `10.0.0.1/32` subnet

- **Ranges**, used in the `port`, `interface_index`, `ip_ttl`, `ip_flow_label`, `icmp_code_name` arguments, support ranges. For example:
  - `80`: Single port
  - `8000-8999`: Port range
  - `0`: Single interface index
  - `0-22`: Interface index range
  - `64`: Single TTL
  - `64-128`: TTL range
  - `12345`: Single Flow Label
  - `12345-12445`: Flow Label range
  - `0`: Single ICMP code
  - `0-8`: ICMP code range

- **Arbitrary strings**, used in more generic arguments like transport names, interface names, and others.
  Supports [globs](https://docs.rs/globset/latest/globset/#syntax). For example:
  - `tcp`: Protocol names
  - `close_wait`: Connection states
  - `eth*`: Interface names

## Common Filtering Scenarios

### HTTP/HTTPS Only

The following configuration captures flows with HTTP/HTTPS destination.

```hcl
filter "destination" {
  port = {
    match = ["80", "443"]
  }
}
```

Example flows:

```json
[
  {...,"source.port": "33567", "destination.port": "443", ...}, // included
  {...,"source.port": "443", "destination.port": "33567", ...}, // EXCLUDED
  {...,"source.port": "43567", "destination.port": "80", ...}, // included
  {...,"source.port": "80", "destination.port": "43567", ...}, // EXCLUDED
  {...,"source.port": "53567", "destination.port": "8080", ...}, // EXCLUDED
  {...,"source.port": "8080", "destination.port": "53567", ...}, // EXCLUDED
  ...
]
```

### Exclude Internal Traffic

The following configuration captures flows originating from non-local addresses:

```hcl
filter "source" {
  address = {
    not_match = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  }
}
```

```json
[
  {...,"source.address": "10.0.0.2", "destination.address": "10.0.0.3", ...}, // EXCLUDED
  {...,"source.address": "10.0.0.3", "destination.address": "10.0.0.2", ...}, // EXCLUDED
  {...,"source.address": "10.0.0.2", "destination.address": "92.1.1.1", ...}, // EXCLUDED
  {..., "source.address": "92.1.1.1", "destination.address": "10.0.0.2", ...}, // included
  {..., "source.address": "10.0.0.2", "destination.address": "92.1.1.1", ...}, // EXCLUDED
  ...
]
```

### TCP Only, Established Connections

The following configuration captures flows for established TCP connections.

```hcl
filter "network" {
  transport = {
    match = ["tcp"]
  }
}

filter "flow" {
  connection_state = {
    match = ["established"]
  }
}
```

## Best Practices

1. **Start permissive**: Begin with no filters, add as needed
2. **Monitor impact**: Check flow reduction with metrics
3. **Test incrementally**: Add one filter at a time
4. **Document rationale**: Comment why filters are applied
5. **Use `match`/`not_match` carefully**: Match patterns can hide important traffic

## Next Steps

- [**Configuration Examples**](examples.md): See complete filter configurations
- [**Flow Span Options**](span.md): Configure flow generation
- [**OTLP Export**](export-otlp.md): Configure export options
