# Attribute Reference

This document is a quick reference for all flow span attributes in Mermin. For design rationale and the full specification, see [Semantic Conventions](../concepts/semantic-conventions.md).

## Overview

Each network flow is represented as a single OpenTelemetry Span with:

* **Span Name**: `flow_<network.type>_<network.transport>` (e.g., `flow_ipv4_tcp`)
* **Span Kind**: `CLIENT` (forward/initiator), `SERVER` (reverse/responder), or `INTERNAL` (unknown)

## Example Span (OTLP JSON)

{% include "../.gitbook/includes/example-flow-trace.md" %}

{% include "../.gitbook/includes/attributes.md" %}

---

## Next Steps

{% tabs %}
{% tab title="Learn More" %}
1. [**Explore the Full Specification**](../concepts/semantic-conventions.md): Design rationale and detailed semantics
2. [**Understand How Flows Are Generated**](../concepts/agent-architecture.md): Agent architecture and data flow
{% endtab %}

{% tab title="Use Flow Traces" %}
1. [**Query Flow Traces in Your Backend**](backend-integrations.md): Use these attributes in your observability platform
2. [**Configure Filters**](../configuration/reference/flow-span-filters.md): Filter flows by attribute values
{% endtab %}
{% endtabs %}

### Need Help?

- [**GitHub Discussions**](https://github.com/elastiflow/mermin/discussions): Ask about specific attributes
