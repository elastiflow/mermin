# Attribute Reference

This document is a quick reference for all flow span attributes in Mermin. For design rationale and the full specification, see [Semantic Conventions](../spec/semantic-conventions.md).

## Overview

Each network flow is represented as a single OpenTelemetry Span with:

* **Span Name**: `flow_<network.type>_<network.transport>` (e.g., `flow_ipv4_tcp`)
* **Span Kind**: `CLIENT` (forward/initiator), `SERVER` (reverse/responder), or `INTERNAL` (unknown)

## Example Span (OTLP JSON)

{% include "../.gitbook/includes/example-flow-trace.md" %}

{% include "../.gitbook/includes/attributes.md" %}
