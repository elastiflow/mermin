# Flow Span Primer (In progress)

## Introduction
This document is a non-normative, user-friendly introduction to the Flow Span semantic convention. It is intended for those who want to understand the core concepts and motivation behind representing network flow data within OpenTelemetry without reading the full specification.

---
## What is a Flow Span?
A **Flow Span** is a single OpenTelemetry Span that represents one network flow record.

Traditionally, OpenTelemetry traces are focused on application-level requests. A Flow Span, however, captures the network conversation itself—the bidirectional exchange of packets between two endpoints as observed by a network monitoring point (like an eBPF agent or network device).

The entire collection of related flow spans can be thought of as a **Flow Trace**.

---
## Why a New Convention?
Existing OpenTelemetry network conventions are primarily designed from the perspective of an instrumented application, capturing a client's request or a server's response. They don't adequately model the full, bidirectional nature of a network conversation as seen by an independent observer.

This convention fills that gap by providing a standard way to represent rich, third-party network observations, enabling a deeper level of observability.

### Goals
* **Standardize Network Flow Data:** Provide a single, consistent model for network flows within the OpenTelemetry ecosystem.
* **Enable Correlation:** Create a clear path for correlating high-level application traces with the underlying network conversations that support them.
* **Provide Full Context:** Capture not just the five-tuple, but also bidirectional metrics, performance data (latency/jitter), tunnel information, and rich Kubernetes metadata.

---
## Core Concepts

### Flow Record as a Span
The fundamental idea is a one-to-one mapping. One flow record, exported when a network conversation ends or times out, becomes one span.
* The **Span's start and end times** represent the observation window of the flow record.
* The **Span's attributes** contain all the details of the flow.

### Bidirectional Metrics
Network conversations are two-way. To represent this, we capture metrics for both the forward (source -> destination) and reverse (destination -> source) directions of the flow.
* `flow.bytes.delta` measures bytes from source to destination.
* `flow.reverse.bytes.delta` measures bytes from destination back to source.

### Attribute Namespaces
To keep the convention clean and easy to understand, attributes are organized into logical groups:
* **`flow.*`**: Attributes describing the conversation as a whole.
* **`network.*`**: Protocol-specific details (IP, TCP, etc.).
* **`source.*` / `destination.*`**: Information about the two endpoints, including IP addresses and Kubernetes metadata.

---
## Example
Here is what a simple Flow Span might look like in OTLP JSON format. It represents a TCP flow between two Kubernetes pods.
```json
{
  "name": "flow",
  "kind": "SPAN_KIND_INTERNAL",
  "startTimeUnixNano": "1727149620000000000",
  "endTimeUnixNano": "1727149680000000000",
  "attributes": [
    { "key": "flow.community_id", "value": { "stringValue": "1:LQU9qZlK+B+2dM2I2n1kI/M5a/g=" } },
    { "key": "flow.direction", "value": { "stringValue": "initiator" } },
    { "key": "flow.bytes.delta", "value": { "intValue": "1024" } },
    { "key": "flow.reverse.bytes.delta", "value": { "intValue": "32768" } },
    { "key": "source.address", "value": { "stringValue": "10.1.1.5" } },
    { "key": "source.port", "value": { "intValue": "54211" } },
    { "key": "source.k8s.pod.name", "value": { "stringValue": "frontend-abcde" } },
    { "key": "destination.address", "value": { "stringValue": "10.1.2.10" } },
    { "key": "destination.port", "value": { "intValue": "80" } },
    { "key": "destination.k8s.pod.name", "value": { "stringValue": "backend-xyz" } },
    { "key": "network.transport", "value": { "stringValue": "tcp" } }
  ]
}
