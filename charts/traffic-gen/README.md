# mermin Helm Chart

- [mermin Helm Chart](#mermin-helm-chart)
  - [Overview](#overview)
  - [Installation](#installation)
  - [Configuration](#configuration)

## Overview

Mermin is a Kubernetes-native network observability tool that uses eBPF to capture network traffic and export it as Flow Traces via the OpenTelemetry Protocol (OTLP).

## Installation

```sh
helm repo add mermin https://elastiflow.github.io/mermin/
helm repo update
helm install mermin mermin/mermin
```

## Configuration

For configuration information, please refer to the comments in the [default values file](./values.yaml).
