# mermin Helm Chart

- [Overview](#overview)
- [Installation](#installation)
- [Configuration](#configuration)

## Overview

Mermin is a suite of Kubernetes native network traffic observability tools. It includes mermin, an eBPF agent for generating flows, and mercoll, an Open Telemetry collector.

## Installation

```sh
helm repo add mermin https://elastiflow.github.io/mermin/
helm repo update
helm install mermin mermin/mermin
```

## Configuration

For configuration information, please refer to the comments in the [default values file](./values.yaml).
