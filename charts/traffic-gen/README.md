# traffic-gen Helm Chart

- [traffic-gen Helm Chart](#traffic-gen-helm-chart)
  - [Overview](#overview)
  - [Installation](#installation)
  - [Configuration](#configuration)

## Overview

This is a dummy traffic generator ([`hey`](https://github.com/rakyll/hey)) and a cronjob with dummy pods that sleep for `0.1` - `3.9` seconds.

- The traffic generator can be ran via deployment and/or cronjob.
- A cronjob with dummy pods iis used to simulate cluster activity

## Installation

```sh
helm install traffic-gen charts/traffic-gen
```

## Configuration

For configuration information, please refer to the comments in the [default values file](./values.yaml).
