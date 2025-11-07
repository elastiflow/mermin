# mermin Helm Chart

- [mermin Helm Chart](#mermin-helm-chart)
  - [Overview](#overview)
  - [Installation](#installation)

## Overview

This is a composite chart to install Mermin with NetObserv, OpenSearch and OpenSearch Dashboards

## Installation

```sh
helm repo add mermin https://elastiflow.github.io/mermin/
helm repo update
helm install mermin-netobserv-os-stack mermin/mermin-netobserv-os-stack
```
