# Mermin with OpenTelemetry Collector

- [Mermin with OpenTelemetry Collector](#mermin-with-opentelemetry-collector)
  - [Overview](#overview)
  - [Install](#install)
    - [Debug charts](#debug-charts)

## Overview

This example deploys Mermin with the OpenTelemetry Collector for testing purposes.
The OpenTelemetry Collector's output is set to `debug` (`stdout`), and has been tested by using [Kind](https://kind.sigs.k8s.io/)

Notes on the example deployment:

- You may optionally customize and use `config.hcl` instead of the default config.
- Mermin values use `mermin:latest` image, it is expected you build it and load to your K8s cluster

## Install

- Deploy the chart

  ```sh
  # Deploy OpenTelemetry Collector
  helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
  helm upgrade -i \
    -f examples/local_otel/values_otel.yaml \
    otel-collector open-telemetry/opentelemetry-collector

  # Build Mermin image and load to the Kind cluster
  docker build -t mermin:latest --target runner-debug .
  kind load docker-image -n atlantis mermin:latest

  # Deploy Mermin
  helm upgrade -i --wait --timeout 15m \
    -f examples/local_otel/values_mermin.yaml \
    --set-file config.content=examples/local_otel/config.hcl \
    mermin charts/mermin
  ```

- Optionally install `metrics-server` to get metrics if it has not been installed yet

  ```sh
  kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/download/v0.8.0/components.yaml
  # Patch to use insecure TLS, commonly needed on dev local clusters
  kubectl -n kube-system patch deployment metrics-server --type='json' -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]'
  ```

### Debug charts

In order to render K8s manifests you may use following commands

- OpenTelemetry Collector

  ```sh
  rm -rf helm_rendered; helm template otel-collector \
    -f examples/local_otel/values_otel.yaml \
    --output-dir helm_rendered \
    open-telemetry/opentelemetry-collector
  ```

- Mermin

  ```sh
  rm -rf helm_rendered; helm template \
    -f examples/local_otel/values.yaml \
    --set-file config.content=examples/local_otel/config.hcl \
    --output-dir helm_rendered \
    mermin charts/mermin
  ```
