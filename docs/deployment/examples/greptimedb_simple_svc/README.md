---
hidden: true
---

# Mermin with GreptimeDB

- [Mermin with GreptimeDB](#mermin-with-greptimedb)
  - [Overview](#overview)
  - [Install](#install)
    - [GreptimeDB](#greptimedb)
    - [Mermin](#mermin)
  - [Access](#access)
  - [Debug charts](#debug-charts)

## Overview

This example deploys Mermin alongside a standalone GreptimeDB instance for persistence. Mermin is configured to write metrics directly to GreptimeDB via HTTP using the OTLP protocol.
Although local [Kind](https://kind.sigs.k8s.io/) was used for testing, any kubernetes cluster should work if nodes have sufficient resources

Notes on the example deployment:

- [Location in the repository](https://github.com/elastiflow/mermin/tree/beta/docs/deployment/examples/local_greptime) - `docs/deployment/examples/local_greptime`
- **Topology**: Mermin runs as a DaemonSet to monitor pod-to-pod communication on all nodes.
- **Storage**: GreptimeDB is deployed as the persistence layer for network telemetry.
- **Connectivity**: Mermin sends data directly to GreptimeDB using `http_binary` protocol.
- GreptimeDB is accessed via K8s Service (ClusterIP) for simplicity.

## Install

### GreptimeDB

Deploy GreptimeDB to serve as the persistence layer for the collected network telemetry.

- Create a values file for GreptimeDB with [contents](values_greptime.yaml) or use one from the repo, which includes configurations to receive Mermin metrics.
- Deploy GreptimeDB using the values file and the helm chart provided by the Greptime team.

    ```sh
    helm repo add greptime https://greptimeteam.github.io/helm-charts/
    helm repo update
    helm upgrade -i --wait --timeout 15m -n greptimedb --create-namespace \
      -f values_greptime.yaml \
      greptimedb greptime/greptimedb-standalone
    ```

### Mermin

Deploy Mermin configured to output directly to the GreptimeDB service using HTTP headers required for signal parsing.

- Create a `config.hcl` file with [contents](config.hcl), or use the one from the repo. Modify as desired, but retain the `export.traces.otlp.headers` and `export.traces.otlp.protocol` sections.
- Note: TLS is disabled in the repository example. This is not recommended for production deployments.
- Deploy the Mermin chart

    ```sh
    helm repo add mermin https://elastiflow.github.io/mermin/
    helm repo update
    helm upgrade -i --wait --timeout 15m -n elastiflow --create-namespace \
      --set-file config.content=config.hcl \
      --devel \
      mermin mermin/mermin
    ```

- Optionally install `metrics-server` to get metrics if it has not been installed yet

    ```sh
    kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/download/v0.8.0/components.yaml
    # Patch to use insecure TLS, commonly needed on dev local clusters
    kubectl -n kube-system patch deployment metrics-server --type='json' -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]'
    ```

## Access

You may ensure the data is reaching GreptimeDB by using a [GreptimeDB Dashboard App](https://github.com/GreptimeTeam/dashboard/releases).

- First, port forward the OpenSearch Dashboards service

  ```sh
  kubectl -n greptimedb port-forward svc/greptimedb-greptimedb-standalone 4000:4000
  ```

- Use `http://localhost:4000` as host and `public` as database.
- Run following query to ensure data is reaching GreptimeDB
  
  ```sql
  SELECT * FROM "opentelemetry_traces" WHERE "span_attributes.source.k8s.pod.name" IS NOT NULL ORDER BY "timestamp" DESC LIMIT 100
  ```

## Debug charts

In order to render K8s manifests you may use following commands

- GreptimeDB

  ```sh
  rm -rf helm_rendered; helm template \
    -n greptimedb \
    -f values_greptime.yaml \
    greptimedb greptime/greptimedb-standalone \
    --output-dir helm_rendered

  # Diff with existing K8s resources
  kubectl -n greptimedb diff -R -f helm_rendered/greptimedb-standalone/
  ```
  
- Mermin

    ```sh
    rm -rf helm_rendered; helm template \
      -n elastiflow \
      --set-file config.content=config.hcl \
      --devel \
      mermin mermin/mermin \
      --output-dir helm_rendered

    # Diff with existing K8s resources
    kubectl diff -R -f helm_rendered/mermin/    
    ```
