# Mermin with GreptimeDB

* [Mermin with GreptimeDB](./#mermin-with-greptimedb)
    * [Overview](./#overview)
    * [Install](./#install)
        * [Cluster Foundations](./#cluster-foundations)
        * [GreptimeDB](./#greptimedb)
        * [Mermin](./#mermin)

## Overview

This example deploys Mermin alongside a standalone GreptimeDB instance for persistence. Mermin is configured to write metrics directly to GreptimeDB via HTTP using the OTLP protocol. This deployment has been tested by using [Kind](https://kind.sigs.k8s.io/)

Notes on the example deployment:

* [Location in the repository](https://github.com/elastiflow/mermin/tree/beta/docs/deployment/examples/local_greptime) - `docs/deployment/examples/local_greptime`
* **Topology**: Mermin runs as a DaemonSet to monitor pod-to-pod communication on all nodes.
* **Storage**: GreptimeDB is deployed as the persistence layer for network telemetry.
* **Connectivity**: Mermin sends data directly to GreptimeDB using `http_binary` protocol.

## Install

### GreptimeDB

Deploy GreptimeDB to serve as the persistence layer for the collected network telemetry.

* Create a values file for GreptimeDB with [contents](values_greptime.yaml) or use one from the repo, which includes configurations to receive Mermin metrics.
* Deploy GreptimeDB using the values file and the helm chart provided by the Greptime team.

    ```sh
    helm repo add greptime https://greptimeteam.github.io/helm-charts/
    helm repo update
    helm install greptimedb greptime/greptimedb-standalone  \
      -f values_greptime.yaml
    ```

### Mermin

Deploy Mermin configured to output directly to the GreptimeDB service using HTTP headers required for signal parsing.

* Create a `config.hcl` file with [contents](config.hcl), or use the one from the repo. Modify as desired, but retain the `otlp_http_headers` and `otlp_protocol` sections.
* Note: TLS is disabled in the repository example. This is not recommended for production deployments.

* Deploy the Mermin chart

    ```sh
    helm repo add mermin https://elastiflow.github.io/mermin/
    helm upgrade -i --wait --timeout 15m \
      -f docs/deployment/examples/local/values.yaml \
      --set-file config.content=config.hcl \
      --devel \
      mermin mermin/mermin
    ```

* Optionally install `metrics-server` to get metrics if it has not been installed yet

    ```sh
    kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/download/v0.8.0/components.yaml
    # Patch to use insecure TLS, commonly needed on dev local clusters
    kubectl -n kube-system patch deployment metrics-server --type='json' -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]'
    ```

### Debug charts

In order to render K8s manifests you may use following commands

* GreptimeDB

        ```sh
  rm -rf helm_rendered; helm template \
  -f values_greptime.yaml \
  greptimedb greptime/greptimedb \
  --output-dir helm_rendered

  # Diff with existing K8s resources
  kubectl diff -R -f helm_rendered/greptimedb/
    ```
  
* Mermin

    ```sh
    rm -rf helm_rendered; helm template \
      --set-file config.content=config.hcl \
      --devel \
      mermin mermin/mermin \
      --output-dir helm_rendered

    # Diff with existing K8s resources
    kubectl diff -R -f helm_rendered/mermin/    
    ```

