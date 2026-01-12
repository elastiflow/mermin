# Mermin with GreptimeDB

* [Mermin with GreptimeDB](./#mermin-with-greptimedb)
    * [Overview](./#overview)
    * [Install](./#install)
        * [Cluster Foundations](./#cluster-foundations)
        * [GreptimeDB](./#greptimedb)
        * [Mermin](./#mermin)

## Overview

This example deploys Mermin alongside a standalone GreptimeDB instance for persistence. Mermin is configured to write metrics directly to GreptimeDB via HTTP using the OTLP protocol.

Notes on the example deployment:

* [Location in the repository](https://github.com/elastiflow/mermin/tree/beta/docs/deployment/examples/local_greptime) - `docs/deployment/examples/local_greptime`
* **Topology**: Mermin runs as a DaemonSet to monitor pod-to-pod communication on all nodes.
* **Storage**: GreptimeDB is deployed as the persistence layer for network telemetry.
* **Connectivity**: Mermin sends data directly to GreptimeDB using `http_binary` protocol.

## Install

### GreptimeDB

Deploy GreptimeDB to serve as the persistence layer for the collected network telemetry.

* The `values_greptime.yaml` includes slight modifications to GreptimeDB to accept Mermin output. Pull the standalone GreptimeDB helm chart and install the modified version:

    ```sh
    helm repo add greptime https://greptimeteam.github.io/helm-charts/
    helm repo update
    helm install greptimedb greptime/greptimedb \
      --namespace elastiflow \
      --create-namespace \
      -f values_greptime.yaml
    ```

### Mermin

Deploy Mermin configured to output directly to the GreptimeDB service using HTTP headers required for signal parsing.

* Create a `config.hcl` file with [contents](config.hcl), or use the one from the repo. Modify as desired, but retain the `otlp_http_headers` and `otlp_protocol` sections.
  If you would like to run with TLS enabled, add TLS configurations (caCert, clientCert, clientKey) to `config.hcl`, and modify Mermin's `values.yaml` to include the certificate.

* Build and load the Mermin image into the cluster:

    ```sh
    docker build -t mermin:latest --target runner-debug .
    kind load docker-image -n atlantis mermin:latest
    ```

* Deploy the Mermin chart:

    ```sh
    helm upgrade -i --wait --timeout 15m -n elastiflow --create-namespace \
      -f docs/deployment/examples/local/values.yaml \
      --set-file config.content=config.hcl \
      --devel \
      mermin charts/mermin
    ```

* Optionally install `metrics-server` to get metrics if it has not been installed yet

    ```sh
    kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/download/v0.8.0/components.yaml
    # Patch to use insecure TLS, commonly needed on dev local clusters
    kubectl -n kube-system patch deployment metrics-server --type='json' -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]'
    ```


In order to render K8s manifests you may use following commands

* OpenTelemetry Collector

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

