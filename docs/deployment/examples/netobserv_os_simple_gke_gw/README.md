# Mermin with NetObserv Flow and OpenSearch in GKE with Gateway

- [Mermin with NetObserv Flow and OpenSearch in GKE with Gateway](#mermin-with-netobserv-flow-and-opensearch-in-gke-with-gateway)
  - [Overview](#overview)
  - [Install](#install)
  - [Access](#access)
  - [Hints](#hints)

## Overview

This example deploys Mermin and NetObserv Flow (as OTel receiver) with OpenSearch as the data platform in a GCP GKE cluster.
This example is intended only for demonstration, testing, or proof-of-concept use, since OpenSearch is deployed in a single-node mode.

Notes on the example deployment:

- This example assumes you can access internal GCP subnets via a VPN.
- Namespace used in the example: `elastiflow`.
- GKE [node auto-provisioning](https://cloud.google.com/kubernetes-engine/docs/how-to/node-auto-provisioning) must be enabled.
- Gateway API is used to route the traffic to the NetObserv Collector (API and OTel gRPC) so it must be enabled on the GKE custer - [doc](https://cloud.google.com/kubernetes-engine/docs/how-to/deploying-gateways#enable-gateway).
- TLS:
  - GCP Load Balancer (ingress) needs the backend with TLS enabled since OTlp input uses gRPC, so a self-signed certificate is used (validity `Not After : Sep 24 10:48:37 2035 GMT`)
  - In order to enable gRPC between client and GCP Load Balancer certificate is also required, same self-signed certificate is used.
  - HTTP (port `80`) is completely disabled on the GCP Load Balancer that is used for the collector (gRPC, REST)
- A GKE internal load balancer is used for the OpenSearch Dashboard ingress.
- Spot instances are used, please tweak affinity and tolerations in the `values.yaml` if needed.
- You may optionally customize and use `config.hcl` instead of the default config.

## Install

The installation process consists of two phases:

1. Install NetObserv with OpenSearch.
2. Install Mermin.

This installation assumes that no additional DNS controllers are running in the cluster. Therefore, it is not possible to know the IP address of the NetObserv gRPC load balancer without extra GCP actions before the NetObserv chart (dependency) is ready.

- Phase 1
  - Add Helm charts and Deploy

    ```sh
    helm repo add mermin https://elastiflow.github.io/mermin/
    helm repo add netobserv https://elastiflow.github.io/helm-chart-netobserv/
    helm repo add opensearch https://opensearch-project.github.io/helm-charts/
    helm repo update
    # Deploy
    helm upgrade -i --wait --timeout 15m -n elastiflow \
      -f values.yaml \
      --set-file mermin.config.content=config.hcl \
      --devel \
      mermin mermin/mermin-netobserv-os-stack
    ```

- Phase 2:
  - Get the NetObserv Gateway (Load Balancer) IP

    ```sh
    kubectl get gtw netobserv-flow -o=jsonpath='{.status.addresses[0].value}'
    ```

  - Modify `export.traces.otlp.endpoint` in the `config.hcl` to the value from the previous step and redeploy the chart

    ```sh
    helm upgrade -i --wait --timeout 15m -n elastiflow \
      -f values.yaml \
      --set-file mermin.config.content=config.hcl \
      --devel \
      mermin mermin/mermin-netobserv-os-stack
    ```

## Access

First, get the OpenSearch Dashboards address:

```sh
kubectl get ingress elastiflow-os-dashboards -o=jsonpath='{.status.loadBalancer.ingress[0].ip}'
```

Now you can navigate to the obtained IP in your browser (assuming you have access to the private network), using `admin`/`Elast1flow!` as the user/password. Select "global tenant", and explore the data.

## Hints

To render and diff Helm templates to Kubernetes manifests, run:

```sh
rm -rf helm_rendered; helm template -n elastiflow \
  -f values.yaml \
  --set-file mermin.config.content=config.hcl \
  --devel \
  mermin mermin/mermin-netobserv-os-stack \
  --output-dir helm_rendered

# Diff with existing K8s resources
kubectl diff -R -f helm_rendered/mermin/
```
