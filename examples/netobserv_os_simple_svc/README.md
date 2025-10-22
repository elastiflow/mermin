# Mermin with NetObserv Flow and OpenSearch

- [Mermin with NetObserv Flow and OpenSearch](#mermin-with-netobserv-flow-and-opensearch)
  - [Overview](#overview)
  - [Install](#install)
  - [Access](#access)
  - [Hints](#hints)

## Overview

This example deploys Mermin and NetObserv Flow (as OTel receiver) with OpenSearch as the data platform. Although local [Kind](https://kind.sigs.k8s.io/) was used for testing, any kubernetes cluster should work if nodes have sufficient resources and don't have any taints that should be tolerated (`tolerations` values may be used)
This example is intended only for demonstration, testing, or proof-of-concept use, since OpenSearch is deployed in a single-node mode.

Notes on the example deployment:

- Namespace used in the example: `elastiflow`.
- Allocatable resources needed (mCPU/MiB):
  - OpenSearch `2000m`/`4000Mi`
  - OpenSearch Dashboards `1000m`/`768M`
  - NetObserv Flow `1000m`/`6000Mi`
- You may optionally customize and use `config.hcl` instead of the default config.

## Install

<!-- TODO(Cleanup for GA): Once repo is public, this step should become part of the next step without any dependencies -->
- Add Mermin Helm chart

  ```sh
  helm repo add \
    --username x-access-token \
    --password ${GH_PAT} \
    mermin https://raw.githubusercontent.com/elastiflow/mermin/gh-pages
  ```

- Deploy the chart

  ```sh
  helm repo add netobserv https://elastiflow.github.io/helm-chart-netobserv/
  helm repo add opensearch https://opensearch-project.github.io/helm-charts/
  helm repo update
  helm dependency build mermin/mermin-netobserv-os-stack
  kubectl create namespace elastiflow

  # TODO(Cleanup for GA): image pull secrets not needed when going public
  kubectl create secret docker-registry ghcr \
      --docker-server=ghcr.io \
      --docker-username=elastiflow-ghcr \
      --docker-password=${CLASSIC_GH_TOKEN}

  # Deploy
  helm upgrade -i --wait --timeout 15m -n elastiflow \
    -f examples/netobserv_os_simple_svc/values.yaml \
    --set-file mermin.config.content=examples/netobserv_os_simple_svc/config.hcl \
    mermin mermin/mermin-netobserv-os-stack
  ```

- Optionally install `metrics-server` to get metrics if it has not been installed yet

  ```sh
  kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/download/v0.8.0/components.yaml
  # Patch to use insecure TLS, commonly needed on dev local clusters
  kubectl -n kube-system patch deployment metrics-server --type='json' -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]'
  ```

## Access

First, port forward the OpenSearch Dashboards service

```sh
kubectl port-forward svc/elastiflow-os-dashboards 5601:5601
```

Now you can navigate to `http://localhost:5601/` in your browser to open OpenSearch Dashboards, using `admin`/`Elast1flow!` as the user/password. Select "global tenant", and explore the data.

## Hints

To render and diff Helm templates to Kubernetes manifests, run:

```sh
rm -rf helm_rendered; helm template -n elastiflow \
  -f examples/netobserv_os_simple_svc/values.yaml \
  --set-file mermin.config.content=examples/netobserv_os_simple_svc/config.hcl \
  --output-dir helm_rendered \
  mermin mermin/mermin-netobserv-os-stack

# Diff with existing K8s resources
kubectl diff -R -f helm_rendered/mermin/
```
