# Local Performance Testing

The document describes an opinionated reproducible local environment

## Prerequisites

Ensure you have the following installed:

- [**Docker**](https://docs.docker.com/get-docker/): Container runtime
- [**kind**](https://kind.sigs.k8s.io/docs/user/quick-start/#installation): Kubernetes in Docker
- [**kubectl**](https://kubernetes.io/docs/tasks/tools/): Kubernetes command-line tool
- [**Helm**](https://helm.sh/docs/intro/install/): Kubernetes package manager (version 3.x)
- [**colima**](./development-workflow.md#using-colima-for-lsm-development)

## Overview

Under the hood the reproducible local environment consists of:

- Kind local K8s cluster
- [metrics-server](https://github.com/kubernetes-sigs/metrics-server) for resource metrics
- [Prometheus stack](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack) to visualize metrics
- [Sample backend](https://github.com/stefanprodan/podinfo/tree/master/charts/podinfo) to accept HTTP requests
- [traffic-gen](https://github.com/elastiflow/mermin/tree/main/charts/traffic-gen) to generate flows and simulate cluster activity
- Mermin itself with [example config](../deployment/examples/local/config.example.hcl) and [values](../deployment/examples/local/values.yaml)
  - Optionally deployment with the [OTel collector](../deployment/examples/local-otel/README.md) is supported using [otel config](../deployment/examples/local-otel/config.hcl)

A set of `Makefile` targets (`hack/local-perf-testing/lpt.mk`) is provided for convenient spin-up, teardown, build and rebuild.

## Workflow

1. Spin-up the environment

    ```shell
    make lpt-kind-create lpt-up
    ```

    Optionally deploy [Mermin with the OTel output to a local OTel collector](../deployment/examples/local-otel/README.md)

    ```shell
    make lpt-mermin-otel
    ```

2. Expose grafana (accessible via `http://localhost:3000/`)

    ```shell
    until kubectl -n prometheus port-forward svc/prometheus-grafana 3000:3000; do sleep 3; done
    ```

3. Import the [workload resources](https://github.com/elastiflow/mermin/tree/main/hack/local-perf-testing/workload-resources.json) dashboard
4. Test, observe

To teardown the environment (delete Kind cluster) run

```shell
make lpt-kind-delete
```

### Mermin source, config and values

The "local" values and config is used for Mermin, in order to modify them make changes to

- `docs/deployment/examples/local/config.example.hcl`
- `docs/deployment/examples/local/values.yaml`

And run:

```shell
make lpt-mermin
# or
make lpt-mermin-otlp
```

In order to test local changes you need to rebuild Mermin image and restart Mermin daemonset

```shell
make lpt-build-restart
```

{% hint style="info" %}
Will work only if `mermin:latest` is defined in the values
{% endhint %}

### Modify the traffic generator

Default values should produce around 49k active flows and 1600 flows per second.

In order to modify the traffic generate you may simply change the default `docs/deployment/examples/local/values.yaml` and re-deploy the generator

```shell
make lpt-traffic-gen
```

## `lpt` Makefile targets

- Kind Cluster Management
  - `lpt-kind-create`: Create a local Kind Kubernetes cluster using a predefined config.
  - `lpt-kind-delete`: Delete the Kind cluster named "atlantis".

- Mermin Build & Deployment
  - `lpt-build`: Build the `mermin:latest` Docker image (debug), and load it into the Kind cluster.
  - `lpt-build-restart`: Build the image and restart the Mermin daemonset to pick up the new image.
  - `lpt-mermin`: Install the Mermin Helm chart with a sample config.
  - `lpt-mermin-otel`: Install the Mermin Helm chart with OpenTelemetry integration and deploy a local OTel collector.

- Monitoring & Sample Apps
  - `lpt-mon`: Deploy the monitoring stack (metrics-server, Prometheus, Grafana).
  - `lpt-sample-be`: Deploy a sample backend (podinfo) with Redis enabled.
  - `lpt-traffic-gen`: Deploy the traffic generator Helm chart.
  - `lpt-doc`: Print commands to port-forward Grafana, Prometheus, and the sample backend for local access.

- Convenience Targets
  - `lpt-up`: Run all steps to build, deploy monitoring, Mermin, sample backend, traffic generator, and print port-forward instructions.
