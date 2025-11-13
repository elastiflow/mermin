# Metrics Testing Guide

This guide demonstrates how to deploy Mermin to a local Kubernetes cluster, generate network traffic between pods, and inspect the Prometheus metrics endpoint to verify proper instrumentation.

## Prerequisites

Ensure you have the following installed:

* [**Docker**](https://docs.docker.com/get-docker/): Container runtime
* [**kind**](https://kind.sigs.k8s.io/docs/user/quick-start/#installation): Kubernetes in Docker
* [**kubectl**](https://kubernetes.io/docs/tasks/tools/): Kubernetes command-line tool
* [**Helm**](https://helm.sh/docs/intro/install/): Kubernetes package manager (version 3.x)
* **k9s** (optional): Terminal-based Kubernetes UI

Also be sure to read the relevant metrics documentation first to get an understanding of the types of metrics that exist for Mermin. This page is a minimal working example to view metrics output.
@TODO: Link to final metrics pages in Gitbook.

## Complete Example Workflow

```bash
# 1. Setup
kind create cluster --config docs/deployment/examples/local/kind-config.yaml
docker build -t mermin:latest --target runner-debug .
kind load docker-image mermin:latest --name atlantis

# 2. Deploy
helm upgrade --install mermin ./charts/mermin \
  --values docs/deployment/examples/local/values.yaml

# 3. Generate traffic
kubectl create deployment nginx --image=nginx --replicas=2
kubectl expose deployment nginx --port=80
kubectl run traffic-gen --image=curlimages/curl --rm -it -- sh -c \
  'for i in {1..30}; do curl -s http://nginx > /dev/null && echo "Request $i"; sleep 2; done'

# 4. View metrics
POD=$(kubectl get pod -l app.kubernetes.io/name=mermin -o jsonpath='{.items[0].metadata.name}')
kubectl exec $POD -- wget -qO- http://localhost:10250/metrics 2>/dev/null | grep -E "userspace|span_flows"

# 5. Cleanup
helm uninstall mermin
kubectl delete deployment nginx
kind delete cluster --name atlantis
```

