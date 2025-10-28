# Quick Start

This guide will help you deploy Mermin on a local Kubernetes cluster using `kind` (Kubernetes in Docker) in just a few minutes. By the end, you'll have Mermin capturing network flows and displaying them in your terminal.

## Prerequisites

Before starting, ensure you have the following tools installed:

- **[Docker](https://docs.docker.com/get-docker/)**: Container runtime
- **[kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)**: Kubernetes in Docker
- **[kubectl](https://kubernetes.io/docs/tasks/tools/)**: Kubernetes command-line tool
- **[Helm](https://helm.sh/docs/intro/install/)**: Kubernetes package manager (version 3.x)

{% hint style="info" %}
This quick start is designed for local testing and development. For production deployments, see the [Deployment Guide](deployment/README.md).
{% endhint %}

## Step 1: Create a kind Cluster

First, create a local Kubernetes cluster using kind:

```bash
# Create a kind configuration file
cat <<EOF > kind-config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: mermin-demo
nodes:
  - role: control-plane
  - role: worker
  - role: worker
EOF

# Create the cluster
kind create cluster --config kind-config.yaml
```

This creates a cluster with one control plane node and two worker nodes, providing multiple nodes to observe inter-node network traffic.

Verify the cluster is running:

```bash
kubectl get nodes
```

You should see three nodes in the `Ready` state.

## Step 2: Build and Load the Mermin Image

Build the Mermin container image and load it into the kind cluster:

// TODO: REPLACE WITH DOCKER PULL COMMAND

```bash
# Clone the repository (if you haven't already)
git clone https://github.com/elastiflow/mermin.git
cd mermin

# Build the Mermin image
docker build -t mermin:latest --target runner-debug .

# Load the image into kind
kind load docker-image mermin:latest --name mermin-demo
```

{% hint style="warning" %}
Building the image may take several minutes on the first run as it compiles the eBPF programs and Rust binaries.
{% endhint %}

## Step 3: Deploy Mermin with Helm

Deploy Mermin using the Helm chart with a configuration that outputs flows to stdout (for easy viewing):

```bash
# Create a basic configuration file
cat <<EOF > mermin-config.hcl
# Logging configuration
log_level = "info"

# Network interfaces to monitor (default patterns for kind)
discovery "instrument" {
  interfaces = ["eth*", "ens*"]
}

# Export configuration - output to stdout for easy viewing
export "traces" {
  stdout = "text_indent"
}

# API and metrics configuration
api {
  enabled = true
  listen_address = "0.0.0.0"
  port = 8080
}

metrics {
  enabled = true
  listen_address = "0.0.0.0"
  port = 10250
}
EOF

# Deploy Mermin using Helm
helm upgrade --install mermin ./charts/mermin \
  --set image.tag=latest \
  --set image.pullPolicy=Never \
  --set-file config.content=mermin-config.hcl \
  --wait \
  --timeout 10m
```

## Step 4: Verify the Deployment

Check that the Mermin pods are running:

```bash
kubectl get pods -l app.kubernetes.io/name=mermin
```

You should see one Mermin pod per worker node, all in the `Running` state:

```
NAME           READY   STATUS    RESTARTS   AGE
mermin-abc123  1/1     Running   0          2m
mermin-def456  1/1     Running   0          2m
```

Check the health of a Mermin pod:

```bash
# Get pod name
POD_NAME=$(kubectl get pods -l app.kubernetes.io/name=mermin -o jsonpath='{.items[0].metadata.name}')

# Check health endpoints
kubectl exec $POD_NAME -- wget -q -O- http://localhost:8080/livez
kubectl exec $POD_NAME -- wget -q -O- http://localhost:8080/readyz
```

Both should return `ok`.

## Step 5: View Network Flow Data

Now let's view the network flows Mermin is capturing:

```bash
# Stream logs from a Mermin pod
kubectl logs -l app.kubernetes.io/name=mermin -f --tail=20
```

You should see flow records in a human-readable format. Let's generate some traffic to see more flows:

```bash
# In a new terminal, create a test pod
kubectl run test-pod --image=nicolaka/netshoot -it --rm -- bash

# Inside the test pod, generate traffic
ping -c 10 8.8.8.8
curl https://www.google.com
exit
```

Switch back to the logs terminal, and you'll see network flow records for the traffic you just generated, including:

- Source and destination IP addresses and ports
- Protocol (TCP, UDP, ICMP)
- Packet and byte counts
- Kubernetes metadata (pod name, namespace, labels)

Example flow record (stdout format):

```
Flow Record:
  Timestamp: 2025-10-27T10:30:45Z
  Source: 10.244.1.5:45678 (test-pod)
  Destination: 8.8.8.8:0
  Protocol: ICMP
  Packets: 10 sent, 10 received
  Bytes: 840 sent, 840 received
  Namespace: default
```

## Step 6: Explore Mermin Features (Optional)

### Check Metrics

Mermin exposes Prometheus metrics. You can view them with:

```bash
kubectl port-forward -n default \
  $(kubectl get pods -l app.kubernetes.io/name=mermin -o jsonpath='{.items[0].metadata.name}') \
  10250:10250
```

Then in another terminal or browser, access `http://localhost:10250/metrics`.

### View Kubernetes Metadata Enrichment

Create a deployment and service to see richer metadata:

```bash
kubectl create deployment nginx --image=nginx --replicas=2
kubectl expose deployment nginx --port=80 --type=ClusterIP
kubectl run curl-test --image=curlimages/curl -it --rm -- curl http://nginx
```

The flow logs will now include metadata about the nginx deployment, service, and pods.

## Cleanup

When you're done experimenting, clean up the resources:

```bash
# Remove the test deployment and service (if created)
kubectl delete deployment nginx --ignore-not-found
kubectl delete service nginx --ignore-not-found

# Uninstall Mermin
helm uninstall mermin

# Delete the kind cluster
kind delete cluster --name mermin-demo
```

## Next Steps

Congratulations! You've successfully deployed Mermin and captured network flows.

To use Mermin in production:

1. **[Review the Architecture](architecture.md)** to understand how Mermin works
2. **[Explore Deployment Options](deployment/README.md)** for production-ready configurations
3. **[Configure OTLP Export](configuration/export-otlp.md)** to send flows to your observability backend
4. **[Set Up Integrations](integrations/README.md)** with Grafana, Elastic, or other platforms
5. **[Customize Configuration](configuration/README.md)** to match your environment and requirements

## Troubleshooting

If you encounter issues:

- **Pods not starting**: Check `kubectl describe pod <pod-name>` for errors
- **No Flow Traces**: Verify network interfaces with `kubectl exec <pod-name> -- ip link show`
- **Permission errors**: Ensure the SecurityContext allows privileged mode
- See the **[Troubleshooting Guide](troubleshooting/README.md)** for more help
