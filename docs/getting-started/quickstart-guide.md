# Quickstart Guide

This guide will help you deploy Mermin on a local Kubernetes cluster using `kind` (Kubernetes in Docker) in just a few minutes. By the end, you'll have Mermin capturing network flows and displaying them in your terminal.

## Prerequisites

Before starting, ensure you have the following tools installed:

* [**Docker**](https://docs.docker.com/get-docker/): Container runtime
* [**kind**](https://kind.sigs.k8s.io/docs/user/quick-start/#installation): Kubernetes in Docker
* [**kubectl**](https://kubernetes.io/docs/tasks/tools/): Kubernetes command-line tool
* [**Helm**](https://helm.sh/docs/intro/install/): Kubernetes package manager (version 3.x)

{% hint style="info" %}
This quick start is designed for local testing and development. For production deployments, see the [Deployment Guide](../deployment/overview.md).
{% endhint %}

## Step 1: Create a kind Cluster

Create a local Kubernetes cluster using kind:

```bash
# Create a kind configuration file
cat <<EOF > kind-config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: atlantis
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

## Step 2: Deploy Mermin with Helm

Deploy Mermin using the Helm chart with a configuration that outputs flows to stdout (for easy viewing):

```bash
# Add Mermin Helm registry
helm repo add mermin https://elastiflow.github.io/mermin
helm repo update

# Deploy Mermin using Helm
helm upgrade --install mermin mermin/mermin \
  --set-file config.content=docs/deployment/examples/local/config.example.hcl \
  --wait \
  --timeout 5m
```

## Step 3: Verify the Deployment

Check that the Mermin pods are running:

```bash
kubectl get pods -l app.kubernetes.io/name=mermin
```

You should see one Mermin pod per worker node, all in the `Running` state:

```text
NAME           READY   STATUS    RESTARTS   AGE
mermin-abc123  1/1     Running   0          2m
mermin-def456  1/1     Running   0          2m
```

## Step 4: View Network Flow Data

Now let's view the network flows Mermin is capturing:

```bash
# Stream logs from a Mermin pod
kubectl logs -l app.kubernetes.io/name=mermin -f --tail=100
```

You should see flow records in a human-readable format. Let's generate some traffic to see more flows:

```bash
# In a new terminal, create a test pod
kubectl run --rm -it --image=alpine/curl test-pod -- sh

# Inside the test pod, generate traffic
ping -c 10 8.8.8.8
curl https://www.google.com
exit
```

Switch back to the logs terminal, and you'll see network flow records for the traffic you just generated, including:

* Source and destination IP addresses and ports
* Protocol (TCP, UDP, ICMP)
* Packet and byte counts
* Kubernetes metadata (pod name, namespace, labels)

Example flow record (stdout format):

```text
Span #1
        Instrumentation Scope
                Name         : "mermin"

        Name         : flow_ipv4_icmp
        TraceId      : 25532f1af4ef46087ab38fd181e8c409
        SpanId       : 0e610e187627dfac
        TraceFlags   : TraceFlags(1)
        ParentSpanId : f5bc1abf5a703419
        Kind         : Server
        Start time   : 2026-02-04 18:57:36.295385
        End time     : 2026-02-04 18:57:38.297897
        Status       : Unset
        Attributes:
                 ->  flow.community_id: String(Owned("1:a962MiVftHsve9ogcQKeY0/p9bc="))
                 ->  network.type: String(Static("ipv4"))
                 ->  network.transport: String(Static("icmp"))
                 ->  source.address: String(Owned("8.8.8.8"))
                 ->  source.port: I64(0)
                 ->  destination.address: String(Owned("10.244.2.4"))
                 ->  destination.port: I64(0)
                 ->  flow.bytes.delta: I64(98)
                 ->  flow.bytes.total: I64(98)
                 ->  flow.packets.delta: I64(1)
                 ->  flow.packets.total: I64(1)
                 ->  flow.reverse.bytes.delta: I64(0)
                 ->  flow.reverse.bytes.total: I64(0)
                 ->  flow.reverse.packets.delta: I64(0)
                 ->  flow.reverse.packets.total: I64(0)
                 ->  flow.end_reason: String(Static("idle timeout"))
                 ->  network.interface.index: I64(14)
                 ->  network.interface.name: String(Owned("veth8ef8af66"))
                 ->  network.interface.mac: String(Owned("1a:b2:da:f1:5d:d3"))
                 ->  flow.ip.dscp.id: I64(0)
                 ->  flow.ip.dscp.name: String(Owned("df"))
                 ->  flow.ip.ecn.id: I64(0)
                 ->  flow.ip.ecn.name: String(Owned("non-ect"))
                 ->  flow.ip.ttl: I64(62)
                 ->  flow.reverse.ip.ttl: I64(0)
                 ->  flow.reverse.ip.dscp.id: I64(0)
                 ->  flow.reverse.ip.ecn.id: I64(0)
                 ->  flow.icmp.type.id: I64(0)
                 ->  flow.icmp.type.name: String(Owned("echo_reply"))
                 ->  flow.icmp.code.id: I64(0)
                 ->  flow.icmp.code.name: String(Owned(""))
                 ->  flow.reverse.icmp.type.id: I64(0)
                 ->  flow.reverse.icmp.type.name: String(Owned("echo_reply"))
                 ->  flow.reverse.icmp.code.id: I64(0)
                 ->  flow.reverse.icmp.code.name: String(Owned(""))
                 ->  client.address: String(Owned("10.244.2.4"))
                 ->  client.port: I64(0)
                 ->  server.address: String(Owned("dns.google"))
                 ->  server.port: I64(0)
                 ->  destination.k8s.namespace.name: String(Owned("default"))
                 ->  destination.k8s.pod.name: String(Owned("test-pod"))
```

## Step 5: Explore Mermin Features (Optional)

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

### Explore Essential Configuration Options

To view flows with Kubernetes metadata enrichment, Mermin requires four core configuration blocks: Network Interface Discovery, Kubernetes Informer, Flow-to-Kubernetes Attribute Mapping & Export.

A minimal example configuration is available here: [Example Configuration](../deployment/examples/local/config.example.hcl), for a more comprehensive example, please see the [Default Config](https://github.com/elastiflow/mermin/tree/beta/charts/mermin/config/default/config.hcl)

<details>

<summary>Network Interface Discovery</summary>

**CNI-Specific Patterns:**

```hcl
discovery "instrument" {
  # Kind / kindnet
  # interfaces = ["veth*"]

  # Flannel
  # interfaces = ["veth*", "flannel*", "vxlan*"]

  # Calico
  # interfaces = ["veth*", "cali*", "tunl*", "ip6tnl*"]

  # Cilium
  # interfaces = ["veth*", "cilium_*", "lxc*"]

  # GKE
  # interfaces = ["veth*", "gke*"]

  # AWS VPC CNI
  # interfaces = ["veth*", "eni*"]
}
```

Default:

```text
"veth*", "tunl*", "ip6tnl*", "vxlan*", "flannel*", "cali*", "cilium_*", "lxc", "gke*", "eni*", "ovn-k8s*"
```

**What you'll see**: All pod-to-pod traffic (inter-node and intra-node)\
**What you'll miss**: Traffic on other CNI-specific interfaces not listed\
**Use cases**: Fine-tuning for specific CNI setups, reducing monitored interface count

{% hint style="info" %}
Mermin's goal is to show you pod-to-pod traffic which is exposed by Virtual Ethernet Devices, which match patterns like `"veth*", "gke*", "cali*"`. Currently, bridge interfaces like `"tun*"` or `flannel*` are ignored,
because Mermin does not support parsing tunneled/encapsulated traffic. This feature will come very soon.
{% endhint %}

**Physical Interfaces Only:**

{% hint style="warning" %}
Most of the traffic on the physical interfaces will be ignored, because Mermin currently lacks support for tunneled/encapsulated traffic.
{% endhint %}

Monitor only physical network interfaces for inter-node traffic:

```hcl
discovery "instrument" {
  interfaces = ["eth*", "ens*", "en*"]
}
```

**What you'll see**: Inter-node pod traffic, node-to-node traffic, external connections\
**What you'll miss**: Same-node pod-to-pod communication (never hits physical interfaces)

**Trade-offs**: Lower overhead (fewer interfaces), incomplete visibility, may cause flow duplication if combined with veth monitoring\
**Use cases**: Infrastructure-focused monitoring, cost-sensitive deployments, clusters with minimal same-node communication

> **For more information, please reference**: [Network Interface Discovery](../configuration/reference/network-interface-discovery.md)

</details>

<details>

<summary>Kubernetes Informer</summary>

Configures which Kubernetes resources Mermin watches to enrich network flows with metadata. This enables Mermin to associate IP addresses and ports with pod names, services, deployments, and other Kubernetes contexts.

**For more information, please reference:** [Owner Relations](../configuration/reference/kubernetes-owner-relations.md) **&** [Selector Relations](../configuration/reference/kubernetes-selector-relations.md)

</details>

<details>

<summary>Flow-to-Kubernetes Attribute Mapping</summary>

Configures how Mermin matches network flow data (source/destination IPs and ports) to Kubernetes resources. This mapping defines which Kubernetes object fields to extract and how to associate them with captured flows.

> **For more information, please reference:** [Flow Attributes](../configuration/reference/flow-span-kubernetes-attribution.md)

</details>

<details>

<summary>Exporter</summary>

Configures how Mermin exports network flow data. Flows can be sent to an OTLP receiver (OpenTelemetry Protocol) for storage and analysis, or output to stdout for debugging.

> **For more information, please reference:** [OTLP Exporter](../configuration/reference/opentelemetry-otlp-exporter.md)

</details>

## Cleanup

When you're done experimenting, clean up the resources:

```bash
# Remove the test deployment and service (if created)
kubectl delete deployment nginx --ignore-not-found
kubectl delete service nginx --ignore-not-found

# Uninstall Mermin
helm uninstall mermin

# Delete the kind cluster
kind delete cluster --name atlantis
```

## Next Steps

Congratulations! You've successfully deployed Mermin and captured network flows.

To use Mermin in production:

1. [**Review the Architecture**](../concepts/agent-architecture.md) to understand how Mermin works
2. [**Explore Deployment Options**](../deployment/overview.md) for production-ready configurations
3. [**Configure OTLP Export**](../configuration/reference/opentelemetry-otlp-exporter.md) to send flows to your observability backend
4. [**Set Up Integrations**](backend-integrations.md) with Grafana, Elastic, or other platforms
5. [**Customize Configuration**](../configuration/overview.md) to match your environment and requirements

## Troubleshooting

If you encounter issues:

* **Pods not starting**: Check `kubectl describe pod <pod-name>` for errors
* **No Flow Traces**: Verify network interfaces with `kubectl exec <pod-name> -- ip link show`
* **Permission errors**: Ensure the SecurityContext allows privileged mode
* See the [**Troubleshooting Guide**](../troubleshooting/troubleshooting.md) for more help
