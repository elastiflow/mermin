# Beta Program

{% include "../.gitbook/includes/version-requirement-v0.1.0... (2).md" %}

### Accessing Beta Image

Before starting, configure access to the beta Helm charts and container images:

```bash
# Add Helm repositories
helm repo add \
  --username x-access-token \
  --password ${GH_PAT} \
  mermin https://raw.githubusercontent.com/elastiflow/mermin/gh-pages

helm repo add netobserv https://elastiflow.github.io/helm-chart-netobserv/
helm repo add opensearch https://opensearch-project.github.io/helm-charts/
helm repo update

# Create namespace and image pull secret
kubectl create namespace elastiflow

kubectl -n elastiflow create secret docker-registry ghcr \
    --docker-server=ghcr.io \
    --docker-username=elastiflow-ghcr \
    --docker-password=${CLASSIC_GH_TOKEN}
```

**Required credentials:**

* `GH_PAT`: Your GitHub Personal Access Token
* `CLASSIC_GH_TOKEN`: Provided GitHub token for ghcr.io access

### Configuration Essentials

To see flows with Kubernetes metadata enrichment, Mermin requires three core configuration blocks:

#### Network Interface Discovery

Configure which network interfaces Mermin monitors. Choose based on your visibility needs:

**Recommended: CNI Bridge Interfaces (Pod-Focused)**

**Best for application monitoring** - Captures all pod-to-pod traffic, including intra-node communication:

```hcl
discovery "instrument" {
  # CNI bridge interfaces - captures all pod traffic
  # Choose patterns matching your CNI:
  
  # Flannel
  interfaces = ["cni*", "flannel*"]
  
  # Calico
  # interfaces = ["cali*", "tunl*"]
  
  # Cilium
  # interfaces = ["cilium_*", "lxc*"]
  
  # GKE
  # interfaces = ["gke*"]
  
  # AWS VPC CNI
  # interfaces = ["eni*"]
  
  # Multi-CNI (comprehensive)
  # interfaces = ["cni*", "flannel*", "cali*", "tunl*", "cilium_*", "lxc*", "gke*", "eni*"]
}
```

**What you'll see**: All pod-to-pod traffic (both inter-node and intra-node)\
**What you'll miss**: Host network pods, node-to-node infrastructure traffic\
**Note**: Generates 4 flow records per inter-node flow, 2 per intra-node flow (deduplication coming soon)

**Alternative: Physical Interfaces (Infrastructure-Focused)**

**Best for node/infrastructure monitoring** - Captures only inter-node traffic:

```hcl
discovery "instrument" {
  # Physical network interfaces
  interfaces = ["eth*", "ens*", "en*"]
}
```

**What you'll see**: Inter-node pod traffic, node-to-node traffic, host network pods\
**What you'll miss**: Intra-node pod-to-pod communication\
**Note**: Generates 2 flow records per flow (one at the source node, one at the destination node)

> **For more information please reference**:  [Network Interface Discovery](../configuration/discovery-interfaces.md)

#### Kubernetes Informer Discovery

Defines which Kubernetes resources to watch for metadata enrichment

```hcl
discovery "informer" "k8s" {
  # Kubernetes resources to watch
  selectors = [
    { kind = "Service" }, { kind = "Endpoint" }, { kind = "EndpointSlice" },
    { kind = "Gateway" }, { kind = "Ingress" },
    { kind = "Pod" }, { kind = "ReplicaSet" }, { kind = "Deployment" },
    { kind = "DaemonSet" }, { kind = "StatefulSet" },
    { kind = "Job" }, { kind = "CronJob" }, { kind = "NetworkPolicy" }
  ]

  # Owner reference walking (Pod -> ReplicaSet -> Deployment)
  owner_relations = {
    max_depth     = 5
    include_kinds = ["Service"]
    exclude_kinds = ["EndpointSlice"]
  }

  # Selector-based relations (NetworkPolicy -> Pod, Service -> Pod)
  selector_relations = [
    {
      kind                             = "NetworkPolicy"
      to                               = "Pod"
      selector_match_labels_field      = "spec.podSelector.matchLabels"
      selector_match_expressions_field = "spec.podSelector.matchExpressions"
    },
    {
      kind                        = "Service"
      to                          = "Pod"
      selector_match_labels_field = "spec.selector"
    }
  ]
}
```

> **For more information please reference:** [Owner Relations](../configuration/owner-relations.md) **&**  [Selector Relations](../configuration/selector-relations.md)&#x20;

#### Flow-to-Kubernetes Attribute Mapping

Maps flow data (IPs, ports) to Kubernetes resources:

```hcl
# Source IP/port mapping
attributes "source" "k8s" {
  extract {
    metadata = [
      "[*].metadata.name",
      "[*].metadata.namespace",
      "[*].metadata.uid"
    ]
  }

  association {
    pod = {
      sources = [
        { from = "flow", name = "source.ip", to = ["status.podIP", "status.podIPs[*]"] },
        { from = "flow", name = "source.port", to = ["spec.containers[*].ports[*].containerPort"] }
      ]
    }
    service = {
      sources = [
        { from = "flow", name = "source.ip", to = ["spec.clusterIP", "spec.clusterIPs[*]"] },
        { from = "flow", name = "source.port", to = ["spec.ports[*].port"] }
      ]
    }
  }
}

# Destination IP/port mapping
attributes "destination" "k8s" {
  extract {
    metadata = [
      "[*].metadata.name",
      "[*].metadata.namespace",
      "[*].metadata.uid"
    ]
  }

  association {
    pod = {
      sources = [
        { from = "flow", name = "destination.ip", to = ["status.podIP", "status.podIPs[*]"] },
        { from = "flow", name = "destination.port", to = ["spec.containers[*].ports[*].containerPort"] }
      ]
    }
    service = {
      sources = [
        { from = "flow", name = "destination.ip", to = ["spec.clusterIP", "spec.clusterIPs[*]"] },
        { from = "flow", name = "destination.port", to = ["spec.ports[*].port"] }
      ]
    }
  }
}
```

> **For more information please reference:** [Flow Attributes](../configuration/attributes.md)

### Running Mermin With Configuration

A fleshed-out config is available here: [Examples](../../charts/mermin/config/examples/config.hcl). Once the config is ready, you can deploy it with the following command.

{% include "../.gitbook/includes/helm-install-mermin-mermin-....md" %}

### See Your First Flows

View network flows captured by Mermin:

```bash
# Stream flow logs
kubectl -n elastiflow logs -l app.kubernetes.io/name=mermin -f --tail=20

# In a new terminal, generate test traffic
kubectl run test-traffic --rm -it --image=busybox -- ping -c 5 8.8.8.8
```

**Expected output** (flow span example):

```
Flow Span:
  TraceID: 1a2b3c4d5e6f7g8h9i0j
  Source: 10.244.1.5:54321 (test-traffic pod)
  Destination: 8.8.8.8:0
  Protocol: ICMP
  Packets: 5 sent, 5 received
  Bytes: 420 sent, 420 received
  Duration: 4.2s
```

### Next Steps

* **Full Deployment Guide** - Production deployment with OTLP
* **OTLP Configuration** - Export to observability backends
* **Integrations** - Connect to Grafana, Elastic, Tempo, Jaeger
* **Architecture Overview** - How Mermin works
* **Configuration Reference** - Complete configuration options
* **Troubleshooting** - Common issues and solutions

### Providing Feedback

* **Email**: [merminbeta@elastiflow.com](mailto:merminbeta@elastiflow.com)
* **Slack:** [**https://elastiflowcommunity.slack.com/archives/C09MANJTSP3**](https://elastiflowcommunity.slack.com/archives/C09MANJTSP3)

