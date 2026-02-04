# Beta Program

Thank you for participating in the Mermin beta program. Mermin captures network traffic passing through your Kubernetes cluster and generates flow traces in OpenTelemetry format,
allowing you to see exactly what is happening inside your cluster. See [Mermin Overview](../) for a more detailed description of what Mermin can do for you.

We plan to update the beta image multiple times throughout this beta period. We will reach out to you every time a new version is available and describe the changes included.

## Accessing the Beta Image

> **Version Requirement**: v0.1.0-beta.40 or higher

Before starting, add the beta Helm chart:

```bash
# Add Helm repository
helm repo add mermin https://elastiflow.github.io/mermin/
helm repo update
```

## Configuration Essentials

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

**Default:**

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

**For more information, please reference:** [Owner Relations](../configuration/owner-relations.md) **&** [Selector Relations](../configuration/selector-relations.md)

</details>

<details>

<summary>Flow-to-Kubernetes Attribute Mapping</summary>

Configures how Mermin matches network flow data (source/destination IPs and ports) to Kubernetes resources. This mapping defines which Kubernetes object fields to extract and how to associate them with captured flows.

> **For more information, please reference:** [Flow Attributes](../configuration/attributes.md)

</details>

<details>

<summary>Exporter</summary>

Configures how Mermin exports network flow data. Flows can be sent to an OTLP receiver (OpenTelemetry Protocol) for storage and analysis, or output to stdout for debugging.

> **For more information, please reference:** [OTLP Exporter](../configuration/export-otlp.md)

</details>

## Deploying Mermin

Once your configuration is ready, you can deploy with the following command:

```bash
helm upgrade -i mermin mermin/mermin \
  --namespace elastiflow \
  --create-namespace \
  --set-file config.content=config.hcl \
  --wait --devel

# Verify deployment
kubectl -n elastiflow get pods -l app.kubernetes.io/name=mermin
```

* **Additional Helm deployment examples**
  * [Mermin with OpenTelemetry Collector](../deployment/examples/local_otel/)
  * [Mermin with NetObserv Flow and OpenSearch](../deployment/examples/netobserv_os_simple_svc/)
  * [Mermin with NetObserv Flow and OpenSearch in GKE with Gateway](../deployment/examples/netobserv_os_simple_gke_gw/)

## See Your First Flows

View network flows captured by Mermin:

```bash
# Stream flow logs
kubectl -n elastiflow logs -l app.kubernetes.io/name=mermin -f --tail=20

# In a new terminal, generate test traffic
kubectl run test-traffic --rm -it --image=busybox -- ping -c 5 8.8.8.8
```

**Expected output** (flow span example):

```text
Flow Span:
  TraceID: 1a2b3c4d5e6f7g8h9i0j
  Source: 10.244.1.5:54321 (test-traffic pod)
  Destination: 8.8.8.8:0
  Protocol: ICMP
  Packets: 5 sent, 5 received
  Bytes: 420 sent, 420 received
  Duration: 4.2s
```

## Known Limitations

<details>

<summary><b>Tunneled/Encapsulated Traffic Parsing</b></summary>

Deep packet parsing for tunneled traffic is not yet implemented in userspace.

**Current functionality:**

The default configuration monitors veth interfaces and CNI-specific interfaces where packets are already decapsulated. This includes:

* veth\* interfaces (pod network namespaces)
* CNI workload interfaces (cali\*, cilium\__, lxc_, eni\*, etc.)

**Not currently supported:**

* Direct monitoring of tunnel interfaces (tunl\*, vxlan\*, flannel\*) as the primary capture point
* Bare metal deployments where packet encapsulation is not removed
* Parsing nested/encapsulated protocol headers

</details>

<details>

<summary><b>Kernel and Platform Compatibility</b></summary>

Mermin has been tested and verified on the following platforms:

| Platform         | Status    |
| ---------------- | --------- |
| Debian 13        | Supported |
| Debian 12        | Supported |
| GKE Standard     | Supported |
| Kind (local dev) | Supported |

**Important:** eBPF verifier requirements vary between kernel versions. If you encounter eBPF program loading failures, include your kernel version when reporting the issue.

</details>

## eBPF Errors

When deploying Mermin for the first time, you may encounter issues.
Depending on your kernel version, you may encounter eBPF verifier errors. See [Troubleshoot Common eBPF Errors](../troubleshooting/common-ebpf-errors.md) for details.

**Minimum requirements:**

* Linux kernel 5.4 or later (may work, but has not been fully tested)
* BTF support enabled
* eBPF support enabled

**Note:** While Mermin may work on kernels older than 6.1, it has been tested and validated on 6.1+. If you encounter verifier errors on older kernels, please report the issue with your kernel version using the template below.

## Reporting Issues

If you encounter problems during the beta, please report them using the template below. This information helps us diagnose and resolve issues quickly

Feedback Channels

* **Email**: [merminbeta@elastiflow.com](mailto:merminbeta@elastiflow.com)​
* **Slack:** [Click to Join](https://join.slack.com/t/elastiflowcommunity/shared_invite/zt-23jpnlw9g-Q4nKOwKKOE1N2MjfA2mXpg)

{% code expandable="true" %}

```markup
**Issue Title:** [Brief description of the problem]
**Problem Description:**
[Describe what's happening and what you expected to happen]
**Error Messages:***
**Config File:**
**Environment:**
- Mermin Version: [e.g., v0.1.0-beta.40]
- Platform: [GKE/EKS/AKS/bare metal/Kind/other]
- Kubernetes Version: [output of `kubectl version --short`]
- Kernel Version: [output of `uname -r`]
- Node OS: [e.g., Debian 12, Ubuntu 22.04, etc.]
- CNI: [e.g., Calico, Flannel, Cilium, kindnet, etc.]

#### Additional Information to Include
- **eBPF Verifier Errors**: Include the full verifier output from logs
- **Interface Issues**: List output of `ip link show` from the node
- **Deployment Method**: Helm chart version and values used
- **Resource Constraints**: Pod resource limits/requests if relevant
- Additional Context: [Any other relevant information - recent changes, specific workloads, etc.]
```

{% endcode %}
