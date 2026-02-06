# Debugging Network Traffic with Wireshark

This guide outlines how to perform live network packet captures from a running pod in your Kubernetes cluster and
inspect the traffic using Wireshark. This is incredibly useful for debugging network policies, service connectivity, and
analyzing the behavior of your eBPF programs.

## Prerequisites

Before you begin, ensure you have the following tools installed and configured on your local machine:

- **kubectl**: The Kubernetes command-line tool, configured to connect to your cluster.
- **Wireshark**: The network protocol analyzer.
- **k9s** (Optional): A terminal-based UI to manage Kubernetes clusters, which simplifies getting a shell into pods.

## 1. Identify Your Target Pod

First, list the running pods to identify the one you want to inspect. Pay attention to the pod's name, its IP address,
and the node it's running on.

```shell
kubectl get pods -o wide
```

You'll see output similar to this:

| NAME         | READY | STATUS  | RESTARTS | AGE | IP          | NODE               | NOMINATED NODE | READINESS GATES |
|--------------|-------|---------|----------|-----|-------------|--------------------|----------------|-----------------|
| mermin-vrxd2 | 1/1   | Running | 0        | 42s | 10.244.0.11 | kind-control-plane | \<none\>       | \<none\>        |
| mermin-8k9x7 | 1/1   | Running | 0        | 42s | 10.244.3.21 | kind-worker        | \<none\>       | \<none\>        |
| mermin-pdsn7 | 1/1   | Running | 0        | 42s | 10.244.1.7  | kind-worker2       | \<none\>       | \<none\>        |

For this example, we will capture traffic from mermin-vrxd2.

## 2. Start the Live Capture

To start the capture, we will use `kubectl debug` to attach a temporary container with networking tools (netshoot) to
our target pod. We'll then pipe the output of tcpdump from that container directly into Wireshark on your local
machine.

Run the following command in your terminal. Replace `<pod-name>` with your target pod's name (e.g., mermin-vrxd2)
and `<container-name>` with the name of the container (e.g., mermin) inside the pod (if it's not the default one).

```shell
kubectl debug -i -q <pod-name> --image=nicolaka/netshoot --target=<container-name> --profile=sysadmin -- tcpdump -i eth0 -w - | wireshark -k -i -
```

### Command Breakdown

- `kubectl debug -i -q <pod-name>`: Attaches an interactive, ephemeral debug container to the specified pod.
- `--image=nicolaka/netshoot`: Uses the netshoot image, which is packed with useful networking utilities like tcpdump.
- `--target=<container-name>`: Specifies which container in the pod to target for debugging.
- `--profile=sysadmin`: Specifies the security context profile to use for the debug container. This is required to
  run tcpdump.
- `-- tcpdump -i eth0 -w -`: Executes tcpdump inside the debug container.
  - `-i eth0`: Listens on the primary network interface, eth0.
  - `-w -`: Writes the raw packet data to standard output (-) instead of a file.
- `| wireshark -k -i -`: Pipes the standard output from tcpdump into Wireshark.
- `-k`: Starts the capture session immediately.
- `-i -`: Reads packet data from standard input (-).

### Example command

```shell
kubectl debug -i -q mermin-vrxd2 --image=nicolaka/netshoot --target=mermin --profile=sysadmin -- tcpdump -i eth0 -w - | wireshark -k -i -
```

Wireshark will launch automatically and begin capturing packets from the pod's network interface.

## 3. Generate Network Traffic

To see packets in Wireshark, you need to generate some network activity. Open a second terminal window and get a
shell into another pod. You can do this with kubectl exec or more easily with a tool like k9s.

From your pod list, pick a different pod to be the source of the traffic (e.g., mermin-8k9x7).

### Get a shell into the source pod

```shell
kubectl exec -it mermin-8k9x7 -- sh
```

### From inside the pod's shell, ping the target pod

```shell
ping -c 4 10.244.0.11
```

## 4. Inspect the Packets

Switch back to Wireshark. You will see the ICMP (ping) request and reply packets appearing in real-time. You can now
use Wireshark's powerful filtering and inspection tools to analyze the traffic in detail, verifying that your eBPF
programs are functioning as expected.

## Common Wireshark Filters

Here are some useful Wireshark display filters for analyzing network traffic:

- `icmp` - Show only ICMP packets (ping)
- `tcp` - Show only TCP traffic
- `udp` - Show only UDP traffic
- `ip.addr == 10.244.0.11` - Show packets to/from a specific IP
- `tcp.port == 80` - Show HTTP traffic
- `tcp.port == 443` - Show HTTPS traffic

## Troubleshooting

### Permission Denied

If you encounter permission issues when running tcpdump, ensure you're using the `--profile=sysadmin` flag in the kubectl debug command.

### Wireshark Not Starting

Ensure Wireshark is installed and available in your PATH. On macOS, you may need to use the full path:

```shell
/Applications/Wireshark.app/Contents/MacOS/Wireshark
```

### No Packets Captured

- Verify the target pod is actually receiving traffic
- Check that you're monitoring the correct network interface (eth0 is typical, but may vary)
- Ensure the debug container successfully attached to the target pod

## Next Steps

{% tabs %}
{% tab title="Continue Debugging" %}
1. [**Inspect eBPF Programs with bpftool**](debugging-ebpf.md): Program inspection and optimization
2. [**Troubleshoot Common Issues**](../troubleshooting/troubleshooting.md): Resolve deployment and capture problems
{% endtab %}

{% tab title="Contribute" %}
1. [**Return to Contributor Guide**](development-workflow.md): Build, test, and contribute
2. [**Read Contributing Guidelines**](../CONTRIBUTING.md): PR process and commit conventions
{% endtab %}
{% endtabs %}

### Need Help?

- [**GitHub Discussions**](https://github.com/elastiflow/mermin/discussions): Ask questions about debugging techniques
