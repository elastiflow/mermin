---
hidden: true
---

# Docker on Bare Metal

This guide covers deploying Mermin as a Docker container on bare metal or virtual machines without Kubernetes. This is useful for monitoring standalone Linux hosts or environments where Kubernetes is not available.

{% hint style="warning" %}
Kubernetes metadata enrichment is not available in bare metal deployments. Flows will only contain network-level information (IPs, ports, protocols) without pod, service, or deployment metadata.
{% endhint %}

## Prerequisites

Before deploying on bare metal:

* **Linux OS**: RHEL/CentOS 7+, Ubuntu 18.04+, Debian 10+, or similar
* **Linux Kernel**: Version 4.18 or newer with eBPF support
* **Docker**: Version 19.03 or newer, or containerd/Podman as alternative
* **Root Access**: Required to run privileged containers
* **Network Access**: To OTLP collector endpoint

### Verify eBPF Support

Check that your kernel supports eBPF:

```bash
# Check kernel version
uname -r
# Should be >= 4.18

# Verify CONFIG_BPF is enabled
grep CONFIG_BPF /boot/config-$(uname -r)
# Should show: CONFIG_BPF=y

# Check for BPF filesystem
mount | grep bpf
# Should show: bpffs on /sys/fs/bpf type bpf
```

If `bpffs` is not mounted:

```bash
sudo mount -t bpf bpf /sys/fs/bpf
```

## Configuration

Create a Mermin configuration file optimized for bare metal:

```hcl
# mermin-baremental.hcl

# Logging configuration
log_level = "info"

# Shutdown timeout
shutdown_timeout = "10s"

# Pipeline configuration
pipeline {
  ring_buffer_capacity = 8192
  worker_count = 4
}

# Network interfaces to monitor
discovery "instrument" {
  # Adjust interface names for your system
  # Use: ip link show
  interfaces = ["eth0", "ens*"]
}

# Flow span configuration
span {
  max_record_interval = "60s"
  generic_timeout = "30s"
  icmp_timeout = "10s"
  tcp_timeout = "20s"
  tcp_fin_timeout = "5s"
  tcp_rst_timeout = "5s"
  udp_timeout = "60s"
  community_id_seed = 0
}

# OTLP exporter configuration
export "traces" {
  # For testing: output to stdout
  stdout = "text_indent"

  # For production: send to OTLP collector
  # otlp = {
  #   endpoint = "http://collector.example.com:4317"
  #   protocol = "grpc"
  #   timeout = "10s"
  #   max_batch_size = 512
  #   max_batch_interval = "5s"
  #   max_queue_size = 2048
  # }
}

# API server (health checks)
api {
  enabled = true
  listen_address = "0.0.0.0"
  port = 8080
}

# Metrics server (Prometheus)
metrics {
  enabled = true
  listen_address = "0.0.0.0"
  port = 10250
}

# Parser configuration
parser {
  geneve_port = 6081
  vxlan_port = 4789
  wireguard_port = 51820
}
```

## Deployment with Docker

### Pull the Image

```bash
docker pull ghcr.io/elastiflow/mermin:latest
```

### Run Mermin Container

Run Mermin with necessary privileges and volume mounts:

```bash
docker run -d \
  --name mermin \
  --privileged \
  --network host \
  --pid host \
  --cap-add SYS_ADMIN \
  --cap-add SYS_PTRACE \
  --cap-add NET_ADMIN \
  --cap-add BPF \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v $(pwd)/mermin-baremetal.hcl:/etc/mermin/config.hcl:ro \
  ghcr.io/elastiflow/mermin:latest \
  --config /etc/mermin/config.hcl
```

**Flags explained:**

* `--privileged`: Required for eBPF program loading
* `--network host`: Access host network interfaces
* `--pid host`: Access host process information (optional)
* `--cap-add`: Explicit capabilities for eBPF and networking
* `-v /sys/kernel/debug`: Debug filesystem for eBPF (read-only)
* `-v /sys/fs/bpf`: BPF filesystem for program management
* `-v config.hcl`: Mount configuration file

### Verify Deployment

Check that the container is running:

```bash
docker ps | grep mermin
```

View logs:

```bash
docker logs mermin -f
```

Check health:

```bash
curl http://localhost:8080/livez
curl http://localhost:8080/readyz
```

Both should return `ok`.

## Deployment with Systemd

For production deployments, use systemd to manage the container:

### Create Systemd Service

```bash
sudo nano /etc/systemd/system/mermin.service
```

```ini
[Unit]
Description=Mermin Network Observability Agent
After=docker.service
Requires=docker.service

[Service]
Type=simple
Restart=always
RestartSec=10
TimeoutStartSec=0
ExecStartPre=-/usr/bin/docker stop mermin
ExecStartPre=-/usr/bin/docker rm mermin
ExecStartPre=/usr/bin/docker pull ghcr.io/elastiflow/mermin:latest
ExecStart=/usr/bin/docker run --rm \
  --name mermin \
  --privileged \
  --network host \
  --pid host \
  --cap-add SYS_ADMIN \
  --cap-add SYS_PTRACE \
  --cap-add NET_ADMIN \
  --cap-add BPF \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /etc/mermin/config.hcl:/etc/mermin/config.hcl:ro \
  ghcr.io/elastiflow/mermin:latest \
  --config /etc/mermin/config.hcl
ExecStop=/usr/bin/docker stop mermin

[Install]
WantedBy=multi-user.target
```

### Enable and Start Service

```bash
# Create config directory
sudo mkdir -p /etc/mermin
sudo cp mermin-baremetal.hcl /etc/mermin/config.hcl

# Reload systemd
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable mermin

# Start service
sudo systemctl start mermin

# Check status
sudo systemctl status mermin

# View logs
sudo journalctl -u mermin -f
```

## Deployment with Podman

Podman is a daemonless alternative to Docker:

```bash
# Run with Podman (similar flags as Docker)
podman run -d \
  --name mermin \
  --privileged \
  --network host \
  --pid host \
  --cap-add SYS_ADMIN \
  --cap-add SYS_PTRACE \
  --cap-add NET_ADMIN \
  --cap-add BPF \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v $(pwd)/mermin-baremetal.hcl:/etc/mermin/config.hcl:ro \
  ghcr.io/elastiflow/mermin:latest \
  --config /etc/mermin/config.hcl

# Generate systemd service unit
podman generate systemd --name mermin --files --new

# Move service file and enable
sudo mv container-mermin.service /etc/systemd/system/mermin.service
sudo systemctl daemon-reload
sudo systemctl enable mermin
sudo systemctl start mermin
```

## Configuration for Bare Metal

### Identifying Network Interfaces

List available interfaces:

```bash
ip link show
```

Common interface naming:

* **Traditional**: `eth0`, `eth1`
* **Predictable**: `ens32`, `eno1`, `enp0s3`
* **Virtual**: `docker0`, `veth*`, `br-*`

Update your configuration:

```hcl
discovery "instrument" {
  # Monitor primary interface
  interfaces = ["ens32"]

  # Or use glob patterns
  # interfaces = ["eth*", "ens*"]
}
```

### Multi-Host Deployments

Deploy Mermin on multiple hosts for fleet-wide observability:

**Host 1:**

```hcl
export "traces" {
  otlp = {
    endpoint = "http://central-collector.example.com:4317"
    protocol = "grpc"

    # Add host identifier
    resource_attributes = {
      "host.name" = "web-server-01"
      "host.ip" = "192.168.1.10"
      "host.role" = "webserver"
    }
  }
}
```

**Host 2:**

```hcl
export "traces" {
  otlp = {
    endpoint = "http://central-collector.example.com:4317"
    protocol = "grpc"

    resource_attributes = {
      "host.name" = "db-server-01"
      "host.ip" = "192.168.1.20"
      "host.role" = "database"
    }
  }
}
```

## Monitoring and Logs

### View Real-Time Logs

```bash
# Docker
docker logs mermin -f --tail 100

# Systemd
sudo journalctl -u mermin -f -n 100
```

### Access Metrics

```bash
# Prometheus metrics
curl http://localhost:10250/metrics

# Or use port forwarding if needed
ssh -L 10250:localhost:10250 user@remote-host
# Then access http://localhost:10250/metrics locally
```

### Log Rotation

Configure Docker log rotation in `/etc/docker/daemon.json`:

```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "5"
  }
}
```

Restart Docker:

```bash
sudo systemctl restart docker
sudo systemctl restart mermin
```

## Limitations Compared to Kubernetes

Bare metal deployments have these limitations:

| Feature               | Kubernetes  | Bare Metal      |
| --------------------- | ----------- | --------------- |
| **Pod Metadata**      | ✅ Full      | ❌ Not Available |
| **Service Mapping**   | ✅ Yes       | ❌ No            |
| **Owner References**  | ✅ Yes       | ❌ No            |
| **Network Policies**  | ✅ Yes       | ❌ No            |
| **Auto-Discovery**    | ✅ Informers | ❌ Manual Config |
| **Flow Traces**       | ✅ Available | ✅ Available     |
| **Protocol Analysis** | ✅ Available | ✅ Available     |

Bare metal deployments capture raw network flows without Kubernetes context.

## Use Cases for Bare Metal

Bare metal deployments are suitable for:

* **Non-Kubernetes Environments**: Traditional VMs or physical servers
* **Host-Level Monitoring**: Monitor host OS network activity
* **Hybrid Environments**: Bridge Kubernetes and non-Kubernetes infrastructure
* **Edge Deployments**: Lightweight observability at edge locations
* **Testing and Development**: Quick setup for experimentation

## Troubleshooting

### Container Exits Immediately

Check logs for errors:

```bash
docker logs mermin
```

Common causes:

* Missing configuration file
* Invalid configuration syntax
* Interface not found

### "Operation not permitted" Errors

Ensure container has necessary privileges:

```bash
docker run --privileged \
  --cap-add SYS_ADMIN \
  --cap-add SYS_PTRACE \
  --cap-add NET_ADMIN \
  --cap-add BPF \
  ...
```

### No Flow Traces

Check that interfaces exist:

```bash
docker exec mermin ip link show
```

Verify eBPF programs are loaded:

```bash
docker exec mermin ls /sys/fs/bpf/
```

### High CPU Usage

Reduce monitored interfaces:

```hcl
discovery "instrument" {
  # Monitor only specific interface
  interfaces = ["eth0"]
}
```

Increase flow timeouts:

```hcl
span {
  generic_timeout = "60s"
  tcp_timeout = "30s"
  udp_timeout = "120s"
}
```

## Updating Mermin

### Docker

```bash
# Stop and remove old container
docker stop mermin
docker rm mermin

# Pull new image
docker pull ghcr.io/elastiflow/mermin:latest

# Start with same configuration
docker run -d ... [same flags as before]
```

### Systemd

```bash
# Service will automatically pull latest on restart
sudo systemctl restart mermin

# Or manually
sudo systemctl stop mermin
docker pull ghcr.io/elastiflow/mermin:latest
sudo systemctl start mermin
```

## Best Practices

1. **Always use systemd**: For production deployments
2. **Configure log rotation**: Prevent disk filling
3. **Monitor resource usage**: Set up alerts on CPU/memory
4. **Use configuration management**: Ansible, Puppet, or Chef for fleet deployments
5. **Secure OTLP connections**: Use TLS and authentication
6. **Test configuration**: Validate before rolling out to production
7. **Document host identifiers**: Maintain inventory of monitored hosts

## Next Steps

* [**Configuration Reference**](../configuration/configuration.md): Optimize for bare metal
* [**OTLP Export**](../configuration/export-otlp.md): Configure secure export
* [**Observability Backends**](../observability/backends.md): Send data to observability backends
* [**Troubleshooting**](../troubleshooting/troubleshooting.md): Solve common issues

For Kubernetes deployments with full metadata enrichment, see [**Kubernetes with Helm**](kubernetes-helm.md).
