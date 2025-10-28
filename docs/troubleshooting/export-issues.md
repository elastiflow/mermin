# Export Issues

This guide helps resolve problems sending Flow Traces to OTLP endpoints and observability backends.

## OTLP Connection Failures

### Symptom

Logs show connection errors:

```
ERROR Failed to export traces: connection refused
ERROR OTLP export timeout
```

Metrics show export errors:

```bash
curl http://localhost:10250/metrics | grep mermin_export_errors_total
```

### Diagnosis

Test connectivity from Mermin pod:

```bash
# Test OTLP gRPC endpoint
kubectl exec mermin-xxxxx -n mermin -- \
  nc -zv otel-collector 4317

# Test OTLP HTTP endpoint
kubectl exec mermin-xxxxx -n mermin -- \
  nc -zv otel-collector 4318
```

Check DNS resolution:

```bash
kubectl exec mermin-xxxxx -n mermin -- \
  nslookup otel-collector
```

### Common Causes

#### 1. Wrong Endpoint Address

**Solution**: Verify endpoint format and address:

```hcl
export "traces" {
  otlp = {
    # gRPC: no http:// prefix needed, or use full URL
    endpoint = "otel-collector:4317"
    protocol = "grpc"

    # OR for HTTP
    # endpoint = "http://otel-collector:4318"
    # protocol = "http_binary"
  }
}
```

Common mistakes:

* Using `https://` with `protocol = "grpc"` (should be just hostname:port)
* Wrong port (4317 for gRPC, 4318 for HTTP)
* Missing service namespace: `otel-collector.observability.svc.cluster.local`

#### 2. Network Policy Blocking Egress

**Diagnosis**: Check NetworkPolicies:

```bash
kubectl get networkpolicies -n mermin
kubectl describe networkpolicy <policy-name> -n mermin
```

**Solution**: Allow egress to OTLP endpoint:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mermin-allow-otlp
  namespace: mermin
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: mermin
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: observability
      ports:
        - protocol: TCP
          port: 4317
```

#### 3. Service Not Ready

**Diagnosis**: Check OTLP collector status:

```bash
kubectl get pods -n observability
kubectl logs -n observability otel-collector-xxxxx
```

**Solution**: Wait for collector to be ready or check collector logs for errors.

#### 4. Timeout Too Short

**Symptom**: Intermittent connection failures or timeouts.

**Solution**: Increase timeout:

```hcl
export "traces" {
  otlp = {
    timeout = "60s"  # Increase from default 30s
    max_export_timeout = "2m"
  }
}
```

## TLS Certificate Errors

### Symptom

Logs show TLS errors:

```
ERROR OTLP export failed: x509: certificate signed by unknown authority
ERROR TLS handshake failed: certificate verify failed
```

### Common Causes

#### 1. Self-Signed Certificates

**Solution (Insecure - Development Only)**:

```hcl
export "traces" {
  otlp = {
    endpoint = "otel-collector:4317"
    tls = {
      insecure = true  # Skip TLS verification - NOT FOR PRODUCTION
    }
  }
}
```

**Solution (Production - Use CA Certificate)**:

```hcl
export "traces" {
  otlp = {
    endpoint = "otel-collector:4317"
    tls = {
      ca_file = "/etc/mermin/certs/ca.crt"  # Mount CA cert as volume
    }
  }
}
```

Mount certificate in Helm deployment:

```yaml
# values.yaml
extraVolumes:
  - name: ca-cert
    configMap:
      name: ca-certificate

extraVolumeMounts:
  - name: ca-cert
    mountPath: /etc/mermin/certs
    readOnly: true
```

#### 2. Expired Certificates

**Diagnosis**:

```bash
# Check certificate expiry
kubectl exec mermin-xxxxx -n mermin -- \
  openssl s_client -connect otel-collector:4317 -showcerts
```

**Solution**: Renew certificates and update mounted certificate files.

#### 3. Hostname Mismatch

**Symptom**: Certificate doesn't match endpoint hostname.

**Solution**: Override TLS server name:

```hcl
export "traces" {
  otlp = {
    endpoint = "192.168.1.100:4317"  # Using IP
    tls = {
      server_name = "otel-collector.example.com"  # Certificate CN/SAN
    }
  }
}
```

## Mutual TLS (mTLS) Errors

### Symptom

```
ERROR TLS handshake failed: tls: bad certificate
ERROR Client certificate required
```

### Solution

Configure client certificate and key:

```hcl
export "traces" {
  otlp = {
    endpoint = "otel-collector:4317"
    tls = {
      cert_file = "/etc/mermin/certs/client.crt"
      key_file = "/etc/mermin/certs/client.key"
      ca_file = "/etc/mermin/certs/ca.crt"
    }
  }
}
```

Mount certificates via Kubernetes Secret:

```yaml
# values.yaml
extraVolumes:
  - name: tls-certs
    secret:
      secretName: mermin-tls-certs

extraVolumeMounts:
  - name: tls-certs
    mountPath: /etc/mermin/certs
    readOnly: true
```

## Authentication Failures

### Symptom

```
ERROR OTLP export failed: unauthenticated
ERROR HTTP 401 Unauthorized
```

### Common Causes

#### 1. Missing Authentication Credentials

**Solution**: Configure basic auth or bearer token:

**Basic Auth**:

```hcl
export "traces" {
  otlp = {
    endpoint = "otel-collector:4317"
    auth = {
      basic = {
        username = "mermin"
        password = "secret123"
      }
    }
  }
}
```

**Bearer Token** (using custom headers):

```hcl
export "traces" {
  otlp = {
    endpoint = "otel-collector:4317"
    headers = {
      "authorization" = "Bearer YOUR_API_TOKEN"
    }
  }
}
```

#### 2. Credentials from Environment Variables

**Best Practice**: Don't hardcode credentials in config files.

Use environment variables:

```bash
# In Helm values.yaml
env:
  - name: OTLP_USERNAME
    valueFrom:
      secretKeyRef:
        name: otlp-credentials
        key: username
  - name: OTLP_PASSWORD
    valueFrom:
      secretKeyRef:
        name: otlp-credentials
        key: password
```

Reference in HCL:

```hcl
export "traces" {
  otlp = {
    auth = {
      basic = {
        username = "${OTLP_USERNAME}"
        password = "${OTLP_PASSWORD}"
      }
    }
  }
}
```

## Batching and Backpressure

### Symptom

```
WARN Export queue full, dropping flows
ERROR Batch export failed: deadline exceeded
```

Metrics show growing queue:

```bash
curl http://localhost:10250/metrics | grep mermin_export_queue_size
```

### Common Causes

#### 1. Backend Too Slow

Collector/backend can't keep up with Mermin's export rate.

**Solution**: Increase concurrent exports and batch size:

```hcl
export "traces" {
  otlp = {
    max_concurrent_exports = 8     # More parallel requests
    max_batch_size = 2048           # Larger batches = fewer requests
    max_batch_interval = "10s"      # Wait longer to fill batches
    timeout = "60s"                 # Allow more time per export
  }
}
```

#### 2. Queue Too Small

**Solution**: Increase queue size:

```hcl
export "traces" {
  otlp = {
    max_queue_size = 8192  # Increase from default (2048)
  }
}
```

**Note**: Larger queues use more memory.

#### 3. Network Latency

**Solution**: Optimize for high-latency networks:

```hcl
export "traces" {
  otlp = {
    max_batch_size = 4096           # Very large batches
    max_batch_interval = "30s"      # Wait longer
    max_concurrent_exports = 2      # Fewer concurrent (less overhead)
    timeout = "2m"                  # Long timeout
  }
}
```

## Debugging Export Issues

### Enable Debug Logging

```hcl
log_level = "debug"
```

Look for detailed export logs:

```bash
kubectl logs -f mermin-xxxxx -n mermin | grep -i "export\|otlp"
```

### Check Internal Tracing

Mermin can export its own telemetry:

```hcl
internal {
  traces = {
    span_fmt = "text_indent"
    stdout = true  # Export internal traces to stdout
  }
}
```

This shows export operations and timings.

### Monitor Export Metrics

Key metrics:

```bash
# Export success rate
mermin_flows_exported_total

# Export errors
mermin_export_errors_total

# Queue depth
mermin_export_queue_size

# Export latency (if available)
mermin_export_duration_seconds
```

## Testing OTLP Connectivity

### Manual OTLP Export Test

Use `grpcurl` to test OTLP endpoint:

```bash
# Install grpcurl in test pod
kubectl run grpcurl --image=fullstorydev/grpcurl --rm -it -- \
  grpcurl -plaintext otel-collector:4317 list

# Expected output shows OTLP services
opentelemetry.proto.collector.trace.v1.TraceService
```

### Verify Collector Configuration

Check OpenTelemetry Collector logs:

```bash
kubectl logs -n observability otel-collector-xxxxx
```

Ensure OTLP receiver is configured:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
```

## Next Steps

* [**Configuration: OTLP Export**](../configuration/export-otlp.md): Detailed export configuration
* [**Configuration: TLS**](../configuration/export-otlp.md#tls-configuration): TLS setup guide
* [**Integrations**](../integrations/integrations.md): Backend-specific integration guides
* [**Performance Issues**](performance.md): If export is causing performance problems
