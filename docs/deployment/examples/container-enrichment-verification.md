# Container Enrichment Verification Guide

This guide provides step-by-step instructions to verify that container name and image name enrichment is working correctly in a local Kubernetes environment.

## Prerequisites

- Docker installed
- kind (Kubernetes in Docker) installed
- kubectl installed
- Docker image build capability

## Step 1: Create Local Kind Cluster

```bash
kind create cluster --name mermin-test
```

## Step 2: Build Mermin Image

From the project root:

```bash
docker build -t mermin:test .
```

## Step 3: Load Image into Kind Cluster

```bash
kind load docker-image mermin:test --name mermin-test
```

## Step 4: Create Test Configuration

Create a file `test-config.hcl` with stdout trace export:

```hcl
export {
  otlp {
    traces {
      type = "stdout"
    }
  }
}

discovery {
  informer {
    k8s {
      enabled = true
    }
  }
}

attributes {
  source {
    k8s {
      extract {
        metadata = [
          "[*].metadata.name",
          "[*].metadata.namespace",
          "[*].metadata.uid",
        ]
      }
    }
  }
  destination {
    k8s {
      extract {
        metadata = [
          "[*].metadata.name",
          "[*].metadata.namespace",
          "[*].metadata.uid",
        ]
      }
    }
  }
}
```

## Step 5: Deploy Test Pods

Create a test deployment with known container configurations:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: test-containers
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  namespace: test-containers
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx-web
        image: nginx:1.21
        ports:
        - containerPort: 80
          name: http
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: multi-container-app
  namespace: test-containers
spec:
  replicas: 1
  selector:
    matchLabels:
      app: multi
  template:
    metadata:
      labels:
        app: multi
    spec:
      containers:
      - name: frontend
        image: nginx:alpine
        ports:
        - containerPort: 8080
      - name: sidecar
        image: envoy:v1.20
        ports:
        - containerPort: 9090
      - name: metrics
        image: prom/prometheus:v2.30.0
        ports:
        - containerPort: 3000
---
apiVersion: v1
kind: Service
metadata:
  name: nginx-service
  namespace: test-containers
spec:
  selector:
    app: nginx
  ports:
  - port: 80
    targetPort: 80
```

Apply the configuration:

```bash
kubectl apply -f test-pods.yaml
```

## Step 6: Deploy Mermin

Create a DaemonSet to deploy Mermin:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: mermin
  namespace: test-containers
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: mermin
rules:
- apiGroups: [""]
  resources: ["pods", "nodes", "services", "namespaces"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets", "statefulsets", "daemonsets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["batch"]
  resources: ["jobs", "cronjobs"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies", "ingresses"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["discovery.k8s.io"]
  resources: ["endpointslices"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: mermin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: mermin
subjects:
- kind: ServiceAccount
  name: mermin
  namespace: test-containers
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: mermin
  namespace: test-containers
spec:
  selector:
    matchLabels:
      app: mermin
  template:
    metadata:
      labels:
        app: mermin
    spec:
      serviceAccountName: mermin
      hostNetwork: true
      containers:
      - name: mermin
        image: mermin:test
        imagePullPolicy: Never
        securityContext:
          privileged: true
        volumeMounts:
        - name: config
          mountPath: /etc/mermin
      volumes:
      - name: config
        configMap:
          name: mermin-config
```

## Step 7: Generate Test Traffic

```bash
# Get a shell in the nginx pod
kubectl exec -it -n test-containers deployment/nginx-deployment -- /bin/bash

# Generate some traffic
curl http://nginx-service

# Exit the pod
exit
```

## Step 8: Monitor Mermin Logs

```bash
kubectl logs -n test-containers -l app=mermin --tail=100 -f
```

## Step 9: Verify Container Attributes

Look for log entries containing flow spans. You should see attributes like:

```json
{
  "source.container.name": "nginx-web",
  "source.container.image.name": "nginx:1.21",
  "destination.container.name": "frontend",
  "destination.container.image.name": "nginx:alpine"
}
```

## Expected Results

For traffic between pods, you should see:

1. **Single container pods**: Container name and image populated based on the single container
2. **Multi-container pods**: Container name and image populated based on port matching
   - Traffic to port 8080 → `frontend` container with `nginx:alpine` image
   - Traffic to port 9090 → `sidecar` container with `envoy:v1.20` image
   - Traffic to port 3000 → `metrics` container with `prom/prometheus:v2.30.0` image

## Cleanup

```bash
kubectl delete namespace test-containers
kind delete cluster --name mermin-test
```

## Troubleshooting

### Container attributes not appearing

1. Check that the pods have containerPort specifications
2. Verify the flow is using the correct port
3. Check mermin logs for any errors during container resolution

### Mermin not starting

1. Verify the image was loaded: `docker exec -it mermin-test-control-plane crictl images | grep mermin`
2. Check pod status: `kubectl get pods -n test-containers`
3. Check pod logs: `kubectl logs -n test-containers -l app=mermin`

### No traffic visible

1. Ensure mermin has proper RBAC permissions
2. Verify hostNetwork is enabled
3. Check that eBPF programs are loaded: `kubectl exec -n test-containers -it <mermin-pod> -- bpftool prog list`
