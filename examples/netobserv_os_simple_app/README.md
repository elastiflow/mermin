# Mermin

Deploy network flow observability for microservices applications using Mermin + OpenTelemetry Demo.

---

## What You'll Build

A complete observability stack capturing:
- **Application traces** from OpenTelemetry Demo microservices
- **Network flows** from Mermin eBPF agent
- **Unified view** in OpenSearch showing both layers

---

## Prerequisites

**Required**:
- Docker installed
- kubectl CLI
- Helm 3.x
- 8GB RAM available

**Tools to install**:
```bash
# kind (Kubernetes in Docker)
brew install kind  # macOS
# or: curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64

# Helm
brew install helm  # macOS
# or: curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```



### Step 1.A: Create Kubernetes Cluster with Calico CNI

#### 1A.1 Create the cluster
```bash
kind create cluster --config examples/netobserv_os_simple_app/kind-config.yaml
```


---

### Step 1.B: Create Kubernetes Cluster with Calico CNI

#### 1B.1 Create the cluster
Navigate to examples/netobserv_os_simple_app/kind-config.yaml and ensure `disableDefaultCNI` is set to true

```bash
kind create cluster --config examples/netobserv_os_simple_app/kind-config.yaml
```

#### 1B.2 - Alternative CNI Install Calico CNI
```bash
echo "Installing Calico..."
kubectl apply -f "https://raw.githubusercontent.com/projectcalico/calico/v3.31.0/manifests/calico.yaml"
kubectl rollout status daemonset calico-node -n kube-system --timeout=240s
```

#### 1B.3 -  Verify cluster
```bash
kubectl get pods -n kube-system -l k8s-app=calico-node
```

**Expected**: 3 nodes ready, Calico pods running.


### Step 2: Deploy NetObserv + OpenSearch Stack

```bash
kubectl create namespace elastiflow
kubectl -n elastiflow create secret docker-registry ghcr \
  --docker-server=ghcr.io \
  --docker-username=elastiflow-ghcr \
  --docker-password=${CLASSIC_GH_TOKEN}
  
helm upgrade -i --wait --timeout 15m -n elastiflow --create-namespace \
    -f examples/netobserv_os_simple_app/values.yaml \
    --set-file mermin.config.content=examples/netobserv_os_simple_app/config.hcl \
    --devel \
    mermin mermin/mermin-netobserv-os-stack
```
#### What's deployed:
- Mermin DaemonSet (eBPF agent on each node)
- NetObserv Flow Collector (OTLP receiver)
- OpenSearch + Dashboards (storage + visualization)

### Step 3: Deploy OpenTelemetry Demo Application

#### 3.1 Add OTel Demo Helm repo
```bash
helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
helm repo update
```

#### 3.2 Deploy the demo app
```bash
helm install otel-demo open-telemetry/opentelemetry-demo \
  --namespace demo-app --create-namespace \
  --set opentelemetry-collector.config.exporters.otlp.endpoint=netobserv-flow.elastiflow.svc:4317 \
  --set opentelemetry-collector.config.exporters.otlp.tls.insecure=true
```

#### 3.3 Wait for a few essential pods to be ready
```bash
kubectl get pods -n demo-app | grep -E "(frontend|productcatalog|cart)"
```

#### 3.4 Access the application
```bash
# Port-forward the frontend
kubectl port-forward -n demo-app svc/frontend-proxy 8081:8080
```

#### What's deployed:
-  OpenTelemetry Demo microservices

#### 3.5 Generate Cross-Namespace Traffic (Optional - Choose One Option)

To demonstrate cross-namespace network flows in your dashboards, deploy one of the following options:

**Choose based on your demo focus**:
- **Option 1**: Quick demo, focus on namespace visibility
- **Option 2**: Realistic architecture, focus on database traffic
- **Option 3**: Security/compliance demo, focus on isolation

##### Option 1: Simple Load Generator (Recommended for Quick Demos)

Deploy a continuous client that calls the frontend service:

```bash
kubectl apply -f examples/netobserv_os_simple_app/cross-namespace-traffic/option1-simple-load-generator.yaml

# Verify it's running
kubectl logs -n client-app load-generator -f
```

**What you'll see**: `client-app` → `demo-app` traffic in namespace dashboards

##### Option 2: Database in Separate Namespace (Realistic Architecture)

Deploy PostgreSQL in isolated `databases` namespace:

```bash
kubectl apply -f examples/netobserv_os_simple_app/cross-namespace-traffic/option2-database-namespace.yaml

# Verify database is accessible (wait ~1 minute for database to be ready)
kubectl logs -n demo-app db-query-client -f
```

**What you'll see**: `demo-app` → `databases` traffic with PostgreSQL protocol details

##### Option 3: Multi-Environment (Security/Compliance Demo)

Deploy production and development client namespaces:

```bash
kubectl apply -f examples/netobserv_os_simple_app/cross-namespace-traffic/option3-multi-environment.yaml

# Verify both environments
kubectl get pods -n production-clients
kubectl get pods -n development-clients
```

**What you'll see**: Multiple namespace → `demo-app` traffic, perfect for showing network segmentation

---

### Step 4: Generate Traffic and View Results

**Open browser**: `http://localhost:8081`

**Action**: Browse products, add to cart, complete checkout.

---

### 5 Access OpenSearch Dashboards

#### 5.1 Access the application

```bash
kubectl port-forward -n elastiflow svc/elastiflow-os-dashboards 5601:5601
```

**Open browser**: `http://localhost:5601`
- Username: `admin`
- Password: `Elast1flow!`

#### 5.2 Upload Dashboard
- Go to **Stack Management** → **Saved Objects** -> **Import** 
- Upload: `examples/netobserv_os_simple_app/opensearch_dashboards_objects.json`
- Select all objects and click **Import** Overwrite if prompted.

#### 5.3 View the data
- Go to **Svc/Pod** [Dashboard](http://localhost:5601/app/dashboards#/view/7e43a4f0-b867-11f0-bf0d-63ed40f73764)
- Go to **Pop/Pod** [Dashboard](http://localhost:5601/app/dashboards#/view/7e43a4f0-b867-11f0-bf0d-63ed40f73764)
- Go to **Namespace Traffic** [Dashboard](http://localhost:5601/app/dashboards#/view/7e43a4f0-b867-11f0-bf0d-63ed40f73764)

**Look for cross-namespace traffic** (if you deployed step 3.5):
- **Option 1**: `client-app` → `demo-app` flows
- **Option 2**: `demo-app` → `databases` PostgreSQL traffic
- **Option 3**: `production-clients` → `demo-app` and `development-clients` → `demo-app`

**Try these queries in Discover** (Go to Discover → select `elastiflow-*` index):

Find all cross-namespace traffic from client-app:
```
source.k8s.namespace: "client-app" AND destination.k8s.namespace: "demo-app"
```

Find database traffic from app namespace:
```
source.k8s.namespace: "demo-app" AND destination.k8s.namespace: "databases" AND destination.port: 5432
```

Find all cross-namespace flows (any namespace):
```
NOT (source.k8s.namespace: destination.k8s.namespace)
```

---


### What You've Built

```
┌──────────────────────┐
│  OTel Demo App       │ → Application OTLP Traces
│  (11 microservices)  │
└──────────────────────┘
         ↓
┌──────────────────────┐
│  Mermin (eBPF)       │ → Network Flow OTLP Traces
│  (DaemonSet)         │
└──────────────────────┘
         ↓
┌──────────────────────┐
│  NetObserv Collector │ → Combines both trace types
│  (OTLP receiver)     │
└──────────────────────┘
         ↓
┌──────────────────────┐
│  OpenSearch          │ → Unified storage & analysis
│  + Dashboards        │
└──────────────────────┘
```

---

## Key Observations

**Network flows show what application traces can't**:
1. **DNS resolution**: Kubernetes service discovery timing
2. **TCP behavior**: SYN/ACK timing, retransmissions
3. **Inter-node routing**: Virtual Ethernet (KindNet)
4. **Intra-node routing**: Direct pod-to-pod via cali interfaces
5. **Protocol-level**: HTTP vs gRPC vs Redis protocol traffic
6. **Network issues**: Latency, packet loss, connection failures

---

## Demo Scenarios by Use Case

Use these scenarios to tailor your demo to different customer personas:

### Scenario 1: Platform/SRE - "I need visibility into microservice dependencies"

**Deploy**: Option 1 or 2  
**Show**: Namespace traffic dashboard  

**Talking Points**:
- "This is traffic between your client app and your microservices platform"
- "Mermin automatically enriches flows with namespace, pod, and service metadata"
- "You can see which teams/services are calling which - critical for change management"
- "When you migrate or scale services, you know exactly what will be impacted"

**Customer Value**: Reduce MTTR from hours to minutes, better change management

---

### Scenario 2: Security - "I need to prove namespace isolation"

**Deploy**: Option 3  
**Show**: Cross-namespace traffic matrix  

**Talking Points**:
- "Here we see production and development environments as separate namespaces"
- "Both are calling the demo-app, but they're isolated from each other"
- "If you see unexpected cross-namespace traffic, that's a security finding"
- "You can validate NetworkPolicy enforcement in real-time"
- "Perfect for compliance audits - show auditors exactly what traffic is allowed"

**Customer Value**: Pass security audits faster, detect violations immediately, prove compliance

---

### Scenario 3: FinOps - "What's driving our cross-AZ network costs?"

**Deploy**: Option 2 or 3  
**Show**: Namespace bandwidth dashboard with node information  

**Talking Points**:
- "This database is in a separate namespace, potentially a separate availability zone"
- "Every GB of cross-AZ traffic costs $0.01-0.02 in AWS/GCP"
- "Mermin shows you which namespaces are generating expensive traffic"
- "You can right-size deployments or use read replicas to reduce costs"
- "We've seen customers reduce network costs by 20-40% using this visibility"

**Customer Value**: Reduce cloud network costs by 20-40%, better capacity planning

---

### Scenario 4: Application Team - "My requests are slow, is it the network?"

**Deploy**: Option 1  
**Show**: Flow details with latency metrics, correlated with application traces  

**Talking Points**:
- "Your application traces show slow requests, but don't tell you WHY"
- "Network flows show the actual TCP connection time to the frontend"
- "Here we can see if it's DNS resolution (5ms), connection setup (50ms), or data transfer"
- "You can distinguish between application code issues vs network issues"
- "No more guessing - you have the data to make informed decisions"

**Customer Value**: Faster troubleshooting, improved user experience, reduced escalations

---

## Cleanup

```bash
# Delete everything (includes all namespaces)
kind delete cluster --name mermin-demo

# Or selective cleanup
helm uninstall mermin elastiflow-os, elastiflow-os-dashboards -n elastiflow
helm uninstall otel-demo -n demo-app

# Cleanup cross-namespace traffic deployments (if you deployed step 3.5)
kubectl delete namespace client-app databases production-clients development-clients
```
