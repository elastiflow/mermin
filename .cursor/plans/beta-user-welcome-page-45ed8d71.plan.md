<!-- 45ed8d71-40a4-4954-aa35-0f4070874c52 6e644ad2-54ea-4d50-ab1d-29f2c9374094 -->
# Mermin Training Agenda - Internal Session

## Support Engineers & Solutions Architects

**Duration**: 90 minutes

**Audience**: Support Team & Solutions Architects

**Goal**: Deep configuration understanding + use case positioning for customer conversations

---

## Pre-Session Setup (Attendees - 15 mins before)

**Required**:

- [ ] Clone repo: `git clone https://github.com/elastiflow/mermin.git`
- [ ] Docker Desktop running
- [ ] kubectl + Helm installed
- [ ] GitHub token ready: `export CLASSIC_GH_TOKEN=<your-token>`

**Nice to have**:

- OpenSearch Dashboards experience
- Basic Kubernetes knowledge
- Familiarity with OTLP/OpenTelemetry

---

## Session Outline

### **Part 1: Introduction & Problem Statement** (10 minutes)

#### 1.1 What is Mermin? (3 mins)

**Talking Points**:

- eBPF-based network observability for Kubernetes
- Captures network flows as OpenTelemetry traces
- Enriches flows with Kubernetes metadata (pod, service, namespace, labels)
- Complements application traces with network-level visibility

**Positioning for Sales**:

> "Customers already using OpenTelemetry for application traces can add network visibility without changing a single line of code. Same format, same backend, complete observability."

#### 1.2 Customer Pain Points Mermin Solves (4 mins)

**Real-World Scenarios**:

1. **"My app is slow, but I don't know if it's code or network"**

   - App traces show 500ms request
   - Network flows reveal 450ms was TCP retransmissions to database
   - **Value**: Root cause in minutes, not hours

2. **"I need to prove compliance - which namespaces talk to which?"**

   - Security audit requires proof of network isolation
   - Mermin dashboard shows cross-namespace traffic matrix
   - **Value**: Compliance reporting + violation detection

3. **"Our cloud bill is too high - what's generating inter-AZ traffic?"**

   - AWS charges $0.01/GB for cross-AZ
   - Mermin identifies which services/namespaces are expensive
   - **Value**: FinOps - reduce costs by fixing chatty services

4. **"We deployed a service mesh but don't know if it's working"**

   - mTLS enabled, but is traffic actually encrypted?
   - Network policies deployed, are they enforced?
   - **Value**: Validate infrastructure investments

#### 1.3 Live Demo Goals (3 mins)

**What We'll Build Today**:

- Deploy Mermin on local kind cluster
- Deploy OpenTelemetry Demo app (11 microservices)
- View network flows enriched with K8s metadata
- Explore the configuration file to understand how it works

**Expected Outcome**:

- You can run this demo for customers
- You understand which config knobs to turn for different use cases
- You know how to troubleshoot common issues

---

### **Part 2: Hands-On Deployment** (25 minutes)

#### 2.1 Cluster Setup (5 mins)

**Walk through**:

```bash
# Create kind cluster with Calico CNI
kind create cluster --config examples/netobserv_os_simple_app/kind-config.yaml

# Install Calico
kubectl apply -f "https://raw.githubusercontent.com/projectcalico/calico/v3.31.0/manifests/calico.yaml"
kubectl rollout status daemonset calico-node -n kube-system --timeout=240s
```

**Key Teaching Point**:

- **Why Calico?** We need a CNI that creates identifiable interfaces (`cali*`) for pod traffic
- **Why kind?** Reproducible, customer-friendly demo environment
- **Alternative CNIs**: Flannel (`cni*`), Cilium (`cilium_*`), GKE (`gke*`)

#### 2.2 Deploy Mermin + Stack (10 mins)

**Walk through**:

```bash
# Create namespace and image pull secret
kubectl create namespace elastiflow
kubectl -n elastiflow create secret docker-registry ghcr \
  --docker-server=ghcr.io \
  --docker-username=elastiflow-ghcr \
  --docker-password=${CLASSIC_GH_TOKEN}

# Deploy full stack (Mermin + NetObserv + OpenSearch)
helm upgrade -i --wait --timeout 15m -n elastiflow --create-namespace \
    -f examples/netobserv_os_simple_app/values.yaml \
    --set-file mermin.config.content=examples/netobserv_os_simple_app/config.hcl \
    --devel \
    mermin mermin/mermin-netobserv-os-stack
```

**Key Teaching Points**:

- **What's deployed**:
  - Mermin DaemonSet (eBPF agent on each node)
  - NetObserv Flow Collector (OTLP receiver)
  - OpenSearch + Dashboards (storage + visualization)
- **Why `--wait`?** Ensures everything is ready before proceeding
- **Image pull secret**: Required for beta access (customer onboarding step)

**While waiting** (5 mins): Open `config.hcl` in IDE, preview key sections

#### 2.3 Deploy Demo Application (10 mins)

**Walk through**:

```bash
# Add OTel Demo Helm repo
helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
helm repo update

# Deploy OpenTelemetry Demo (11 microservices)
helm install otel-demo open-telemetry/opentelemetry-demo \
  --namespace demo-app --create-namespace \
  --set opentelemetry-collector.config.exporters.otlp.endpoint=netobserv-flow.elastiflow.svc:4317 \
  --set opentelemetry-collector.config.exporters.otlp.tls.insecure=true

# Check pods (may take 5-10 minutes)
kubectl get pods -n demo-app | grep -E "(frontend|productcatalog|cart)"

# Port-forward frontend
kubectl port-forward -n demo-app svc/frontend-proxy 8081:8080
```

**Key Teaching Points**:

- **Why OTel Demo?** Production-quality microservices app, already OTLP-instrumented
- **OTLP endpoint config**: Pointing app traces to same collector as network flows
- **Real customer scenario**: "You're already sending app traces, now add network flows"

**Activity**: Everyone browse `http://localhost:8081`, add items to cart, checkout

---

### **Part 3: Configuration Deep Dive** (25 minutes)

#### 3.1 Open config.hcl - Top to Bottom Walkthrough

**Open file**: `examples/netobserv_os_simple_app/config.hcl`

---

**Section 1: Basic Settings** (2 mins)

```hcl
log_level = "info"
auto_reload = false
shutdown_timeout = "5s"
packet_channel_capacity = 1024
packet_worker_count = 2
```

**Customer Questions**:

- Q: "What if I need debug logs for troubleshooting?"
  - A: Change `log_level = "debug"`, restart pods
- Q: "My cluster is high-traffic, should I increase workers?"
  - A: Yes, set `packet_worker_count = 4` or `8` based on CPU cores

---

**Section 2: API & Metrics** (2 mins)

```hcl
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
```

**Key Points**:

- `/health` endpoint on port 8080 (Kubernetes liveness probe)
- Prometheus metrics on port 10250 (for monitoring Mermin itself)

**Demo**: `kubectl port-forward -n elastiflow <mermin-pod> 10250:10250`

Visit: `http://localhost:10250/metrics`

**Customer Use Case**: "Integrate Mermin health into your existing Prometheus/Grafana"

---

**Section 3: Network Interface Discovery** (5 mins - **CRITICAL**)

```hcl
discovery "instrument" {
  interfaces = ["*"]
}
```

**This is THE most important config for correct deployment.**

**Explain**:

- eBPF programs attach to network interfaces to capture packets
- Wrong interfaces = missing traffic

**Customer Scenarios**:

| Customer Need | Configuration | What They'll See |

|---|---|---|

| **Pod-to-pod traffic (recommended)** | `interfaces = ["cali*", "tunl*"]` (Calico) | All pod traffic, intra + inter-node |

| **Physical network only** | `interfaces = ["eth*", "ens*"]` | Inter-node traffic, node-level view |

| **Everything (may duplicate)** | `interfaces = ["*"]` | All traffic, but may see duplicates |

**Common Customer Mistake**:

- Setting `interfaces = ["eth0"]` and wondering why they don't see pod-to-pod traffic
- **Solution**: Add CNI-specific patterns

**Activity**: Modify config to `interfaces = ["cali*"]`, explain what changes

---

**Section 4: Kubernetes Informer Discovery** (4 mins)

```hcl
discovery "informer" "k8s" {
  selectors = [
    { kind = "Pod" },
    { kind = "Service" },
    { kind = "Deployment" },
    # ...
  ]
}
```

**Explain**:

- Mermin watches K8s API for these resources
- Builds in-memory cache of objects
- Enriches network flows with metadata from this cache

**Customer Questions**:

- Q: "Will this overload my K8s API server?"
  - A: No, uses efficient watch mechanism, configurable resync period (30m default)
- Q: "I only care about production namespace, can I filter?"
  - A: Yes! `{ kind = "Pod", namespaces = ["production"] }`

**Performance Tip**:

- Large clusters (1000+ pods): Filter by namespace to reduce memory
- Smaller clusters: Watch all namespaces for complete visibility

---

**Section 5: Owner Relations** (3 mins)

```hcl
owner_relations = {
  max_depth = 5
  include_kinds = ["Service"]
  exclude_kinds = ["EndpointSlice"]
}
```

**Explain**:

- Walks K8s owner references: Pod → ReplicaSet → Deployment → ...
- Attaches parent metadata to flows

**Example Flow**:

- Flow from pod `cart-abc123-xyz`
- Owner walk finds: ReplicaSet `cart-abc123` → Deployment `cart`
- Flow gets enriched with: `k8s.deployment.name = "cart"`

**Customer Value**:

- "Show me all traffic from my 'checkout' Deployment" (not just individual pods)

---

**Section 6: Selector Relations** (3 mins)

```hcl
selector_relations = [
  {
    kind = "NetworkPolicy"
    to = "Pod"
    selector_match_labels_field = "spec.podSelector.matchLabels"
  },
  {
    kind = "Service"
    to = "Pod"
    selector_match_labels_field = "spec.selector"
  }
]
```

**Explain**:

- Reverse lookup: Find which NetworkPolicy applies to a pod
- Service → Pod mapping: Which pods are behind a Service?

**Customer Use Case**:

- "Show me all traffic that's allowed/denied by NetworkPolicy X"
- "Which pods are serving traffic for Service Y?"

---

**Section 7: Attributes (Flow Enrichment)** (4 mins)

```hcl
attributes "source" "k8s" {
  extract {
    metadata = [
      "[*].metadata.name",
      "[*].metadata.namespace",
    ]
  }
  
  association {
    pod = {
      sources = [
        { from = "flow", name = "source.ip", to = ["status.podIP"] }
      ]
    }
  }
}
```

**Explain**:

- **Extract**: Which K8s metadata fields to pull
- **Association**: How to map flow IPs/ports to K8s resources

**Flow Example**:

```
Flow: 10.244.1.5:45678 → 10.244.2.10:6379
```

**Mermin looks up**:

- `10.244.1.5` matches Pod `frontend-abc` → Extract pod name, namespace, labels
- `10.244.2.10` matches Service `redis` → Extract service name

**Enriched Flow**:

```
source.k8s.pod.name = "frontend-abc"
source.k8s.namespace = "demo-app"
destination.k8s.service.name = "redis"
destination.k8s.namespace = "demo-app"
```

**Customer Value**: "I can query by pod name, not just IP addresses"

---

**Section 8: Filtering** (2 mins)

```hcl
filter "destination" {
  port = {
    not_match = "9090,10250" # Exclude Prometheus scraping
  }
}
```

**Common Filters**:

- Exclude health checks: `not_match = "/health"`
- Only production namespace: `match = "production"`
- Exclude internal traffic: `not_match = "10.0.0.0/8"`

**Customer Question**: "I'm overwhelmed by noise, what should I filter?"

- **Answer**: Start with excluding metrics endpoints, health checks, DNS

---

### **Part 4: View Results & Use Cases** (15 minutes)

#### 4.1 Access OpenSearch Dashboards (3 mins)

```bash
kubectl port-forward -n elastiflow svc/opensearch-dashboards 5601:5601
```

Visit: `http://localhost:5601`

- Username: `admin`
- Password: `Elast1flow!`

**Import Dashboard**:

- Stack Management → Saved Objects → Import
- Upload: `examples/netobserv_os_simple_app/opensearch_dashboards_objects.json`

#### 4.2 Explore Pre-Built Dashboard (7 mins)

Navigate to: **Svc/Pod Dashboard**

**Walk Through Visualizations**:

1. **Top Pods by Bytes Transferred**

   - Shows: Which pods are network-heavy
   - **Customer Value**: Capacity planning, identify noisy neighbors

2. **Cross-Namespace Traffic Matrix**

   - Shows: `demo-app` → `elastiflow` (Mermin telemetry itself)
   - **Customer Value**: Security audit, compliance reporting

3. **Service-to-Service Communication**

   - Shows: `frontend` → `cartservice` → `redis`
   - **Customer Value**: Dependency mapping for migrations

4. **TCP Connection States**

   - Shows: ESTABLISHED, SYN_SENT, CLOSE_WAIT counts
   - **Customer Value**: Detect connection pool exhaustion

5. **Protocol Distribution**

   - Shows: HTTP, gRPC, Redis protocol breakdown
   - **Customer Value**: Understand application communication patterns

#### 4.3 Live Query Examples (5 mins)

**Go to Discover → elastiflow-*** index

**Query 1: Find all Redis traffic**

```
destination.k8s.service.name: "redis" AND destination.port: 6379
```

**Query 2: Find cross-node traffic (expensive in cloud)**

```
source.k8s.node.name: "kind-worker" AND destination.k8s.node.name: "kind-worker2"
```

**Query 3: Find traffic with TCP resets (errors)**

```
flow.tcp_flags: "*RST*"
```

**Activity**: Ask attendees to create a query for "All traffic from frontend pod"

---

### **Part 5: Customer Scenarios & Objection Handling** (10 minutes)

#### 5.1 Common Customer Objections

**Objection 1**: "We already have Cilium Hubble / Datadog NPM"

**Response**:

- Hubble: Cilium-specific, requires Cilium CNI. Mermin works with any CNI.
- Datadog NPM: Proprietary, expensive. Mermin exports open standard (OTLP), use any backend.
- **Positioning**: "Mermin gives you choice and avoids vendor lock-in"

**Objection 2**: "eBPF sounds complicated and risky"

**Response**:

- eBPF is production-proven (Cilium, Falco, Pixie all use eBPF)
- Read-only observation, doesn't modify packets
- Kernel verifier prevents crashes
- **Positioning**: "eBPF is the industry standard for observability. It's safer than traditional methods."

**Objection 3**: "We don't have time to deploy another tool"

**Response**:

- 3 commands to deploy (show them the README)
- Works with existing OpenSearch/Grafana/Jaeger
- No application changes required
- **Positioning**: "Less than 30 minutes from zero to insights"

**Objection 4**: "What's the performance impact?"

**Response**:

- eBPF is kernel-level, minimal overhead (< 5% CPU)
- Sampling available if needed
- Runs as DaemonSet, scales horizontally
- **Positioning**: "You're already paying for the network, we just make it visible"

#### 5.2 Sales Use Cases by Persona

**Platform/SRE Teams**:

- **Pain**: "We're blind to network issues between services"
- **Mermin Solution**: Network-level visibility without code changes
- **ROI**: Reduce MTTR from hours to minutes

**Security Teams**:

- **Pain**: "Can't prove compliance with network isolation policies"
- **Mermin Solution**: Real-time network policy enforcement validation
- **ROI**: Pass audits faster, detect violations immediately

**FinOps Teams**:

- **Pain**: "Cloud network costs are out of control"
- **Mermin Solution**: Identify which services/namespaces generate cross-AZ traffic
- **ROI**: Reduce cloud network costs by 20-40%

**Application Teams**:

- **Pain**: "Slow requests but don't know if it's app or network"
- **Mermin Solution**: Correlate app traces with network flows
- **ROI**: Faster troubleshooting, better user experience

---

### **Part 6: Troubleshooting Common Issues** (5 minutes)

#### Issue 1: "No flows captured"

**Symptoms**: Dashboard is empty

**Root Cause**: Wrong interface configuration or `hostNetwork: false`

**Solution**:

```bash
# Check Mermin logs for eBPF attachment
kubectl logs -n elastiflow -l app=mermin | grep "ebpf.program_attached"

# Verify hostNetwork is true
kubectl get daemonset mermin -n elastiflow -o yaml | grep hostNetwork

# Fix: Update values.yaml
hostNetwork: true
```

#### Issue 2: "Only see some pod traffic"

**Symptoms**: Missing intra-node pod-to-pod flows

**Root Cause**: Not monitoring CNI bridge interfaces

**Solution**:

```hcl
# Change from physical interfaces to CNI interfaces
interfaces = ["cali*", "tunl*"]  # For Calico
```

#### Issue 3: "Mermin pods crash"

**Symptoms**: DaemonSet pods in CrashLoopBackOff

**Root Cause**: Usually kernel version or BTF issues

**Solution**:

```bash
# Check kernel version (need 5.4+)
kubectl debug node/<node> -it --image=ubuntu -- uname -r

# Check Mermin logs for BTF errors
kubectl logs -n elastiflow <mermin-pod> | grep -i btf
```

**Customer Reassurance**: "These are rare, mostly in very old clusters. We have runbooks for all of them."

---

## Post-Session Resources

**For Attendees**:

- [ ] Bookmark: Mermin docs site
- [ ] Save: `examples/netobserv_os_simple_app/` folder for customer demos
- [ ] Join: Internal Slack #mermin-support channel
- [ ] Review: Customer success stories (link to case studies)

**Follow-Up Tasks**:

- [ ] Run through demo once more on your own
- [ ] Try modifying config for different CNIs (Flannel, Cilium)
- [ ] Create 1 custom dashboard visualization
- [ ] Shadow a customer call where Mermin is discussed

---

## Q&A (Remaining Time)

**Likely Questions to Prepare For**:

1. "How does Mermin compare to Pixie?"
2. "Can we use this with AWS EKS?"
3. "Does it work with Istio service mesh?"
4. "What's the data retention strategy?"
5. "Can we export to Grafana instead of OpenSearch?"

---

## Success Metrics

**You're ready to support customers when you can**:

- [ ] Deploy Mermin in < 15 minutes
- [ ] Explain interface discovery to a customer
- [ ] Customize config for a customer's CNI
- [ ] Create a basic dashboard
- [ ] Troubleshoot "no flows" issue
- [ ] Position Mermin's value for 3 different personas

---

## Appendix: Quick Reference Commands

```bash
# Deploy
helm upgrade -i -n elastiflow --create-namespace \
  -f values.yaml \
  --set-file mermin.config.content=config.hcl \
  mermin mermin/mermin-netobserv-os-stack

# Check health
kubectl get pods -n elastiflow
kubectl logs -n elastiflow -l app=mermin --tail=50

# Access dashboards
kubectl port-forward -n elastiflow svc/opensearch-dashboards 5601:5601

# Update config
kubectl edit cm -n elastiflow mermin-config
kubectl rollout restart daemonset mermin -n elastiflow

# Metrics
kubectl port-forward -n elastiflow <mermin-pod> 10250:10250
curl http://localhost:10250/metrics

# Troubleshooting
stern mermin -n elastiflow | grep -i error
kubectl describe pod -n elastiflow <mermin-pod>
```

### To-dos

- [ ] Analyze CNCF graduated project troubleshooting patterns
- [ ] Create quick reference section with decision tree and diagnostic commands
- [ ] Restructure High CPU section with severity, symptoms, diagnosis, solutions
- [ ] Restructure High Memory section with consistent format
- [ ] Restructure Packet/Flow Drops section with triage workflow
- [ ] Add prevention best practices and capacity planning sections
- [ ] Add real-world troubleshooting scenarios section