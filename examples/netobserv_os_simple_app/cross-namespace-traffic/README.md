# Cross-Namespace Traffic Options

This directory contains three deployment options for generating cross-namespace traffic in your Mermin demo. Each option is designed for different demo scenarios and customer personas.

---

## Quick Deploy

Choose one option based on your demo focus:

```bash
# Option 1: Simple load generator (fastest, best for general demos)
kubectl apply -f option1-simple-load-generator.yaml

# Option 2: Database namespace (realistic architecture)
kubectl apply -f option2-database-namespace.yaml

# Option 3: Multi-environment (security/compliance focus)
kubectl apply -f option3-multi-environment.yaml
```

---

## Option Comparison

| Option | Namespaces Created | Best For | Setup Time | Traffic Pattern |
|--------|-------------------|----------|------------|-----------------|
| **1. Simple Load Generator** | `client-app` | Quick demos, basic namespace visibility | < 1 min | client-app → demo-app (HTTP) |
| **2. Database Namespace** | `databases` | Realistic architecture, DB traffic analysis | 2-3 mins | demo-app → databases (PostgreSQL) |
| **3. Multi-Environment** | `production-clients`, `development-clients` | Security, compliance, isolation testing | 2-3 mins | Multiple namespaces → demo-app |

---

## Option 1: Simple Load Generator

**What it does**:
- Creates `client-app` namespace
- Deploys a single pod that continuously calls the OTel Demo frontend
- Generates consistent HTTP traffic across namespaces

**Use when**:
- You need to quickly show cross-namespace traffic
- Demonstrating namespace-based filtering and enrichment
- Time is limited (< 5 minutes for full demo)

**Verification**:
```bash
kubectl logs -n client-app load-generator -f
```

**Expected Output**:
```
[10:23:45] Calling frontend service in demo-app namespace...
[10:23:45] ✓ Response: HTTP 200 - Success
[10:23:45] Sleeping 5 seconds...
```

---

## Option 2: Database in Separate Namespace

**What it does**:
- Creates `databases` namespace with PostgreSQL
- Deploys a client in `demo-app` that queries the database
- Generates PostgreSQL protocol traffic

**Use when**:
- Showing realistic multi-tier architecture
- Demonstrating database traffic patterns (connection pooling, query timing)
- Customer asks "How do we monitor database traffic?"

**Verification**:
```bash
# Check database is running
kubectl get pods -n databases

# Check client queries
kubectl logs -n demo-app db-query-client -f

# Test database connectivity manually
kubectl run -n demo-app test-connection --rm -it --image=postgres:15 -- \
  psql -h postgres.databases.svc.cluster.local -U postgres -c "SELECT 1"
```

**Expected Output from Client**:
```
[10:25:12] Querying database in databases namespace...
[10:25:12] ✓ Query successful - Found 4 databases
[10:25:12] Sleeping 10 seconds...
```

---

## Option 3: Multi-Environment Clients

**What it does**:
- Creates `production-clients` and `development-clients` namespaces
- Deploys separate client deployments in each namespace
- Both call the same `demo-app` service
- Includes example NetworkPolicy (commented out)

**Use when**:
- Security/compliance demo
- Showing namespace isolation and segmentation
- Demonstrating NetworkPolicy enforcement
- Customer asks about multi-tenancy

**Verification**:
```bash
# Check production clients
kubectl get pods -n production-clients
kubectl logs -n production-clients -l app=prod-client --tail=20

# Check development clients
kubectl get pods -n development-clients
kubectl logs -n development-clients -l app=dev-client --tail=20
```

**Expected Output**:
```
# Production
[PROD][10:27:30] Calling demo-app from PRODUCTION namespace...
[PROD][10:27:30] ✓ HTTP 200

# Development
[DEV][10:27:35] Calling demo-app from DEVELOPMENT namespace...
[DEV][10:27:35] ✓ HTTP 200
```

---

## What to Show in OpenSearch Dashboards

After deploying any option, navigate to the **Namespace Traffic Dashboard** in OpenSearch.

### Queries to Try

**Find cross-namespace traffic (Option 1)**:
```
source.k8s.namespace: "client-app" AND destination.k8s.namespace: "demo-app"
```

**Find database traffic (Option 2)**:
```
source.k8s.namespace: "demo-app" AND destination.k8s.namespace: "databases" AND destination.port: 5432
```

**Compare production vs development traffic (Option 3)**:
```
source.k8s.namespace: ("production-clients" OR "development-clients") AND destination.k8s.namespace: "demo-app"
```

**Cross-namespace traffic matrix (any option)**:
```
NOT (source.k8s.namespace: destination.k8s.namespace)
```

---

## Talking Points by Customer Persona

### Platform/SRE Teams
**Use**: Option 1 or 2  
**Focus**: Dependency mapping, service communication patterns  
**Key Message**: "See exactly which services talk to which, across namespace boundaries"

### Security Teams
**Use**: Option 3  
**Focus**: Namespace isolation, NetworkPolicy validation  
**Key Message**: "Validate that prod and dev are truly isolated, detect policy violations in real-time"

### FinOps Teams
**Use**: Option 2 or 3  
**Focus**: Cross-AZ traffic costs, bandwidth optimization  
**Key Message**: "Identify which namespaces generate expensive cross-AZ traffic ($0.01/GB in AWS)"

### Application Teams
**Use**: Option 1  
**Focus**: Request latency, connection troubleshooting  
**Key Message**: "Correlate slow application traces with network-level timing"

---

## Cleanup

Remove all cross-namespace traffic deployments:

```bash
# Remove all namespaces and resources
kubectl delete namespace client-app databases production-clients development-clients

# Or remove specific options
kubectl delete -f option1-simple-load-generator.yaml
kubectl delete -f option2-database-namespace.yaml
kubectl delete -f option3-multi-environment.yaml
```

---

## Troubleshooting

### "No traffic appearing in dashboards"

1. **Check pods are running**:
   ```bash
   kubectl get pods -n client-app
   kubectl get pods -n databases
   kubectl get pods -n production-clients
   kubectl get pods -n development-clients
   ```

2. **Check pod logs for errors**:
   ```bash
   kubectl logs -n client-app load-generator
   ```

3. **Verify frontend service exists**:
   ```bash
   kubectl get svc -n demo-app | grep frontend
   ```

4. **Check Mermin is capturing traffic**:
   ```bash
   kubectl logs -n elastiflow -l app=mermin | grep "packet.observed"
   ```

### "Database connection failing" (Option 2)

1. **Check PostgreSQL is ready**:
   ```bash
   kubectl get pods -n databases
   kubectl logs -n databases -l app=postgres
   ```

2. **Test connection manually**:
   ```bash
   kubectl run -n demo-app test --rm -it --image=postgres:15 -- \
     psql -h postgres.databases.svc.cluster.local -U postgres -c "SELECT 1"
   ```

### "HTTP 000 or connection timeouts"

This usually means the frontend service isn't ready yet:
```bash
# Wait for frontend to be running
kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=frontend -n demo-app --timeout=300s

# Then restart the client
kubectl delete pod load-generator -n client-app
```

---

## Advanced: Enable NetworkPolicy for Option 3

To test actual network isolation in Option 3, uncomment the NetworkPolicy in `option3-multi-environment.yaml`:

1. Edit the file and uncomment lines 82-104
2. Reapply: `kubectl apply -f option3-multi-environment.yaml`
3. The NetworkPolicy will restrict production clients to only access demo-app namespace

This is great for showing:
- How NetworkPolicies work
- Validation that policies are enforced
- What happens when a policy blocks traffic (you won't see flows if it's blocked)

