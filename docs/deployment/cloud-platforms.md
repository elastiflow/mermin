# Cloud Platforms

This guide provides specific instructions for deploying Mermin on major cloud Kubernetes platforms: Google Kubernetes Engine (GKE), Amazon Elastic Kubernetes Service (EKS), and Azure Kubernetes Service (AKS).

## Google Kubernetes Engine (GKE)

### Prerequisites

* `gcloud` CLI installed and configured
* GKE cluster created (Standard or Autopilot)
* `kubectl` configured for your GKE cluster

### GKE Standard Clusters

GKE Standard clusters work seamlessly with Mermin using the standard Helm deployment.

**Create a GKE Standard cluster:**

```bash
gcloud container clusters create mermin-cluster \
  --zone us-central1-a \
  --num-nodes 3 \
  --machine-type n1-standard-2 \
  --enable-ip-alias \
  --network "default" \
  --subnetwork "default"

# Configure kubectl
gcloud container clusters get-credentials mermin-cluster --zone us-central1-a
```

**Deploy Mermin:**

```bash
helm install mermin ./charts/mermin \
  --set-file config.content=mermin-config.hcl \
  --wait
```

### GKE Autopilot Clusters

GKE Autopilot has stricter security policies. Mermin requires some adjustments:

{% hint style="warning" %}
GKE Autopilot does not allow privileged containers by default. You must enable the `CAP_BPF` capability and use Autopilot-compatible security context.
{% endhint %}

**Create a GKE Autopilot cluster:**

```bash
gcloud container clusters create-auto mermin-autopilot \
  --region us-central1

gcloud container clusters get-credentials mermin-autopilot --region us-central1
```

**Deploy with Autopilot-compatible values:**

```yaml
# values-gke-autopilot.yaml
securityContext:
  privileged: false
  capabilities:
    add:
      - BPF
      - NET_ADMIN
      - SYS_ADMIN
  allowPrivilegeEscalation: true

resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: 1
    memory: 1Gi
```

```bash
helm install mermin ./charts/mermin \
  -f values-gke-autopilot.yaml \
  --set-file config.content=mermin-config.hcl \
  --wait
```

### GKE-Specific Configuration

**Network interfaces** on GKE nodes typically include:

```hcl
discovery "instrument" {
  # GKE uses "gke*" for pod network interfaces
  interfaces = ["eth*", "gke*"]
}
```

**Workload Identity** (optional, for managed identity):

```yaml
serviceAccount:
  annotations:
    iam.gke.io/gcp-service-account: mermin-sa@PROJECT_ID.iam.gserviceaccount.com
```

Set up Workload Identity:

```bash
# Create GCP service account
gcloud iam service-accounts create mermin-sa

# Bind Kubernetes service account to GCP service account
gcloud iam service-accounts add-iam-policy-binding \
  mermin-sa@PROJECT_ID.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:PROJECT_ID.svc.id.goog[default/mermin]"
```

## Amazon Elastic Kubernetes Service (EKS)

### Prerequisites

* `aws` CLI installed and configured
* `eksctl` installed (optional but recommended)
* EKS cluster created
* `kubectl` configured for your EKS cluster

### Creating an EKS Cluster

```bash
# Using eksctl (recommended)
eksctl create cluster \
  --name mermin-cluster \
  --region us-west-2 \
  --nodegroup-name standard-workers \
  --node-type t3.medium \
  --nodes 3 \
  --nodes-min 2 \
  --nodes-max 4 \
  --managed

# Update kubeconfig
aws eks update-kubeconfig --name mermin-cluster --region us-west-2
```

### Deploying Mermin on EKS

Standard Helm deployment works on EKS:

```bash
helm install mermin ./charts/mermin \
  --set-file config.content=mermin-config.hcl \
  --wait
```

### EKS-Specific Configuration

**Network interfaces** on EKS nodes (Amazon Linux 2):

```hcl
discovery "instrument" {
  # EKS uses "eth*" for network interfaces
  interfaces = ["eth*"]
}
```

For nodes using the VPC CNI plugin with secondary ENIs:

```hcl
discovery "instrument" {
  # Capture both primary and secondary ENIs
  interfaces = ["eth*", "eni*"]
}
```

**IAM Roles for Service Accounts (IRSA):**

```yaml
# values-eks.yaml
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT_ID:role/mermin-role
```

Set up IRSA:

```bash
# Create IAM OIDC provider for your cluster
eksctl utils associate-iam-oidc-provider \
  --cluster mermin-cluster \
  --approve

# Create IAM role with trust policy
eksctl create iamserviceaccount \
  --name mermin \
  --namespace default \
  --cluster mermin-cluster \
  --attach-policy-arn arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess \
  --approve
```

## Azure Kubernetes Service (AKS)

### Prerequisites

* `az` CLI installed and configured
* AKS cluster created
* `kubectl` configured for your AKS cluster

### Creating an AKS Cluster

```bash
# Create resource group
az group create --name mermin-rg --location eastus

# Create AKS cluster
az aks create \
  --resource-group mermin-rg \
  --name mermin-cluster \
  --node-count 3 \
  --node-vm-size Standard_DS2_v2 \
  --enable-managed-identity \
  --generate-ssh-keys

# Get credentials
az aks get-credentials --resource-group mermin-rg --name mermin-cluster
```

### Deploying Mermin on AKS

Standard Helm deployment works on AKS:

```bash
helm install mermin ./charts/mermin \
  --set-file config.content=mermin-config.hcl \
  --wait
```

### AKS-Specific Configuration

**Network interfaces** on AKS nodes:

```hcl
discovery "instrument" {
  # AKS uses "eth*" for network interfaces
  interfaces = ["eth*"]
}
```

For nodes using Azure CNI:

```hcl
discovery "instrument" {
  # Azure CNI creates interfaces per pod
  interfaces = ["eth*", "azure*"]
}
```

**Azure AD Pod Identity** (optional):

```yaml
# values-aks.yaml
podLabels:
  aadpodidbinding: mermin-identity
```

Set up Azure AD Pod Identity:

```bash
# Install AAD Pod Identity
kubectl apply -f https://raw.githubusercontent.com/Azure/aad-pod-identity/master/deploy/infra/deployment-rbac.yaml

# Create managed identity
az identity create -g mermin-rg -n mermin-identity

# Assign role
IDENTITY_CLIENT_ID=$(az identity show -g mermin-rg -n mermin-identity --query clientId -o tsv)
az role assignment create \
  --role Reader \
  --assignee $IDENTITY_CLIENT_ID \
  --scope /subscriptions/SUBSCRIPTION_ID/resourceGroups/mermin-rg
```

## Cloud-Specific Networking Considerations

### Network Policies

All cloud platforms support Kubernetes NetworkPolicies. Ensure Mermin can reach:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mermin-egress
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: mermin
  policyTypes:
    - Egress
  egress:
    # Allow OTLP export
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 4317
    # Allow Kubernetes API access
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 443
    # Allow DNS
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: UDP
          port: 53
```

### Load Balancers

If exposing metrics externally:

**GKE:**

```yaml
service:
  type: LoadBalancer
  annotations:
    cloud.google.com/load-balancer-type: "Internal"
```

**EKS:**

```yaml
service:
  type: LoadBalancer
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: nlb
    service.beta.kubernetes.io/aws-load-balancer-internal: "true"
```

**AKS:**

```yaml
service:
  type: LoadBalancer
  annotations:
    service.beta.kubernetes.io/azure-load-balancer-internal: "true"
```

## Cloud-Specific RBAC and IAM

### GKE

Mermin requires Kubernetes RBAC (handled by Helm chart). No additional GCP IAM permissions needed for basic operation.

For advanced features (e.g., accessing GCP APIs):

```bash
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member "serviceAccount:mermin-sa@PROJECT_ID.iam.gserviceaccount.com" \
  --role "roles/compute.viewer"
```

### EKS

Mermin requires Kubernetes RBAC (handled by Helm chart). No additional AWS IAM permissions needed for basic operation.

For advanced features (e.g., accessing AWS APIs):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeNetworkInterfaces"
      ],
      "Resource": "*"
    }
  ]
}
```

### AKS

Mermin requires Kubernetes RBAC (handled by Helm chart). No additional Azure IAM permissions needed for basic operation.

For advanced features (e.g., accessing Azure APIs):

```bash
az role assignment create \
  --role "Reader" \
  --assignee $IDENTITY_CLIENT_ID \
  --scope /subscriptions/SUBSCRIPTION_ID
```

## Performance and Cost Optimization

### GKE

* Use **Preemptible/Spot nodes** for non-critical Mermin pods (with PodDisruptionBudget)
* Use **node autoscaling** to match traffic patterns
* Consider **regional clusters** for high availability

### EKS

* Use **Spot instances** for cost savings (with PodDisruptionBudget)
* Use **Cluster Autoscaler** or **Karpenter** for dynamic scaling
* Enable **Container Insights** for monitoring

### AKS

* Use **Spot node pools** for cost savings
* Use **Cluster Autoscaler** for dynamic scaling
* Enable **Container Insights** for monitoring

## Multi-Region Deployments

For multi-region observability:

1. **Deploy Mermin in each region's cluster**
2. **Use region-specific OTLP collectors** to reduce cross-region data transfer
3. **Aggregate at central collector** if needed
4. **Tag flows with region identifier** for differentiation

Example configuration with region tagging:

```hcl
export "traces" {
  otlp = {
    endpoint = "http://otel-collector.us-west-2:4317"
    # Add region as resource attribute
    resource_attributes = {
      "cloud.region" = "us-west-2"
      "cloud.provider" = "aws"
    }
  }
}
```

## Monitoring and Logging

### Cloud-Native Monitoring

**GKE - Cloud Monitoring:**

```bash
# Enable GKE monitoring
gcloud container clusters update mermin-cluster \
  --enable-cloud-monitoring \
  --zone us-central1-a
```

**EKS - Container Insights:**

```bash
# Install CloudWatch Container Insights
curl https://raw.githubusercontent.com/aws-samples/amazon-cloudwatch-container-insights/latest/k8s-deployment-manifest-templates/deployment-mode/daemonset/container-insights-monitoring/quickstart/cwagent-fluentd-quickstart.yaml | kubectl apply -f -
```

**AKS - Container Insights:**

```bash
# Enable Container Insights
az aks enable-addons \
  --resource-group mermin-rg \
  --name mermin-cluster \
  --addons monitoring
```

## Troubleshooting Cloud-Specific Issues

### GKE Autopilot: "Operation not permitted"

Ensure you're using capabilities instead of `privileged: true`:

```yaml
securityContext:
  privileged: false
  capabilities:
    add: [BPF, NET_ADMIN, SYS_ADMIN]
```

### EKS: "Cannot load eBPF program"

Verify kernel version on AL2 nodes:

```bash
kubectl debug node/NODE_NAME -it --image=amazon/amazon-linux-2
uname -r  # Should be >= 4.18
```

### AKS: "Insufficient permissions"

Ensure managed identity has necessary permissions and AAD Pod Identity is configured correctly.

## Next Steps

* [**Advanced Scenarios**](advanced-scenarios.md): Custom CNI, multi-cluster deployments
* [**Configuration Reference**](../configuration/configuration.md): Fine-tune Mermin for your environment
* [**Integrations**](../integrations/integrations.md): Connect to cloud-native observability platforms
* [**Troubleshooting**](../troubleshooting/troubleshooting.md): Solve cloud-specific issues
