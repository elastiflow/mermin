#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="mermin-demo-loud-talkers"
NAMESPACE="elastiflow"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLEANUP="${CLEANUP:-false}"

RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m' NC='\033[0m'
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_prerequisites() {
    local missing=() tools=(docker kind kubectl helm)
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing+=("$tool")
        elif [ "$tool" = "docker" ] && ! docker info &>/dev/null; then
            log_error "Docker is installed but not running. Please start Docker."
            exit 1
        fi
    done
    [ ${#missing[@]} -eq 0 ] && return
    log_error "Missing required tools: ${missing[*]}"
    echo -e "\nInstallation: Docker (https://docs.docker.com/get-docker/) | kind (https://kind.sigs.k8s.io/docs/user/quick-start/#installation) | kubectl (https://kubernetes.io/docs/tasks/tools/) | helm (https://helm.sh/docs/intro/install/)"
    exit 1
}

cleanup() {
    log_info "Cleaning up demo environment..."
    pkill -f "kubectl.*port-forward.*elastiflow-os-dashboards" 2>/dev/null || true
    if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
        kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
        log_info "Cluster deleted"
    fi
    log_info "Cleanup complete"
}

create_cluster() {
    if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
        log_warn "Cluster $CLUSTER_NAME already exists"
        read -p "Delete and recreate? (y/N) " -n 1 -r
        echo
        [[ $REPLY =~ ^[Yy]$ ]] && kind delete cluster --name "$CLUSTER_NAME" || return
    fi
    log_info "Creating kind cluster: $CLUSTER_NAME"
    kind create cluster --name "$CLUSTER_NAME" --config=- <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
EOF
    kubectl wait --for=condition=Ready nodes --all --timeout=5m
}

setup_helm_repos() {
    log_info "Setting up Helm repositories..."
    helm repo add mermin https://elastiflow.github.io/mermin/ || true
    helm repo add netobserv https://elastiflow.github.io/helm-chart-netobserv/ || true
    helm repo add opensearch https://opensearch-project.github.io/helm-charts/ || true
    helm repo add metrics-server https://kubernetes-sigs.github.io/metrics-server/ || true
    helm repo update
}

install_metrics_server() {
    log_info "Installing metrics-server..."
    helm upgrade -i metrics-server metrics-server/metrics-server \
        -n kube-system \
        --set args={--kubelet-insecure-tls} \
        --wait --timeout=5m
}

deploy_mermin_stack() {
    log_info "Deploying mermin-netobserv-os-stack..."
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    helm upgrade -i --wait --timeout 15m -n "$NAMESPACE" \
        -f "$SCRIPT_DIR/values.yaml" \
        --set-file mermin.config.content="$SCRIPT_DIR/config.hcl" \
        mermin mermin/mermin-netobserv-os-stack
}

deploy_httpbin() {
    log_info "Deploying httpbin service..."
    kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: httpbin
  namespace: default
  labels:
    app: httpbin
spec:
  replicas: 1
  selector:
    matchLabels:
      app: httpbin
  template:
    metadata:
      labels:
        app: httpbin
    spec:
      containers:
      - name: httpbin
        image: kennethreitz/httpbin:latest
        ports:
        - containerPort: 80
          name: http
---
apiVersion: v1
kind: Service
metadata:
  name: httpbin-service
  namespace: default
  labels:
    app: httpbin
spec:
  selector:
    app: httpbin
  ports:
  - port: 80
    targetPort: 80
    protocol: TCP
    name: http
EOF
    kubectl wait --for=condition=Available deployment/httpbin -n default --timeout=5m
}

deploy_traffic_generator() {
    log_info "Deploying traffic generator..."
    kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: traffic-generator
  namespace: default
  labels:
    app: traffic-generator
spec:
  replicas: 2
  selector:
    matchLabels:
      app: traffic-generator
  template:
    metadata:
      labels:
        app: traffic-generator
    spec:
      containers:
      - name: hey
        image: golang:alpine
        command: ["sh", "-c"]
        args:
        - |
          apk add --no-cache git
          export GOPATH=/go
          export PATH=\$PATH:/go/bin
          go install github.com/rakyll/hey@latest
          while true; do
            /go/bin/hey -c 2000 -n 200000 -q 2000 http://httpbin-service.default.svc.cluster.local/get
            sleep 1
          done
        resources:
          limits:
            cpu: 2000m
            memory: 1Gi
          requests:
            cpu: 500m
            memory: 256Mi
EOF
    kubectl wait --for=condition=Available deployment/traffic-generator -n default --timeout=5m
}

setup_port_forward() {
    log_info "Setting up port-forward..."
    pkill -f "kubectl.*port-forward.*elastiflow-os-dashboards" 2>/dev/null || true
    sleep 2
    kubectl -n "$NAMESPACE" port-forward svc/elastiflow-os-dashboards 5601:5601 >/dev/null 2>&1 &
    sleep 3
    kill -0 $! 2>/dev/null || { log_error "Port-forward failed"; exit 1; }
    cat <<EOF

========================================
Demo setup complete!
========================================

OpenSearch Dashboards: http://localhost:5601
  Username: admin
  Password: Elast1flow!

Cleanup cluster: CLEANUP=true $0

EOF
}

main() {
    log_info "Starting Mermin Loud Talkers Demo Setup"
    check_prerequisites
    create_cluster
    setup_helm_repos
    install_metrics_server
    deploy_mermin_stack
    deploy_httpbin
    deploy_traffic_generator
    setup_port_forward
}

if [ "$CLEANUP" = "true" ]; then
    cleanup && exit 0
fi

main
