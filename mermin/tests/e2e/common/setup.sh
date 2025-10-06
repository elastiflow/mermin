#!/usr/bin/env bash
set -euo pipefail

# --- Variable Definitions ---
CLUSTER_NAME="${CLUSTER_NAME:-mermin-cni-test}"
HELM_CHART_PATH="${HELM_CHART_PATH:-./charts/mermin}"
RELEASE_NAME="${RELEASE_NAME:-mermin}"
NAMESPACE="${NAMESPACE:-atlantis}"
DOCKER_IMAGE_NAME="${DOCKER_IMAGE_NAME:-mermin}"
DOCKER_REPOSITORY="${DOCKER_REPOSITORY:-mermin}"
DOCKER_IMAGE_TAG="${DOCKER_IMAGE_TAG:-latest}"
VALUES_FILE="${VALUES_FILE:-examples/local/values.yaml}"
CNI="${CNI:-calico}"
HOST_CNI_PATH="$HOME/cni-plugins-for-kind"
MERMIN_CONFIG_PATH="${MERMIN_CONFIG_PATH:-examples/local/config.hcl}"

# --- CNI Installation Functions ---
install_calico() {
  echo "Installing Calico..."
  local CALICO_TAG
  CALICO_TAG=$(curl -s https://api.github.com/repos/projectcalico/calico/releases/latest | grep '"tag_name":' | head -n1 | cut -d '"' -f4)
  kubectl apply -f "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_TAG}/manifests/calico.yaml"
  kubectl rollout status daemonset calico-node -n kube-system --timeout=240s
}

install_cilium() {
  echo "Installing Cilium..."
  if ! command -v cilium >/dev/null; then
    local CILIUM_CLI_VERSION
    CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
    local OS ARCH
    OS=$(uname | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m | awk '
      /x86_64/ {print "amd64"; exit}
      /aarch64/ || /arm64/ {print "arm64"; exit}
      {print $0; exit}')
    curl -sL --remote-name-all \
      "https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-${OS}-${ARCH}.tar.gz"{,.sha256sum}
    sha256sum --check "cilium-${OS}-${ARCH}.tar.gz.sha256sum"
    sudo tar -C /usr/local/bin -xzvf "cilium-${OS}-${ARCH}.tar.gz"
    rm "cilium-${OS}-${ARCH}.tar.gz"{,.sha256sum}
  fi
  cilium install --wait
}


install_flannel() {
  echo "Installing CNI plugin binaries for Flannel..."
  for node in $(kind get nodes --name "${CLUSTER_NAME}"); do
    docker exec "${node}" sh -c '
      ARCH=$(uname -m | sed "s/x86_64/amd64/" | sed "s/aarch64/arm64/");
      CNI_VERSION="v1.5.0";
      curl -sL "https://github.com/containernetworking/plugins/releases/download/${CNI_VERSION}/cni-plugins-linux-${ARCH}-${CNI_VERSION}.tgz" | tar -C /opt/cni/bin -xz;
    '
  done
  sleep 10
  echo "Installing Flannel manifest..."
  kubectl apply -f https://github.com/flannel-io/flannel/releases/download/v0.24.2/kube-flannel.yml
  kubectl rollout status daemonset kube-flannel-ds -n kube-flannel --timeout=240s
  kubectl wait --for=condition=ready pod -l app=flannel -n kube-flannel --timeout=240s
}

install_kindnetd() {
  echo "Using default Kind CNI (kindnetd)..."
}

install_cni() {
  case "$1" in
    calico)
      install_calico
      ;;
    cilium)
      install_cilium
      ;;
    flannel)
      install_flannel
      ;;
    kindnetd)
      install_kindnetd
      ;;
    *)
      echo "Unsupported CNI: $1"
      exit 1
      ;;
  esac
}

# --- Environment Setup Functions ---
create_kind_cluster() {
  echo "Creating Kind cluster configured for CNI: $1"
  [[ $1 == "kindnetd" ]] && disable_cni=false || disable_cni=true
  [[ $1 == "flannel" ]] && {
    mkdir -p "$HOST_CNI_PATH"
    mounts=$'\n  extraMounts:\n  - hostPath: '"$HOST_CNI_PATH"$'\n    containerPath: /opt/cni/bin'
  }
  cat <<EOF | kind create cluster --name "$CLUSTER_NAME" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  podSubnet: "10.244.0.0/16"
  disableDefaultCNI: $disable_cni
nodes:
- role: control-plane
- role: worker${mounts:-}
EOF
}

load_image_into_kind() {
  echo "Loading image into kind cluster: $DOCKER_IMAGE_NAME"
  kind load docker-image "$DOCKER_IMAGE_NAME" --name "$CLUSTER_NAME"
}

deploy_helm_chart() {
  helm repo add netobserv https://elastiflow.github.io/helm-chart-netobserv/
  helm repo add opensearch https://opensearch-project.github.io/helm-charts/
  helm dependency build $HELM_CHART_PATH
  make helm-upgrade \
    APP="$RELEASE_NAME" \
    HELM_CHART="$HELM_CHART_PATH" \
    HELM_NAMESPACE="$NAMESPACE" \
    HELM_VALUES="$VALUES_FILE" \
    EXTRA_HELM_ARGS="--set image.repository=$DOCKER_REPOSITORY --set image.tag=$DOCKER_IMAGE_TAG --set-file config.source=$MERMIN_CONFIG_PATH --wait --timeout=3m --create-namespace"
}

# --- Main Execution ---
echo "==================================="
echo "Setting up E2E environment for CNI: $CNI"
echo "==================================="

create_kind_cluster "${CNI}"
install_cni "${CNI}"
kubectl wait --for=condition=Ready nodes --all --timeout=3m
load_image_into_kind
deploy_helm_chart

echo "Setup complete. The environment is ready for testing."
