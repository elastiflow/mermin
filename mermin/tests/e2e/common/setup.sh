#!/usr/bin/env bash
set -euo pipefail

# --- Variable Definitions ---
CLUSTER_NAME="${CLUSTER_NAME:-mermin-cni-test}"
HELM_CHART_PATH="${HELM_CHART_PATH:-./charts/mermin}"
RELEASE_NAME="${RELEASE_NAME:-mermin}"
NAMESPACE="${NAMESPACE:-default}"
DOCKER_REPOSITORY="${DOCKER_REPOSITORY:-mermin}"
DOCKER_IMAGE_TAG="${DOCKER_IMAGE_TAG:-latest}"
DOCKER_IMAGE_NAME="${DOCKER_REPOSITORY}:${DOCKER_IMAGE_TAG}"
VALUES_FILE="${VALUES_FILE:-docs/deployment/examples/local/values.yaml}"
CNI="${CNI:-calico}"
MERMIN_CONFIG_PATH="${MERMIN_CONFIG_PATH:-docs/deployment/examples/local/config.example.hcl}"

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

  # Download CNI plugins once on host (much faster than downloading in each container)
  local ARCH
  ARCH=$(uname -m | sed "s/x86_64/amd64/" | sed "s/aarch64/arm64/")
  local CNI_VERSION="v1.5.0"
  local CNI_TGZ="/tmp/cni-plugins-${CNI_VERSION}.tgz"

  if [ ! -f "$CNI_TGZ" ]; then
    echo "Downloading CNI plugins ${CNI_VERSION} to $CNI_TGZ..."
    if ! curl -sL -o "$CNI_TGZ" "https://github.com/containernetworking/plugins/releases/download/${CNI_VERSION}/cni-plugins-linux-${ARCH}-${CNI_VERSION}.tgz"; then
      echo "ERROR: Failed to download CNI plugins"
      exit 1
    fi
    if [ ! -f "$CNI_TGZ" ]; then
      echo "ERROR: Downloaded file $CNI_TGZ does not exist"
      exit 1
    fi
    echo "Successfully downloaded CNI plugins ($(du -h "$CNI_TGZ" | cut -f1))"
  else
    echo "Using cached CNI plugins from $CNI_TGZ ($(du -h "$CNI_TGZ" | cut -f1))"
  fi

  # Copy to all nodes (using /opt for better compatibility with Kind containers)
  for node in $(kind get nodes --name "${CLUSTER_NAME}"); do
    echo "Installing CNI plugins on node: $node"

    # Copy to /opt instead of /tmp (Kind containers may have special /tmp handling)
    echo "Copying CNI plugins to $node:/opt/cni-plugins.tgz..."
    if ! docker cp "$CNI_TGZ" "${node}:/opt/cni-plugins.tgz"; then
      echo "ERROR: Failed to copy CNI plugins to node $node"
      exit 1
    fi

    # Verify the file exists
    if ! docker exec "${node}" test -f /opt/cni-plugins.tgz; then
      echo "ERROR: File /opt/cni-plugins.tgz does not exist on node $node after copy"
      exit 1
    fi

    # Extract the plugins
    echo "Extracting CNI plugins on $node..."
    if ! docker exec "${node}" tar -C /opt/cni/bin -xzf /opt/cni-plugins.tgz; then
      echo "ERROR: Failed to extract CNI plugins on node $node"
      exit 1
    fi

    # Clean up
    docker exec "${node}" rm -f /opt/cni-plugins.tgz
    echo "✓ Successfully installed CNI plugins on node: $node"
  done

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

  cat <<EOF | kind create cluster --name "$CLUSTER_NAME" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  podSubnet: "10.244.0.0/16"
  disableDefaultCNI: $disable_cni
nodes:
- role: control-plane
- role: worker
EOF
  # Explicitly set kubectl context to ensure it's configured correctly
  kubectl config use-context "kind-${CLUSTER_NAME}"
}

load_image_into_kind() {
  echo "Loading image into kind cluster: $DOCKER_IMAGE_NAME"
  kind load docker-image "$DOCKER_IMAGE_NAME" --name "$CLUSTER_NAME"
}

deploy_helm_chart() {
  make helm-upgrade \
    APP="$RELEASE_NAME" \
    HELM_CHART="$HELM_CHART_PATH" \
    HELM_NAMESPACE="$NAMESPACE" \
    HELM_VALUES="$VALUES_FILE" \
    HELM_EXTRA_ARGS="--set image.repository=$DOCKER_REPOSITORY --set image.tag=$DOCKER_IMAGE_TAG --set-file config.content=$MERMIN_CONFIG_PATH --wait --timeout=10m --create-namespace"
}

# --- Main Execution ---
echo "==================================="
echo "Setting up E2E environment for CNI: $CNI"
echo "==================================="

create_kind_cluster "${CNI}"
install_cni "${CNI}"
# Ensure kubectl context is set before waiting for nodes
kubectl config use-context "kind-${CLUSTER_NAME}" || true
kubectl wait --for=condition=Ready nodes --all --timeout=3m
load_image_into_kind
deploy_helm_chart

echo "Setup complete. The environment is ready for testing."
