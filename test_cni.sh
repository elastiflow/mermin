#!/usr/bin/env bash
set -euo pipefail

trap 'cleanup' EXIT

CLUSTER_NAME="${CLUSTER_NAME:-mermin-cni-test}"
HELM_CHART_PATH="${HELM_CHART_PATH:-./charts/mermin}"
RELEASE_NAME="${RELEASE_NAME:-mermin}"
NAMESPACE="${NAMESPACE:-atlantis}"
DOCKER_IMAGE_NAME="${DOCKER_IMAGE_NAME:-mermin}"
DOCKER_IMAGE_TAG="${DOCKER_IMAGE_TAG:-latest}"
VALUES_FILE="${VALUES_FILE:-local/values.yaml}"
CNI="${CNI:-calico}"
HOST_CNI_PATH="$HOME/cni-plugins-for-kind"

install_calico() {
  echo "Installing Calico..."
  local CALICO_TAG
  CALICO_TAG=$(curl -s https://api.github.com/repos/projectcalico/calico/releases/latest | grep '"tag_name":' | head -n1 | cut -d '"' -f4)
  kubectl apply -f "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_TAG}/manifests/calico.yaml"
  kubectl rollout status daemonset calico-node -n kube-system --timeout=120s
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
  echo "Installing Flannel manifest..."
  kubectl apply -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml
  kubectl rollout status daemonset kube-flannel-ds -n kube-flannel --timeout=240s
  echo "Waiting for /run/flannel/subnet.env to appear..."
  for node in $(kind get nodes --name "${CLUSTER_NAME}"); do
    timeout 180s bash -c "until docker exec ${node} test -f /run/flannel/subnet.env; do sleep 1; done" || {
      echo "Timeout waiting for /run/flannel/subnet.env on ${node}"
      exit 1
    }
  done
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
      ;;
  esac
}

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
  helm upgrade --install "$RELEASE_NAME" "$HELM_CHART_PATH" \
    -n "$NAMESPACE" --values "$VALUES_FILE" \
    --set image.repository="$DOCKER_IMAGE_NAME" \
    --set image.tag="$DOCKER_IMAGE_TAG" \
    --wait --timeout=3m --create-namespace
}

verify_deployment() {
  kubectl wait --for=condition=Ready pods -l "app.kubernetes.io/name=${RELEASE_NAME}" -n "$NAMESPACE" --timeout=3m
}

verify_agent_logs() {
  echo "Verifying mermin agent logs are enriching data..."
  export NAMESPACE RELEASE_NAME
  local pods
  mapfile -t pods < <(kubectl get pods -n "${NAMESPACE}" -l "app.kubernetes.io/name=${RELEASE_NAME}" -o 'jsonpath={range .items[*]}{.metadata.name}{"\n"}{end}')

  if [ ${#pods[@]} -eq 0 ]; then
    echo "No mermin pods found to test." && exit 1
  fi

  for pod in "${pods[@]}"; do
    (
      local counter=0
      while [ $counter -lt 30 ]; do
        if grep -q --color=never "Enriched packet" <(kubectl logs -n "${NAMESPACE}" "$pod" --tail=50); then
          exit 0
        fi
        counter=$((counter + 1))
        sleep 2
      done
      exit 1
    ) &
  done

  echo "Waiting for all pod checks to complete..."
  local has_succeeded=0
  for job in $(jobs -p); do
    if wait "$job"; then
      has_succeeded=1
    fi
  done

  if [ "$has_succeeded" -eq 1 ]; then
    echo "Test PASSED: At least one agent pod is enriching data."
  else
    echo "Test FAILED: No agent pods showed 'Enriched packet' logs."
    exit 1
  fi
}

cleanup() {
  kind delete cluster --name "$CLUSTER_NAME" || true
}

dump_debug_info() {
  echo "=== Pod Status Summary ==="
  kubectl get pods -n "${NAMESPACE}" -o wide
  echo "=== Pod Details and Events ==="
  kubectl describe pods -n "${NAMESPACE}"
  echo "=== Full Namespace Event Log (sorted by time) ==="
  kubectl get events -n "${NAMESPACE}" --sort-by='.lastTimestamp'
}

#----------------#
# Main execution #
#----------------#

echo "==============================="
echo "Testing with CNI: $CNI"
echo "==============================="

create_kind_cluster "${CNI}"
install_cni "${CNI}"
kubectl wait --for=condition=Ready nodes --all --timeout=3m
load_image_into_kind
deploy_helm_chart || { dump_debug_info; exit 1; }
verify_deployment
verify_agent_logs

echo "Test succeeded with CNI: $CNI"
