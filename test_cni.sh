#!/usr/bin/env bash
set -euo pipefail

trap 'cleanup' EXIT

CLUSTER_NAME="mermin-cni-test"
HELM_CHART_PATH="./charts/mermin"
RELEASE_NAME="mermin"
NAMESPACE="atlantis"
DOCKER_IMAGE_NAME="mermin:latest"
VALUES_FILE="local/values.yaml"
CNIS=("calico" "cilium" "flannel")
# Define a host path for CNI binaries needed by Flannel
HOST_CNI_PATH="$HOME/cni-plugins-for-kind"

log() {
  printf '%s\n' "$*"
}

error() {
  printf '[ERROR] %s\n' "$*" >&2
}

create_kind_cluster() {
  log "Ensuring host path for CNI plugins exists at ${HOST_CNI_PATH}"
  mkdir -p "${HOST_CNI_PATH}"

  kind create cluster --name "$CLUSTER_NAME" --config=- <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  podSubnet: "10.244.0.0/16"
  disableDefaultCNI: true
nodes:
- role: control-plane
- role: worker
  # Required for Flannel to place CNI binaries on the host
  extraMounts:
  - hostPath: ${HOST_CNI_PATH}
    containerPath: /opt/cni/bin
EOF
}

install_cni() {
  case "$1" in
    calico)
      log "Installing Calico..."
      CALICO_TAG=$(curl -s https://api.github.com/repos/projectcalico/calico/releases/latest | grep '"tag_name":' | head -n1 | cut -d '"' -f4)
      kubectl apply -f "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_TAG}/manifests/calico.yaml"
      kubectl rollout status daemonset calico-node -n kube-system --timeout=120s
      ;;
    cilium)
      log "Installing Cilium..."
      if ! command -v cilium >/dev/null; then
        CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
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
      ;;
    flannel)
      # Flannel requires manually installing the CNI plugin binaries first,
      # as its manifest doesn't bundle them like Calico or Cilium do.
      log "Installing CNI plugin binaries for Flannel..."
      for node in $(kind get nodes --name "${CLUSTER_NAME}"); do
        docker exec "${node}" sh -c '
          ARCH=$(uname -m | sed "s/x86_64/amd64/" | sed "s/aarch64/arm64/");
          CNI_VERSION="v1.5.0";
          curl -sL "https://github.com/containernetworking/plugins/releases/download/${CNI_VERSION}/cni-plugins-linux-${ARCH}-${CNI_VERSION}.tgz" | tar -C /opt/cni/bin -xz;
        '
      done

      log "Installing Flannel manifest..."
      kubectl apply -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml
      kubectl rollout status daemonset kube-flannel-ds -n kube-flannel --timeout=120s
      ;;
    *)
      error "Unsupported CNI: $1"
      exit 1
      ;;
  esac
}

build_image() {
  if ! docker image inspect "$DOCKER_IMAGE_NAME" >/dev/null 2>&1; then
    log "Building Docker image: $DOCKER_IMAGE_NAME"
    docker build -t "$DOCKER_IMAGE_NAME" --target runner-debug .
  else
    log "Docker image already built: $DOCKER_IMAGE_NAME"
  fi
}

load_image_into_kind() {
  log "Loading image into kind cluster: $DOCKER_IMAGE_NAME"
  kind load docker-image "$DOCKER_IMAGE_NAME" --name "$CLUSTER_NAME"
}

deploy_helm_chart() {
  helm upgrade --install "$RELEASE_NAME" "$HELM_CHART_PATH" \
    -n "$NAMESPACE" --values "$VALUES_FILE" --wait --timeout=180s --create-namespace
}

verify_deployment() {
  kubectl wait --for=condition=Ready pods --all -n "$NAMESPACE" --timeout=180s
}

cleanup() {
  kind delete cluster --name "$CLUSTER_NAME" || true
}

verify_agent_logs() {
  log "Verifying mermin agent logs are enriching data..."
  kubectl get pods -n "${NAMESPACE}" -l "app.kubernetes.io/name=${RELEASE_NAME}" -o 'jsonpath={.items[*].metadata.name}' | \
  while read -r pod; do
    (
      counter=0
      while [ $counter -lt 15 ]; do
        if kubectl logs -n "${NAMESPACE}" "$pod" | grep -q "Enriched packet"; then
          printf "✅ Success: Found 'Enriched packet' in logs for %s.\\n" "$pod"
          exit 0
        fi
        counter=$((counter + 1))
        sleep 2
      done
      printf "❌ Failed: Did not find 'Enriched packet' in logs for pod %s after 30 seconds.\\n" "$pod" >&2
      exit 1
    ) &
  done

  local has_failed=0
  for job in $(jobs -p); do
    wait "$job" || has_failed=1
  done

  if [ "$has_failed" -ne 0 ]; then
    error "One or more agent pods failed the log verification."
  fi

  log "🎉 All mermin agent pods have the expected log output."
}

#----------------#
# Main execution #
#----------------#

build_image

for cni in "${CNIS[@]}"; do
  log "==============================="
  log "Testing with CNI: $cni"
  log "==============================="

  create_kind_cluster
  install_cni "$cni"
  kubectl wait --for=condition=Ready nodes --all --timeout=120s
  load_image_into_kind
  deploy_helm_chart
  verify_deployment
  verify_agent_logs
  cleanup

  log "✅ Test succeeded with CNI: $cni"
done

log "🎉 All CNI tests completed successfully."
