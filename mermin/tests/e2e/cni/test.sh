#!/usr/bin/env bash
set -euo pipefail

# This trap will call the cleanup function on script exit
trap 'cleanup' EXIT

# --- Variable Definitions ---
# These variables will be used by the setup script and verification steps
CLUSTER_NAME="${CLUSTER_NAME:-mermin-cni-test}"
RELEASE_NAME="${RELEASE_NAME:-mermin}"
NAMESPACE="${NAMESPACE:-atlantis}"
DOCKER_IMAGE_NAME="${DOCKER_IMAGE_NAME:-mermin}"
DOCKER_IMAGE_TAG="${DOCKER_IMAGE_TAG:-latest}"
VALUES_FILE="${VALUES_FILE:-local/values.yaml}"
CNI="${CNI:-calico}"

# --- Cleanup Function ---
# Delegates cleanup to the centralized teardown script
cleanup() {
  echo "--- Cleaning up CNI test environment ---"
  bash ./mermin/tests/e2e/common/teardown.sh
}

# --- Verification Functions ---
verify_deployment() {
  make k8s-rollout-status \
    APP="$RELEASE_NAME" \
    HELM_NAMESPACE="$NAMESPACE"
}

verify_agent_logs() {
  echo "Verifying mermin agent logs are enriching data..."
  export NAMESPACE RELEASE_NAME
  local pods=()
  while IFS= read -r pod_name; do
    if [[ -n "$pod_name" ]]; then
      pods+=("$pod_name")
    fi
  done < <(kubectl get pods -n "${NAMESPACE}" -l "app.kubernetes.io/name=${RELEASE_NAME}" -o 'jsonpath={range .items[*]}{.metadata.name}{"\n"}{end}')

  if [ ${#pods[@]} -eq 0 ]; then
    echo "No mermin pods found to test." && exit 1
  fi

  for pod in "${pods[@]}"; do
    (
      local counter=0
      while [ $counter -lt 30 ]; do
        if grep --color=never 'destination.k8s.pod.name: String(Owned("coredns' <(kubectl logs -n "${NAMESPACE}" "$pod" --tail=500); then
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
    echo "Test FAILED: No agent pods showed enriched packet logs."
    exit 1
  fi
}

# --- Debugging Function ---
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

bash ./mermin/tests/e2e/common/setup.sh
verify_deployment || { dump_debug_info; exit 1; }
verify_agent_logs || { dump_debug_info; exit 1; }

echo "Test succeeded with CNI: $CNI"
