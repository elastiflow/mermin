#!/usr/bin/env bash
set -euo pipefail

# This trap will call the cleanup function on script exit
trap 'cleanup' EXIT

# --- Variable Definitions ---
# These variables will be used by the setup script and verification steps
CLUSTER_NAME="${CLUSTER_NAME:-mermin-cni-test}"
RELEASE_NAME="${RELEASE_NAME:-mermin}"
NAMESPACE="${NAMESPACE:-default}"
DOCKER_REPOSITORY="${DOCKER_REPOSITORY:-mermin}"
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
  echo "Creating flows generator (pinger)..."
  kubectl -n "${NAMESPACE}" run ping-receiver --grace-period=1 --image=alpine --command -- sleep 3600
  echo "Waiting for ping-receiver pod to be ready..."
  kubectl wait --for=condition=ready pod/ping-receiver -n "${NAMESPACE}" --timeout=60s || {
    echo "ERROR: ping-receiver pod failed to become ready"
    return 1
  }
  
  local counter=0
  ping_receiver_ip=""
  while [ $counter -lt 30 ]; do
    ping_receiver_ip=$(kubectl -n "${NAMESPACE}" get pod ping-receiver -o 'jsonpath={.status.podIP}')
    if [[ -n "$ping_receiver_ip" ]]; then
      echo "ping-receiver IP: $ping_receiver_ip"
      break
    fi
    counter=$((counter + 1))
    sleep 0.5
  done
  
  if [[ -z "$ping_receiver_ip" ]]; then
    echo "ERROR: Failed to get ping-receiver IP after 15 seconds"
    return 1
  fi
  
  kubectl -n "${NAMESPACE}" run pinger --grace-period=1 --image=alpine --command -- ping "${ping_receiver_ip}"
  echo "Waiting for pinger pod to be ready..."
  kubectl wait --for=condition=ready pod/pinger -n "${NAMESPACE}" --timeout=60s || {
    echo "WARNING: pinger pod failed to become ready. Continuing..."
  }

  # Give pinger enough time to generate traffic and for spans to be recorded
  sleep 20

  echo "Verifying mermin agent logs are enriching data..."
  export NAMESPACE RELEASE_NAME
  local pods=()
  while IFS= read -r pod_name; do
    if [[ -n "$pod_name" ]]; then
      pods+=("$pod_name")
    fi
  done < <(kubectl get pods -n "${NAMESPACE}" -l "app.kubernetes.io/name=${RELEASE_NAME}" -o 'jsonpath={range .items[*]}{.metadata.name}{"\n"}{end}')

  if [ ${#pods[@]} -eq 0 ]; then
    echo "No mermin pods found to test." && return 1
  fi

  for pod in "${pods[@]}"; do
    (
      local counter=0
      while [ $counter -lt 120 ]; do
        # examples: https://regex101.com/r/rYbX7m/1
        if kubectl logs -n "${NAMESPACE}" "$pod" --tail=1000 2>/dev/null | grep --color=never -E '(source\.k8s\.pod\.name.*String\(Owned\("pinger"\)|destination\.k8s\.pod\.name.*String\(Owned\("ping-receiver"\))' >/dev/null; then
          exit 0
        fi
        counter=$((counter + 1))
        sleep 2
      done
      return 1
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
    return 1
  fi
}

# --- Debugging Function ---
dump_debug_info() {
  kubectl get pods -n "${NAMESPACE}" -o wide
  kubectl get events -n "${NAMESPACE}" --sort-by='.lastTimestamp' | tail -20
  for pod in $(kubectl get pods -n "${NAMESPACE}" -l "app.kubernetes.io/name=${RELEASE_NAME}" -o name 2>/dev/null | cut -d/ -f2); do
    echo "--- $pod logs ---"
    kubectl logs -n "${NAMESPACE}" "$pod" --tail=100 2>/dev/null || true
  done
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
