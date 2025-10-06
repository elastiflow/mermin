#!/usr/bin/env bash
set -euo pipefail

# Cleanup function to run on script exit
trap 'cleanup' EXIT

# ANSI color codes for logging
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

export HOST_DOCKER_INTERNAL_ADDR="${HOST_DOCKER_INTERNAL_ADDR:-host.docker.internal}"
export MERMIN_CONFIG_PATH="${MERMIN_CONFIG_PATH:-"mermin/tests/e2e/grafana/config/mermin.hcl"}"

log_info() {
  echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_warn() {
  echo -e "${YELLOW}[WARN]${NC} $1"
}

cleanup() {
  log_info "Cleaning up resources..."
  docker-compose -f ./mermin/tests/e2e/grafana/docker-compose.yaml down -v --remove-orphans
  bash ./mermin/tests/e2e/common/teardown.sh
}

check_dependencies() {
  log_info "Checking for dependencies (docker, docker-compose, grpcurl)..."
  if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed. Please install it to continue."
    exit 1
  fi
  if ! command -v docker-compose &> /dev/null; then
    log_error "Docker Compose is not installed. Please install it to continue."
    exit 1
  fi
  if ! command -v grpcurl &> /dev/null; then
    log_error "grpcurl is not installed. Please install it (e.g., 'brew install grpcurl')."
    exit 1
  fi
}

start_services() {
  log_info "Starting services with docker-compose..."
  docker-compose -f mermin/tests/e2e/grafana/docker-compose.yaml up -d
  wait_for_ingestor
  bash ./mermin/tests/e2e/common/setup.sh
}

wait_for_ingestor() {
  log_info "Waiting for ingestor to be healthy..."
  local retries=30
  local count=0
  local healthy=0
  while [ $count -lt $retries ]; do
    if curl -s "http://localhost:3200/ready" | grep -q "ready"; then
        healthy=1
        break
    fi
    count=$((count + 1))
    sleep 5
  done

  if [ $healthy -eq 0 ]; then
    log_error "Services did not become healthy in time."
    dump_debug_info
    exit 1
  fi
}

verify_deployment() {
  make k8s-rollout-status \
    APP="$RELEASE_NAME" \
    HELM_NAMESPACE="$NAMESPACE"
}

verify_data_in_grafana() {
  log_info "Verifying that trace data made it to grafana..."
  local retries=12
  local count=0
  local data_found=0

  log_info "Querying grafana for: source.service.name=mermin"

  while [ $count -lt $retries ]; do
    URL="http://localhost:3000/api/datasources/proxy/uid/tempo/api/search?q=%7Bresource.service.name%3D%22mermin%22%7D&limit=20"

    echo "Querying for mermin traces..."

    response=$(curl -s -G "$URL")
    trace_count=$(echo "$response" | jq '.traces | length')
    if [ -z "$trace_count" ]; then
      trace_count=0
    fi

    if [ "$trace_count" -gt 0 ]; then
        log_info "Success! Received $trace_count trace(s)"
        data_found=1
        break
    fi

    log_warn "Data not found yet. Retrying in 5 seconds... ($((count+1))/$retries)"
    count=$((count + 1))
    sleep 5
  done

  if [ $data_found -eq 0 ]; then
    log_error "Test FAILED: Trace data was not found in grafana after timeout."
    dump_debug_info
    exit 1
  fi
}

dump_debug_info() {
  log_error "Dumping debug information..."
  echo "--- Docker Compose Logs ---"
  docker-compose -f ./mermin/tests/e2e/grafana/docker-compose.yaml logs
  echo "--- grafana Query Response ---"
  echo "${response:-"No response received"}"
}

#----------------#
# Main execution #
#----------------#
check_dependencies
start_services
verify_data_in_grafana

log_info "${GREEN}Test PASSED: OTLP trace successfully sent and verified in grafana.${NC}"
