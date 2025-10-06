#!/usr/bin/env bash
set -euo pipefail

# Define the cluster name, ensuring it matches the setup script's default
CLUSTER_NAME="${CLUSTER_NAME:-mermin-cni-test}"

echo "--- Tearing down the Kind cluster: $CLUSTER_NAME ---"

# The '|| true' ensures the script doesn't fail if the cluster was already deleted
kind delete cluster --name "$CLUSTER_NAME" || true

echo "Teardown complete."
