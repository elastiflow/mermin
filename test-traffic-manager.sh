#!/bin/bash
# Script to manage long-running test traffic for process name resolution testing
# Usage: ./test-traffic-manager.sh [start|stop|status|logs]

set -e

NAMESPACE="${NAMESPACE:-default}"
ACTION="${1:-status}"

case "$ACTION" in
  start)
    echo "=== Starting long-running test traffic ==="
    
    # Check if already running
    if kubectl get pod test-http-server -n $NAMESPACE &>/dev/null; then
      echo "test-http-server already exists. Use 'stop' first or 'restart'"
      exit 1
    fi
    
    if kubectl get pod test-traffic-generator -n $NAMESPACE &>/dev/null; then
      echo "test-traffic-generator already exists. Use 'stop' first or 'restart'"
      exit 1
    fi
    
    # Deploy the test pods
    kubectl apply -f test-long-running-traffic.yaml
    
    # Wait for pods to be ready
    echo "Waiting for test-http-server to be ready..."
    kubectl wait --for=condition=Ready pod/test-http-server -n $NAMESPACE --timeout=60s || {
      echo "Warning: test-http-server did not become ready in time"
    }
    
    echo "Waiting for test-traffic-generator to be ready..."
    kubectl wait --for=condition=Ready pod/test-traffic-generator -n $NAMESPACE --timeout=60s || {
      echo "Warning: test-traffic-generator did not become ready in time"
    }
    
    # Get pod IPs and PIDs
    echo ""
    echo "=== Test Traffic Started ==="
    echo "HTTP Server:"
    kubectl get pod test-http-server -n $NAMESPACE -o wide
    echo ""
    echo "Traffic Generator:"
    kubectl get pod test-traffic-generator -n $NAMESPACE -o wide
    echo ""
    echo "To view logs:"
    echo "  kubectl logs test-http-server -n $NAMESPACE"
    echo "  kubectl logs test-traffic-generator -n $NAMESPACE"
    echo ""
    echo "To get PIDs:"
    echo "  kubectl exec test-http-server -n $NAMESPACE -- pgrep nginx"
    echo "  kubectl exec test-traffic-generator -n $NAMESPACE -- pgrep curl"
    ;;
    
  stop)
    echo "=== Stopping long-running test traffic ==="
    kubectl delete -f test-long-running-traffic.yaml --ignore-not-found=true
    echo "Test traffic stopped"
    ;;
    
  restart)
    echo "=== Restarting long-running test traffic ==="
    kubectl delete -f test-long-running-traffic.yaml --ignore-not-found=true
    sleep 2
    kubectl apply -f test-long-running-traffic.yaml
    echo "Waiting for pods to be ready..."
    kubectl wait --for=condition=Ready pod/test-http-server -n $NAMESPACE --timeout=60s || true
    kubectl wait --for=condition=Ready pod/test-traffic-generator -n $NAMESPACE --timeout=60s || true
    echo "Test traffic restarted"
    ;;
    
  status)
    echo "=== Test Traffic Status ==="
    echo ""
    echo "HTTP Server:"
    if kubectl get pod test-http-server -n $NAMESPACE &>/dev/null; then
      kubectl get pod test-http-server -n $NAMESPACE -o wide
      echo ""
      echo "Server PIDs:"
      kubectl exec test-http-server -n $NAMESPACE -- sh -c 'pgrep nginx || echo "No nginx processes found"' 2>/dev/null || echo "Cannot access pod"
      echo ""
      echo "Server logs (last 5 lines):"
      kubectl logs test-http-server -n $NAMESPACE --tail=5 2>/dev/null || echo "Cannot read logs"
    else
      echo "  Not running"
    fi
    echo ""
    echo "Traffic Generator:"
    if kubectl get pod test-traffic-generator -n $NAMESPACE &>/dev/null; then
      kubectl get pod test-traffic-generator -n $NAMESPACE -o wide
      echo ""
      echo "Generator PIDs:"
      kubectl exec test-traffic-generator -n $NAMESPACE -- sh -c 'pgrep curl || echo "No curl processes found"' 2>/dev/null || echo "Cannot access pod"
      echo ""
      echo "Generator logs (last 10 lines):"
      kubectl logs test-traffic-generator -n $NAMESPACE --tail=10 2>/dev/null || echo "Cannot read logs"
    else
      echo "  Not running"
    fi
    ;;
    
  logs)
    echo "=== HTTP Server Logs ==="
    kubectl logs test-http-server -n $NAMESPACE --tail=20 -f 2>/dev/null || echo "Server not running or cannot access logs"
    ;;
    
  logs-generator)
    echo "=== Traffic Generator Logs ==="
    kubectl logs test-traffic-generator -n $NAMESPACE --tail=20 -f 2>/dev/null || echo "Generator not running or cannot access logs"
    ;;
    
  pids)
    echo "=== Process IDs ==="
    echo ""
    echo "HTTP Server (nginx) PIDs:"
    kubectl exec test-http-server -n $NAMESPACE -- pgrep nginx 2>/dev/null || echo "Cannot get PIDs"
    echo ""
    echo "Traffic Generator (curl) PIDs:"
    kubectl exec test-traffic-generator -n $NAMESPACE -- pgrep curl 2>/dev/null || echo "Cannot get PIDs"
    echo ""
    echo "To test reading process names from mermin pod:"
    MERMIN_POD=$(kubectl get pods -l app.kubernetes.io/name=mermin -n $NAMESPACE -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    if [ -n "$MERMIN_POD" ]; then
      echo "Mermin pod: $MERMIN_POD"
      echo ""
      echo "Example commands:"
      SERVER_PID=$(kubectl exec test-http-server -n $NAMESPACE -- pgrep nginx | head -1 2>/dev/null)
      if [ -n "$SERVER_PID" ]; then
        echo "  kubectl exec $MERMIN_POD -n $NAMESPACE -- cat /proc/$SERVER_PID/comm"
      fi
    fi
    ;;
    
  *)
    echo "Usage: $0 [start|stop|restart|status|logs|logs-generator|pids]"
    echo ""
    echo "Commands:"
    echo "  start           - Start test traffic (HTTP server + traffic generator)"
    echo "  stop            - Stop test traffic"
    echo "  restart         - Restart test traffic"
    echo "  status          - Show status of test traffic"
    echo "  logs            - Follow HTTP server logs"
    echo "  logs-generator  - Follow traffic generator logs"
    echo "  pids            - Show process IDs and test commands"
    exit 1
    ;;
esac

