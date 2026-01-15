# This is the helper script to prepare Grafana Dashboard JSON to be published in Grafana Marketplace:
# curl -s "localhost:3000/api/dashboards/uid/mermin_app" | jq -r -f hack/sanitize_grafana_dashboard.jq > docs/observability/grafana-mermin-app.json

.
|= {"__requires":[{"type":"grafana","id":"grafana","name":"Grafana","version":"11.6.1"}]} + .
| .id = null
| .version = 1
