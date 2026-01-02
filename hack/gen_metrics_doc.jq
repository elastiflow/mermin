# This is the helper script to generate part of the metrics Markdown documentation. Usage example:
# curl -s ${POD_IP}:10250/metrics:summary | jq --arg metric_prefix ${metric_prefix} -r -f hack/gen_metrics_doc.jq
# curl -s localhost:10250/metrics:summary | jq --arg metric_prefix mermin_pipeline -r -f hack/gen_metrics_doc.jq

def labels_formatter(labels):
  if labels | length > 0 then
    "\n  *Labels*:" + (labels | map("\n  - `\(.)`") | join(""))
  else
    ""
  end
;

.metrics[]
| select(.name | startswith($metric_prefix))
| to_entries | sort_by(.name) | from_entries
| "- `\(.name)`
  *Type*: `\(.type)`
  *Description*: \(.description)\(labels_formatter(.labels))"
