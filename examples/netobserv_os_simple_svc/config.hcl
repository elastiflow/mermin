discovery "instrument" {
  # Network interfaces to monitor
  interfaces = ["*"]
}

# OTLP exporter configuration
# See OBI export concepts: https://opentelemetry.io/docs/zero-code/obi/configure/export-data/
export "traces" {
  # stdout = {
  #   format = "text_indent" // text, text_indent(*new), json, json_indent
  # }

  otlp = {
    endpoint = "https://netobserv-flow.elastiflow.svc.cluster.local:4317"

    tls = {
      insecure_skip_verify = true
    }
  }
}
