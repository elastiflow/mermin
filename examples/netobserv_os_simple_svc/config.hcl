# OTLP exporter configuration
# See OBI export concepts: https://opentelemetry.io/docs/zero-code/obi/configure/export-data/
export "traces" {
  stdout = ""

  otlp = {
    endpoint = "https://netobserv-flow.elastiflow.svc.cluster.local:4317"

    tls = {
      insecure_skip_verify = true
    }
  }
}
