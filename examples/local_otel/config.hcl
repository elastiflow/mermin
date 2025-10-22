# OTLP exporter configuration
# See OBI export concepts: https://opentelemetry.io/docs/zero-code/obi/configure/export-data/
export "traces" {
  stdout = ""

  otlp = {
    endpoint = "https://otel-collector.default.svc.cluster.local:4317"

    tls = {
      insecure_skip_verify = true
    }
  }
}
