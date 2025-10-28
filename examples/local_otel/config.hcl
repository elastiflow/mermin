# OTLP exporter configuration
# See OBI export concepts: https://opentelemetry.io/docs/zero-code/obi/configure/export-data/
export "traces" {
  otlp = {
    endpoint = "https://otel-collector:4317"

    tls = {
      insecure_skip_verify = true
    }
  }
}
