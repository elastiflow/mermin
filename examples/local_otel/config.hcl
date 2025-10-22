# OTLP exporter configuration
# See OBI export concepts: https://opentelemetry.io/docs/zero-code/obi/configure/export-data/
export "traces" {
  stdout = ""

  otlp = {
    endpoint = "http://otel-collector.default.svc.cluster.local:4317"

    # tls = {
    #   insecure = true
    # }
  }
}
