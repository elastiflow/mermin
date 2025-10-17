# OTLP exporter configuration
# See OBI export concepts: https://opentelemetry.io/docs/zero-code/obi/configure/export-data/
export "traces" {
  stdout = "disabled"

  otlp = {
    endpoint = "https://10.0.7.216:443"

    tls = {
      insecure = true
    }
  }
}
