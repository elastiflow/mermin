# OTLP exporter configuration
# See OBI export concepts: https://opentelemetry.io/docs/zero-code/obi/configure/export-data/
export "traces" {
  stdout = ""

  otlp = {
    endpoint = "https://192.0.2.100:443"

    tls = {
      insecure_skip_verify = true
    }
  }
}
