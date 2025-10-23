# OTLP exporter configuration
# See OBI export concepts: https://opentelemetry.io/docs/zero-code/obi/configure/export-data/
export "traces" {
  # stdout = "" # Uncomment if you need spans in the stdout

  otlp = {
    endpoint = "https://10.0.7.231:443"

    tls = {
      insecure_skip_verify = true
    }
  }
}
