# OTLP exporter configuration
# See OBI export concepts: https://opentelemetry.io/docs/zero-code/obi/configure/export-data/
export "traces" {
  # Uncomment to receive spans in STDOUT
  # stdout = {
  #   format = "text_indent" // text, text_indent(*new), json, json_indent
  # }

  otlp = {
    endpoint = "https://192.168.0.100:443"

    tls = {
      insecure_skip_verify = true
    }
  }
}
