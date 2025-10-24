# OTLP exporter configuration
# See OBI export concepts: https://opentelemetry.io/docs/zero-code/obi/configure/export-data/
export "traces" {
  # stdout = {
  #   format = "text_indent" // text, text_indent(*new), json, json_indent
  # }

  otlp = {
    endpoint = "https://10.0.7.231:443"

    tls = {
      insecure_skip_verify = true
    }
  }
}
