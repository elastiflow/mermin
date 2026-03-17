export "traces" {
  otlp = {
    endpoint = "https://otel-collector:4317"

    tls = {
      insecure_skip_verify = true
    }
  }
}
