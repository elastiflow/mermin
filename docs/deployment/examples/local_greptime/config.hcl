# OTLP exporter configuration
# See OBI export concepts: https://opentelemetry.io/docs/zero-code/obi/configure/export-data/
export "traces" {
  stdout = {
    format = "text_indent" // text, text_indent(*new), json, json_indent
  }

  otlp = {
      endpoint = "http://greptimedb-standalone.elastiflow.svc.cluster.local:4000/v1/otlp/v1/traces"

      protocol = "http_binary"

      headers = {
        "x-greptime-db-name"       = "public"
        "x-greptime-pipeline-name" = "greptime_trace_v1"
      }

      tls = {
        insecure_skip_verify = true
      }
    }

}
# Metrics server configuration (for Prometheus scraping)
metrics {
  enabled        = true
  listen_address = "0.0.0.0"
  port           = 10250
}
# Test configuration optimized for fast CI runs
# Reduce flow export intervals for faster test feedback
span {
  max_record_interval = "10s"   # Export active flows every 5s (default: 60s)
  icmp_timeout = "5s"          # ICMP flows timeout after 3s (default: 10s)
}

discovery "instrument" {
  interfaces = ["veth*"]
}

log_level = "trace"
