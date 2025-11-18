# Span configuration for flow tracking and trace correlation
span {
  # Trace ID correlation timeout
  # Flows with the same community ID will share the same trace ID until this timeout expires
  # This enables correlation of related flows (e.g., multiple records from a long TCP connection)
  # Default: 24h
  trace_id_timeout = "24h"
  
  # Test-optimized values for faster CI feedback
  max_record_interval = "10s"   # Export active flows every 10s (default: 60s)
  icmp_timeout        = "5s"    # ICMP flows timeout after 5s (default: 10s)
  
  # Other span options use default values if not specified:
  # tcp_timeout         = "20s"  # Idle timeout for TCP flows
  # udp_timeout         = "60s"  # Idle timeout for UDP flows
}

# OTLP exporter configuration
# See OBI export concepts: https://opentelemetry.io/docs/zero-code/obi/configure/export-data/
export "traces" {
  stdout = {
    format = "text_indent" // text, text_indent(*new), json, json_indent
  }

  # otlp = {
  #   endpoint               = "http://otelcol:4317" # Use `https` for TLS encrypted OTLP receivers

  #   # Authentication config
  #   # auth = {
  #   #   basic = {
  #   #     user = "USERNAME"
  #   #     pass = "PASSWORD"
  #   #   }
  #   # }

  #   # TLS config
  #   # tls = {
  #   #   insecure_skip_verify = false # Skip verifying the OTLP receiver certificate
  #   #   ca_cert              = "/etc/certs/ca.crt" # Path to the receiver certificate Certificate Authority
  #   #   client_cert          = "/etc/certs/cert.crt" # Client TLS certificate (mTLS)
  #   #   client_key           = "/etc/certs/cert.key" # Client TLS key (mTLS)
  #   # }
  # }
}

# Metrics server configuration (for Prometheus scraping)
metrics {
  enabled        = true
  listen_address = "0.0.0.0"
  port           = 10250
}
