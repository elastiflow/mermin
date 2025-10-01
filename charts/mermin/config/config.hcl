# Mermin Default Configuration for Local Development
# This configuration file contains default settings for the Mermin eBPF network observability tool for local development.

# Network interfaces to monitor
interface = [
  "eth0"
]

# Logging configuration
log_level = "debug" # TODO(Cleanup for GA): Should be "info"

# Automatic configuration reloading
auto_reload = false

# Pipeline configuration
packet_channel_capacity = 1024
packet_worker_count     = 2
shutdown_timeout        = "5s"

# API server configuration (health endpoints)
api {
  enabled        = true
  listen_address = "0.0.0.0"
  port           = 8080
}

# Metrics server configuration (for Prometheus scraping)
metrics {
  enabled        = true
  listen_address = "0.0.0.0"
  port           = 10250
}

# Flow Span configuration
span {
  max_batch_size = 64
  max_batch_interval = "5s"
  max_record_interval = "60s"
  generic_timeout = "30s"
  icmp_timeout = "10s"
  tcp_timeout = "20s"
  tcp_fin_timeout = "5s"
  tcp_rst_timeout = "5s"
  udp_timeout = "60s"
}

# Specify which exporters are enabled
agent "traces" "main" {
  exporters = [
    "exporter.stdout.console"
  ]
}

# ------------------------
# New config format
# ------------------------

# OTLP exporter configuration
exporter "otlp" "main" {
  address = "example.com"
  port    = 4317

  auth "basic" {
    pass = "PASSWORD"
    user = "USERNAME"
  }

  tls {
    insecure    = false
    ca_cert     = "/etc/certs/ca.crt"
    client_cert = "/etc/certs/cert.crt"
    client_key  = "/etc/certs/cert.key"
    enabled     = true
  }
}

exporter "stdout" "console" {
  format = "full"
}
