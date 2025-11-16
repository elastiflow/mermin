# Logging configuration
# Automatic configuration reloading
auto_reload = false

# Pipeline configuration
pipeline {
  ring_buffer_capacity  = 8192
  worker_count          = 4
  worker_poll_interval  = "5s"
  k8s_decorator_threads = 12
}
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

# Discovery configuration
discovery "instrument" {
  # Network interfaces to monitor
  #
  # Glob example: match all ethernet interfaces starting with "eth"
  # interfaces = ["eth*"]
  # Regex example: match slot-based PNIN like en0p<digits>
  # interfaces = ["/^en0p\\d+$/"]
  interfaces = ["eth0"]
}

# Flow Span configuration
span {
  max_record_interval = "60s"
  generic_timeout     = "30s"
  icmp_timeout        = "10s"
  tcp_timeout         = "20s"
  tcp_fin_timeout     = "5s"
  tcp_rst_timeout     = "5s"
  udp_timeout         = "60s"
}

# Specify which exporters are enabled
agent "traces" "main" {
  exporters = [
    "exporter.otlp.main"
  ]
}

# OTLP exporter configuration
exporter "otlp" "main" {
  address = "host.docker.internal"
  port    = 4318

  tls {
    insecure_skip_verify = true
  }
}
