# Mermin Default Configuration for Local Development
# This configuration file contains default settings for the Mermin eBPF network observability tool for local development.

# Network interfaces to monitor
# Literal example
interfaces = ["eth0"]
# Glob example: match all ethernet interfaces starting with "eth"
# interfaces = ["eth*"]
# Regex example: match slot-based PNIN like en0p<digits>
# interfaces = ["/^en0p\\d+$/"]

# Logging configuration
log_level = "info"

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
  max_record_interval = "60s"
  generic_timeout = "30s"
  icmp_timeout = "10s"
  tcp_timeout = "20s"
  tcp_fin_timeout = "5s"
  tcp_rst_timeout = "5s"
  udp_timeout = "60s"
}

# Parser configuration for eBPF packet parsing
# Configure tunnel port detection (defaults shown)
parser {
  geneve_port    = 6081   # IANA default for Geneve
  vxlan_port     = 4789   # IANA default for VXLAN
  wireguard_port = 51820  # IANA default for WireGuard
}

# OTLP exporter configuration
# See OBI export concepts: https://opentelemetry.io/docs/zero-code/obi/configure/export-data/
export "traces" {
  stdout = "text_indent" // text, text_indent(*new), json, json_indent

  // otlp = {
  //   endpoint = "http://otelcol:4317"
  //   protocol = "grpc"
  //   timeout  = "10s"

  //   auth = {
  //     basic = {
  //       user = "USERNAME"
  //       pass = env("USER_SPECIFIED_ENV_VAR_TRITON_PASS")
  //     }
  //   }

  //   tls = {
  //     insecure    = false
  //     ca_cert     = "/etc/certs/ca.crt"
  //     client_cert = "/etc/certs/cert.crt"
  //     client_key  = "/etc/certs/cert.key"
  //   }
  // }
}
