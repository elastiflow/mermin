export "traces" {
  stdout = {
    format = "text_indent" # text, text_indent(*new), json, json_indent
  }

  # otlp = {
  #   endpoint = "http://otel-collector:4317" # Uncomment to export to an OTel Demo Collector

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

# Test configuration optimized for fast CI runs
# Reduce flow export intervals for faster test feedback
span {
  max_record_interval = "10s" # Export active flows every 10s (default: 60s)
  icmp_timeout        = "5s"  # ICMP flows timeout after 5s (default: 10s)
}
