# OTLP exporter configuration
# See OBI export concepts: https://opentelemetry.io/docs/zero-code/obi/configure/export-data/
export "traces" {
//   Uncomment to receive spans in STDOUT
//   stdout = {
//     format = "text_indent" // text, text_indent(*new), json, json_indent
//   }

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
