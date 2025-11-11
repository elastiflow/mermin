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

# TODO(mack#ENG-286|2025-11-04): attributes "source" and "destination" sections should be gone
# Source attributes - maps flow source data to K8s resources
attributes "source" "k8s" {
  extract {
    metadata = [
      "[*].metadata.name",      # All kinds, metadata.name
      "[*].metadata.namespace", # All kinds, metadata.namespace
      "[*].metadata.uid",       # All kinds, metadata.uid (if present)
    ]
  }

  association {
    pod = {
      sources = [
        {
          from = "flow", name = "source.ip",
          to   = ["status.podIP", "status.podIPs[*]", "status.hostIP", "status.hostIPs[*]"]
        },
        {
          from = "flow", name = "source.port",
          to   = ["spec.containers[*].ports[*].containerPort", "spec.containers[*].ports[*].hostPort"]
        },
        { from = "flow", name = "network.transport", to = ["spec.containers[*].ports[*].protocol"] },
      ]
    }
    node = {
      sources = [
        { from = "flow", name = "source.ip", to = ["status.addresses[*].address"] },
      ]
    }
    service = {
      sources = [
        {
          from = "flow", name = "source.ip", to = [
            "spec.clusterIP", "spec.clusterIPs[*]", "spec.externalIPs[*]", "spec.loadBalancerIP", "spec.externalName"
          ]
        },
        { from = "flow", name = "source.port", to = ["spec.ports[*].port"] },
        { from = "flow", name = "network.transport", to = ["spec.ports[*].protocol"] },
        { from = "flow", name = "network.type", to = ["spec.ipFamilies[*]"] },
      ]
    }
    endpoint = {
      sources = [
        { from = "flow", name = "source.ip", to = ["subsets[*].addresses[*].ip"] },
        { from = "flow", name = "source.port", to = ["subsets[*].ports[*].port"] },
        { from = "flow", name = "network.transport", to = ["subsets[*].ports[*].protocol"] },
      ]
    }
    endpointslice = {
      sources = [
        { from = "flow", name = "source.ip", to = ["endpoints[*].addresses[*]"] },
        { from = "flow", name = "source.port", to = ["ports[*].port"] },
        { from = "flow", name = "network.transport", to = ["ports[*].protocol"] },
        { from = "flow", name = "network.type", to = ["addressType"] },
      ]
    }
    ingress = {
      sources = [
        {
          from = "flow", name = "source.ip",
          to   = ["status.loadBalancer.ingress[*].ip", "status.loadBalancer.ingress[*].hostname"]
        },
        {
          from = "flow", name = "source.port",
          to   = ["spec.defaultBackend.service.port", "spec.rules[*].http.paths[*].backend.service.port.number"]
        }
      ]
    }
    gateway = {
      sources = [
        { from = "flow", name = "source.ip", to = ["spec.addresses[*].value", "status.addresses[*].value"] },
        { from = "flow", name = "source.port", to = ["spec.listeners[*].port"] },
      ]
    }
    networkpolicy = {
      sources = [
        {
          from = "flow", name = "source.ip",
          to   = ["spec.ingress[*].from[*].ipBlock.cidr", "spec.egress[*].to[*].ipBlock.cidr"]
        },
        { from = "flow", name = "source.port", to = ["spec.ingress[*].ports[*].port", "spec.egress[*].ports[*].port"] },
        {
          from = "flow", name = "network.transport",
          to   = ["spec.ingress[*].ports[*].protocol", "spec.egress[*].ports[*].protocol"]
        },
      ]
    }
  }
}

# Destination attributes - maps flow destination data to K8s resources
attributes "destination" "k8s" {
  extract {
    metadata = [
      "[*].metadata.name",      # All kinds, metadata.name
      "[*].metadata.namespace", # All kinds, metadata.namespace
      "pod.metadata.uid",       # All kinds, metadata.uid
    ]
  }

  association {
    pod = {
      sources = [
        {
          from = "flow", name = "destination.ip",
          to   = ["status.podIP", "status.podIPs[*]", "status.hostIP", "status.hostIPs[*]"]
        },
        {
          from = "flow", name = "destination.port",
          to   = ["spec.containers[*].ports[*].containerPort", "spec.containers[*].ports[*].hostPort"]
        },
        { from = "flow", name = "network.transport", to = ["spec.containers[*].ports[*].protocol"] },
      ]
    }
    node = {
      sources = [
        { from = "flow", name = "destination.ip", to = ["status.addresses[*].address"] },
      ]
    }
    service = {
      sources = [
        {
          from = "flow", name = "destination.ip", to = [
            "spec.clusterIP", "spec.clusterIPs[*]", "spec.externalIPs[*]", "spec.loadBalancerIP", "spec.externalName"
          ]
        },
        { from = "flow", name = "destination.port", to = ["spec.ports[*].port"] },
        { from = "flow", name = "network.transport", to = ["spec.ports[*].protocol"] },
        { from = "flow", name = "network.type", to = ["spec.ipFamilies[*]"] },
      ]
    }
    endpoint = {
      sources = [
        { from = "flow", name = "destination.ip", to = ["subsets[*].addresses[*].ip"] },
        { from = "flow", name = "destination.port", to = ["subsets[*].ports[*].port"] },
        { from = "flow", name = "network.transport", to = ["subsets[*].ports[*].protocol"] },
      ]
    }
    endpointslice = {
      sources = [
        { from = "flow", name = "destination.ip", to = ["endpoints[*].addresses[*]"] },
        { from = "flow", name = "destination.port", to = ["ports[*].port"] },
        { from = "flow", name = "network.transport", to = ["ports[*].protocol"] },
      ]
    }
    ingress = {
      sources = [
        {
          from = "flow", name = "destination.ip",
          to   = ["status.loadBalancer.ingress[*].ip", "status.loadBalancer.ingress[*].hostname"]
        },
        {
          from = "flow", name = "destination.port",
          to   = ["spec.defaultBackend.service.port", "spec.rules[*].http.paths[*].backend.service.port.number"]
        }
      ]
    }
    gateway = {
      sources = [
        { from = "flow", name = "destination.ip", to = ["spec.addresses[*].value", "status.addresses[*].value"] },
        { from = "flow", name = "destination.port", to = ["spec.listeners[*].port"] },
      ]
    }
    networkpolicy = {
      sources = [
        {
          from = "flow", name = "destination.ip",
          to   = ["spec.ingress[*].from[*].ipBlock.cidr", "spec.egress[*].to[*].ipBlock.cidr"]
        },
        {
          from = "flow", name = "destination.port",
          to   = ["spec.ingress[*].ports[*].port", "spec.egress[*].ports[*].port"]
        },
        {
          from = "flow", name = "network.transport",
          to   = ["spec.ingress[*].ports[*].protocol", "spec.egress[*].ports[*].protocol"]
        },
      ]
    }
  }
}
