# lpt stands for local performance testing

red := $(shell tput setaf 1)
green := $(shell tput setaf 2)
yellow := $(shell tput setaf 3)
sgr0 := $(shell tput sgr0)
define log_info
    @echo "\n${green}[INFO]${sgr0} ${1}"
endef
define log_warn
    @echo "\n${yellow}[WARN]${sgr0} ${1}"
endef
define log_error
    @echo "\n${red}[ERROR]${sgr0} ${1}"
endef

#########################################
# Kind cluster management
#########################################
.PHONY: lpt-kind-delete
lpt-kind-delete:
	$(call log_warn,Deleting kind cluster)
	@kind delete clusters atlantis

.PHONY: lpt-kind-create
lpt-kind-create:
	$(call log_info,Creating kind cluster)
	@kind create cluster --config docs/deployment/examples/local/kind-config.yaml

#########################################
# Mermin build
#########################################
.PHONY: lpt-build
lpt-build:
	$(call log_info,Building debug mermin:latest image)
	@docker build --progress plain -t mermin:latest --target runner-debug ./
	@kind load docker-image mermin:latest --name atlantis

.PHONY: lpt-build-restart
lpt-build-restart: lpt-build
	$(call log_info,Restarting Mermin daemonset to pick up new image)
	@kubectl rollout restart daemonset/mermin -n default
	@kubectl rollout status --watch --timeout 120 daemonset/mermin -n default

#########################################
# Mermin deployment
#########################################
.PHONY: lpt-mermin
lpt-mermin:
	$(call log_info,Installing Mermin helm chart)
	$(MAKE) helm-upgrade HELM_EXTRA_ARGS='--set-file config.content=docs/deployment/examples/local/config.example.hcl'


.PHONY: lpt-mermin-otel
lpt-mermin-otel: lpt-otel
	$(call log_info,Installing Mermin helm chart with OpenTelemetry)
	$(MAKE) helm-upgrade HELM_EXTRA_ARGS='--set-file config.content=docs/deployment/examples/local-otel/config.hcl'

.PHONY: lpt-otel
lpt-otel:
	$(call log_info,Installing OpenTelemetry Collector)
	helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
	helm upgrade --install --wait --timeout 120s -n default \
		-f docs/deployment/examples/local-otel/values_otel.yaml \
		otel-collector open-telemetry/opentelemetry-collector

#########################################
# Monitoring and sample app deployment
#########################################
.PHONY: lpt-mon
lpt-mon:
	$(call log_info,Deploying monitoring stack)
	@kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/download/v0.8.0/components.yaml
	@kubectl -n kube-system patch deployment metrics-server --type='json' -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]'
	@helm repo add prometheus https://prometheus-community.github.io/helm-charts
	@helm upgrade --install --wait --timeout 300s -n prometheus --create-namespace \
		-f docs/deployment/examples/local/values_prom_stack.yaml \
		prometheus prometheus/kube-prometheus-stack
	@kubectl -n prometheus patch sts prometheus-grafana \
		--type="json" -p='[{"op":"replace","path":"/spec/persistentVolumeClaimRetentionPolicy/whenDeleted", "value": "Delete"}]'

.PHONY: lpt-sample-be
lpt-sample-be:
	$(call log_info,Deploying sample backend)
	@helm repo add podinfo https://stefanprodan.github.io/podinfo
	@helm upgrade --install --wait --timeout 120s --create-namespace \
		--namespace default \
		--set replicaCount=2 \
		--set redis.enabled=true \
		backend podinfo/podinfo

.PHONY: lpt-traffic-gen
lpt-traffic-gen:
	$(call log_info,Deploying traffic generator)
	@helm upgrade --install --wait --timeout 120s --create-namespace \
		--namespace default \
		traffic-gen charts/traffic-gen

.PHONY: lpt-doc
lpt-doc:
	$(call log_info,To expose grafana run:)
	@echo "	until kubectl -n prometheus port-forward svc/prometheus-grafana 3000:3000; do sleep 3; done"
	$(call log_info,To expose prometheus (for debug) run:)
	@echo "	until kubectl -n prometheus port-forward svc/prometheus-kube-prometheus-prometheus 9090:9090; do sleep 3; done"
	$(call log_info,To sample backend run:)
	@echo "	until kubectl -n netdumb port-forward svc/backend-podinfo 9080:9898; do sleep 3; done"

########################
# Convenience targets
########################
.PHONY: lpt-up
lpt-up: lpt-build lpt-mon lpt-mermin lpt-sample-be lpt-traffic-gen lpt-doc
