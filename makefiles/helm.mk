# Makefile is intended for a local use only for development and testing purposes

###########################
# Docker/Versioning vars
###########################
K8S_ROLLOUT_TIMEOUT=600s

##############
# Helm vars
##############
HELM_CHART?="charts/mermin"
HELM_CHART_VERSION?=
HELM_OUTPUT_DIR_PREFIX?=helm_rendered
HELM_OUTPUT_DIR?=${HELM_OUTPUT_DIR_PREFIX}/mermin/templates
HELM_NAMESPACE?=default
HELM_VALUES=docs/deployment/examples/local/values.yaml
HELM_CHART_VERSION_ARG=$(if $(HELM_CHART_VERSION),--version ${HELM_CHART_VERSION})
define HELM_ARGS
	${HELM_CHART_VERSION_ARG} \
	-n ${HELM_NAMESPACE} \
	--create-namespace \
	--values ${HELM_VALUES}
endef
EXTRA_HELM_ARGS?=

#######################
# Deployment targets
#######################
.PHONY: helm-template
helm-template:
	rm -rf ${HELM_OUTPUT_DIR_PREFIX}
	helm template ${APP} ${HELM_CHART} \
		--output-dir ${HELM_OUTPUT_DIR_PREFIX} \
		${HELM_ARGS} ${EXTRA_HELM_ARGS}

.PHONY: helm-template-silent
helm-template-silent:
	@rm -rf ${HELM_OUTPUT_DIR_PREFIX} > /dev/null
	@helm template ${APP} ${HELM_CHART} \
		--output-dir ${HELM_OUTPUT_DIR_PREFIX} \
		${HELM_ARGS} ${EXTRA_HELM_ARGS} > /dev/null

.PHONY: helm-upgrade
helm-upgrade:
	helm upgrade \
		--install --wait --timeout 10m \
		${HELM_ARGS} ${EXTRA_HELM_ARGS} \
		${APP} ${HELM_CHART}

.PHONY: k8s-diff
k8s-diff: helm-template-silent
	@# kubectl diff exist codes: 0 - no diff, 1 - there is a diff, 2 - something is wrong
	@# Since exit code 1 is failure, make will always fail if there is a diff, so code modification required
	@find ${HELM_OUTPUT_DIR}/ -type f -name 'helm_hook_job.yaml' -exec rm {} \;
	@kubectl diff -f ${HELM_OUTPUT_DIR}/ || (st=$$?; if [ $$st = 1 ]; then exit 0; else echo $$st; exit $$st; fi)

.PHONY: k8s-rollout-status
k8s-rollout-status: helm-template-silent
	rm -f ${HELM_OUTPUT_DIR}/secretproviderclass.yaml \
		${HELM_OUTPUT_DIR}/podmonitoring.yaml \
		${HELM_OUTPUT_DIR}/redpanda_topic.yaml \
		${HELM_OUTPUT_DIR}/certificate.yaml
	kubectl -n ${HELM_NAMESPACE} rollout status -f ${HELM_OUTPUT_DIR}/daemonset.yaml \
		--timeout=${K8S_ROLLOUT_TIMEOUT}

.PHONY: k8s-get
k8s-get: helm-template-silent
	kubectl get -f ${HELM_OUTPUT_DIR}
