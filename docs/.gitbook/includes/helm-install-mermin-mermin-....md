---
title: helm install mermin mermin/...
---

```
helm install mermin mermin/mermin \
  --namespace elastiflow \
  --version 0.1.0-beta.16 \
  --set image.repository=ghcr.io/elastiflow/mermin \
  --set image.tag=v0.1.0-beta.16 \
  --set imagePullSecrets[0].name=ghcr \
  --set-file config.content=mermin-config.hcl \
  --wait

# Verify deployment
kubectl -n elastiflow get pods -l app.kubernetes.io/name=mermin
```
