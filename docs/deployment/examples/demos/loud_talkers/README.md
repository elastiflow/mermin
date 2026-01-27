# Mermin Loud Talkers Demo

Demonstrate Mermin's ability to identify high-traffic applications ("loud talkers") in your cluster.

## Prerequisites

- Docker, kind, kubectl, helm ([install links](https://docs.docker.com/get-docker/), [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation), [kubectl](https://kubernetes.io/docs/tasks/tools/), [helm](https://helm.sh/docs/intro/install/))

## Usage

```bash
cd docs/deployment/examples/demos/loud_talkers
./demo.sh
```

It takes ~2-3 minute to start up. The script sets up a Kind cluster, deploys Mermin, NetObserv, OpenSearch, and OpenSearch Dashboards, and starts traffic generation.

## Accessing Dashboards

- URL: http://localhost:5601
- Username: `admin`
- Password: `Elast1flow!`
- Select "global tenant" on first login

Look for the `traffic-generator` pod as the loudest talker in network flow visualizations.

## Cleanup

```bash
CLEANUP=true ./demo.sh
```

Or manually: `kind delete cluster --name mermin-demo-loud-talkers`
