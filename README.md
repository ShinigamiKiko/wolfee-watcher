<p align="center">
  <img src="docs/logo.png" alt="Wolfee-Watcher" width="340">
</p>

<p align="center">Kubernetes runtime-security platform — one central UI/backend surrounded by security agents, all talking over mandatory mTLS.</p>

---

A central service (`kvisior`) serves the React UI and proxies to a set of Go
agents that watch the cluster: eBPF syscalls (via Tracee), Kubernetes audit
events, file/forensic changes, image vulnerabilities, honeypots, and behavioural
anomalies. Every service-to-service call is mTLS with certificates issued and
rotated by `cert-server`. Deployment is a single Helm chart into the
`wolfee-watcher` namespace.

## Architecture

![Wolfee-Watcher architecture](docs/architecture.svg)

The diagram shows a cluster connected as an edge to an external kvisior hub and
the shared PostgreSQL. Without a hub, kvisior-ui is the only UI and PostgreSQL
can run in the cluster.

## Features

In addition to Kubernetes audit monitoring, Wolfee-Watcher includes:

- **Honeypots** for recording connections and login attempts.
- **Container forensics** with file change history, logs, and TAR export.
- **Syscall monitoring** through Tracee/eBPF, with filters by pod and event.
- **Tracepoints** for kernel events such as module loading and process switches.
- **LSM hooks** for monitoring file, process, socket, and BPF operations inside
  the kernel.
- **FSTEC BDU mapping** for matching detected CVEs with BDU records.

### FSTEC database

The database is not included in this repository. To enable FSTEC enrichment,
download the latest database file from the official FSTEC website and make it
available to `scanner-agent`.
One kvisior and one PostgreSQL can serve several clusters: every row carries a
`cluster_id` taken from the pushing agent's certificate, and the UI has a cluster
switcher. See [`docs/multicluster.md`](docs/multicluster.md).

## Quick start (single-node dev)

```bash
# 1. Build all images and import them into the node's containerd
./1.sh

# 2. Generate a CA + per-service certs
cd pkg/certgen && go run . -out ../../deploy/certs -namespace wolfee-watcher && cd ../..

# 3. Namespace + CA secret
kubectl create ns wolfee-watcher
kubectl apply -f deploy/certs/00-ca-key-secret.yaml -n wolfee-watcher

# 4. Install
helm install wolfee-watcher ./helm -n wolfee-watcher \
  --set namespace.create=false \
  --set global.internalPushSecret="$(openssl rand -hex 32)" \
  --set ui.ingress.enabled=true   --set ui.ingress.host=kvisior8.127.0.0.1.nip.io \
  --set ui.ingress.denyInternalPaths=true \
  --set networkPolicy.nodeCIDRs="{10.0.0.0/8}"
```

The initial admin password is printed once in the migrate Job log:

```bash
kubectl logs -n wolfee-watcher job/central-migrate
```

Open the UI at the `ui.ingress.host` you set. The ingress is off by default:
a cluster connected to a hub serves no UI of its own and is viewed from the
hub, so enable it only for a standalone cluster.

## Production notes

- **Multi-node:** build and push images to a registry, then set
  `image.repository`, `image.tag`, and `image.pullPolicy: IfNotPresent`. The
  single-node default (`localhost/wolfee-watcher/*`, `pullPolicy: Never`)
  requires the image to exist on each node.
- **`global.internalPushSecret` is required** — an empty value disables auth on
  the `/internal/push/*` endpoints, so the install fails closed.
- **Network policies** are on by default. Every component accepts traffic only
  from the components that call it. Tracee (hostNetwork) and the API server reach
  `tracee-bridge:8080` and the sentry-audit webhook from node addresses: on Cilium
  the chart allows the node entities, elsewhere set `networkPolicy.nodeCIDRs`
  (and `networkPolicy.apiServerCIDRs` for a managed control plane), otherwise the
  render fails. On Cilium the chart also restricts egress: DNS, the namespace,
  the API server and PostgreSQL; scanner-agent may reach the internet on 443 and
  audit-runner reaches avd.aquasec.com. Integrations are configured in the UI at
  run time, so kvisior-ui and anomaly-detector, which deliver to them, may reach
  the internet on the ports in `networkPolicy.cilium.integrations.ports` (443 by
  default; an empty list closes it) and the networks in
  `global.integrations.allowedCIDRs`. Add federation peers and anything else with
  `networkPolicy.cilium.extraEgress.<component>`.
- **mTLS is mandatory** — no plaintext fallback. Missing CA material means pods
  refuse to start.
- **Install via Helm only**, and **not** with `--wait`: the `central-migrate`
  hook and the pods' `wait-for-schema` init deadlock under `--wait`.
- **Own your CA.** The test CA in `deploy/certs/` has its key committed — dev
  only, never production.
- Review before real use: Postgres password/`sslmode`, per-service DB
  credentials, image tags, Kafka replication, and HA (replicas, PDBs).

The schema is owned by the `central-migrate` Job: it applies DDL, seeds the
`admin` account, and creates one least-privilege role per service. Only
`kvisior` and `anomaly-detector` hold direct DB access; `tracee-bridge` writes
to Postgres only as a fallback when Central is down.

## Docs

- [`DEPLOY.md`](DEPLOY.md) — full deployment reference
- [`helm/UPGRADE.md`](helm/UPGRADE.md) — upgrade notes
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — build, layout, conventions
- [`SECURITY.md`](SECURITY.md) — reporting vulnerabilities
