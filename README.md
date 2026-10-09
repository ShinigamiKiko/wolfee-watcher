<div align="center">
  <img src="docs/logo.png" alt="Wolfee-Watcher" width="340">

  <p>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
    <img src="https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&amp;logoColor=white" alt="Go 1.25">
    <img src="https://img.shields.io/badge/Kubernetes-runtime_security-326CE5?logo=kubernetes&amp;logoColor=white" alt="Kubernetes runtime security">
    <img src="https://img.shields.io/badge/Helm_chart-2.0.0-0F1689?logo=helm&amp;logoColor=white" alt="Helm chart 2.0.0">
  </p>

  <h3>Runtime security for Kubernetes, from one console</h3>

  <p>Wolfee-Watcher watches what runs in your clusters, who changes them and what they are built from,
  and lets you reconstruct an incident without shelling into a node. One hub UI, any number of clusters,
  mandatory mTLS between every component.</p>
</div>

## How Wolfee-Watcher Sees a Cluster

- **Runtime** — Tracee (eBPF) on every node reports syscalls, tracepoints and LSM hooks; `tracee-bridge` streams them through Kafka to the rule engine and the anomaly detector.
- **Kubernetes API** — `sentry-audit` is a validating admission webhook for creates, updates, deletes, `exec`, `attach` and `port-forward`; it can also tail the kube-apiserver audit log for reads, users and source IPs.
- **Supply chain** — `scanner-agent` scans every image running in the cluster with Trivy, adds EPSS, CISA KEV, public PoCs and FSTEC BDU, and keeps a package inventory.
- **Cluster state** — `sensor` keeps a live snapshot of workloads, RBAC, network policies, secrets metadata and webhooks for posture checks and configuration views.
- **Deception and forensics** — `honey-operator` deploys honeypots, and `forensic-watcher` keeps per-pod file changes and binary exec history that survive the pod.

## Features

- 🛡️ **Runtime policies**: syscall, binary, tracepoint and LSM-hook rules evaluated on the live event stream.
- 🧠 **Anomaly detection**: per-deployment baselines flag unexpected binaries, fileless execution, raw sockets, process injection, namespace escapes and binary tampering.
- 📜 **Kubernetes audit logs**: monitoring and investigation views, audit checks grouped by risk, silences, per-user rollups and a configurable retention.
- 🔍 **Vulnerability management**: CVEs by image, workload and node, risk score from CVSS and EPSS, KEV and PoC flags, fixable counts, SBOM and FSTEC BDU mapping.
- 📋 **Compliance and posture**: CIS, FSTEC, NIST, PCI DSS and HIPAA controls, plus Build and Deploy policies evaluated server-side.
- 🍯 **Honeypots**: decoy services inside the cluster that record connections and login attempts.
- 🧪 **Forensics**: per-pod syscall watch, file change history, container logs and TAR export.
- 🌐 **Network**: network policy graph, policy viewer and network anomaly events.
- 🏢 **Multi-cluster**: one hub UI for every cluster, data shared in one PostgreSQL or kept in a dedicated database per cluster.
- 🔔 **Alerting**: Discord, Mattermost and Jira integrations with a durable delivery queue and retries; Harbor as an image source.
- 🔐 **Secure by default**: mTLS everywhere with certificates rotated by `cert-server`, least-privilege database roles, network policies and admin / read-only accounts.

![Wolfee-Watcher architecture](docs/architecture.svg)

The diagram shows a cluster connected as an edge to an external kvisior hub and the shared
PostgreSQL. Without a hub, `kvisior-ui` is the only UI and PostgreSQL can run in the cluster.

## Table of Contents

- [Get Started](#get-started)
  - [Standalone Cluster](#standalone-cluster)
  - [Hub with Many Clusters](#hub-with-many-clusters)
- [Detection](#detection)
- [Alerts and Integrations](#alerts-and-integrations)
- [Multi-Cluster](#multi-cluster)
- [Configuration](#configuration)
- [FSTEC Database](#fstec-database)
- [Production Notes](#production-notes)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## Get Started

Wolfee-Watcher runs in two shapes. A **standalone cluster** has its own UI and database inside the
cluster. A **hub** serves one UI for many clusters: each cluster runs the chart as an *edge* that
collects and writes its data, and the hub shows everything.

### Standalone Cluster

Requirements: a Kubernetes cluster on containerd (k3s works best; Tracee is a privileged eBPF
DaemonSet with `hostPID`), plus `podman` or `docker`, `ctr`, `helm`, `kubectl`, `go` and `openssl`
on the build host.

```bash
# 1. Build every image and import it into the node's containerd
deploy/build-images.sh

# 2. Generate a CA and the per-service certificates
cd pkg/certgen && go run . -out ../../deploy/certs -namespace wolfee-watcher && cd ../..

# 3. Namespace and CA secret
kubectl create ns wolfee-watcher
kubectl apply -f deploy/certs/00-ca-key-secret.yaml -n wolfee-watcher

# 4. Install
helm install wolfee-watcher ./helm -n wolfee-watcher \
  --set namespace.create=false \
  --set global.internalPushSecret="$(openssl rand -hex 32)" \
  --set ui.ingress.enabled=true \
  --set ui.ingress.host=kvisior8.127.0.0.1.nip.io \
  --set ui.ingress.denyInternalPaths=true \
  --set networkPolicy.nodeCIDRs="{10.0.0.0/8}"
```

The initial `admin` password is printed once by the migration job:

```bash
kubectl logs -n wolfee-watcher job/central-migrate
```

Open the UI at the `ui.ingress.host` you set.

> **Tip:** on a multi-node cluster push the images to a registry with
> `deploy/build-images.sh --push <registry> --tag <tag>` and set `image.repository`, `image.tag`
> and `image.pullPolicy: IfNotPresent` for each component. The single-node default
> (`localhost/wolfee-watcher/*`, `pullPolicy: Never`) needs the image on every node.

### Hub with Many Clusters

The hub is kvisior and PostgreSQL in containers on a plain host. Clusters connect to it as edges.

```bash
# On the hub host
cd deploy/hub
cp hub.env.example hub.env                      # fill every secret: openssl rand -hex 24
./pki.sh /srv/wolfee <hub-ip> <edge-ip> ...     # private CA, PostgreSQL and hub certificates
./pg-firewall.sh <edge-ip> <hub-ip> <pod-cidr>  # allow-list PostgreSQL
podman-compose --env-file hub.env up -d         # or docker compose

# From any machine with kubectl, helm and SSH to the hub
deploy/edge/install.sh                          # one edge per kubeconfig, asks as it goes
```

- The hub UI listens on `https://<hub-ip>:8443`; edges serve no UI of their own.
- Every edge writes its data straight into its database; the hub reads it and reaches the edge
  over federation (`:30443`) only for live views.
- A cluster can keep its data in a dedicated PostgreSQL on another host:
  `deploy/hub/add-cluster-db.sh` prepares the database, its certificate and the hub route.

See [`deploy/hub/README.md`](deploy/hub/README.md) for the full walkthrough.

## Detection

Policies are created in **Policy Management** and apply to every cluster connected to the hub.

| Type | Evaluated on | Example |
|---|---|---|
| Runtime — syscall | Tracee syscall events | `setns` from a workload pod |
| Runtime — binary | process and path | `nc` started anywhere in `production` |
| Tracepoint | kernel tracepoints | kernel module load |
| LSM hook | LSM decisions | `security_inode_unlink` on a system binary |
| Build | image layers and registry | image not from a trusted registry, `curl \| sh` in a layer |
| Deploy | workload specs | privileged container, `hostPID`, missing limits |
| Audit | Kubernetes API activity | `exec` into a pod, ClusterRoleBinding created |

Matches become **violations** with severity, workload and evidence. A policy marked **Alert** also
produces an **alert**. False positives can be marked per instance or silenced per category.

> **Note:** the anomaly detector works without policies: it learns a baseline per deployment during
> the observation period and reports deviations on its own.

## Alerts and Integrations

Alerts from every source land in the **Alert Log** and fan out to the integrations configured in
**Settings → Integrations**:

| Integration | Purpose |
|---|---|
| Discord | alert messages to a channel webhook |
| Mattermost | alert messages to an incoming webhook |
| Jira | an issue for every anomaly |
| Harbor | registry credentials the scanner uses to pull images for Trivy |

Delivery is durable: each alert is queued in PostgreSQL, retried with backoff and marked delivered
once accepted, so a webhook outage does not lose alerts.

## Multi-Cluster

Every row carries a `cluster_id` taken from the agent's mTLS certificate, and the hub UI has a
cluster switcher. Two storage layouts can be mixed:

1. **Shared database** — every edge writes into the hub's PostgreSQL. Simple, suits a few clusters.
2. **Dedicated database per cluster** — a cluster writes into its own PostgreSQL on any host. The hub
   opens a connection pool per cluster from `clusters/databases.conf` (reloaded every 15 s) and copies
   policies, audit rules and retention settings into it.

Accounts, sessions, policies and the cluster list always live in the hub database.

> **Note:** clusters move to a dedicated database one at a time; data already written to the shared
> database stays there.

See [`docs/multicluster.md`](docs/multicluster.md) and [`deploy/hub/README.md`](deploy/hub/README.md).

## Configuration

The Helm chart is the single source of truth. The values most edge installs set:

```yaml
global:
  clusterId: prod-eu-1                    # stable, unique, DNS-label; stamped into every row and certificate
  internalPushSecret: ${PUSH_SECRET}      # required; an empty value fails the install
  federationToken: ${FED_TOKEN}           # shared with the hub (hub.env FEDERATION_TOKEN)

postgres:
  enabled: false                          # true runs PostgreSQL inside the cluster (standalone)
  external:
    enabled: true
    host: 10.20.0.5                       # hub database or the cluster's dedicated database
    port: 5432
    sslMode: verify-ca
    caBundle: |                           # hub CA (/srv/wolfee/pki/ca.crt)
      -----BEGIN CERTIFICATE-----
  serviceCredentials:                     # one least-privilege role per service
    ui: { user: ww_ui, password: ${PG_UI_PASSWORD} }
    traceeBridge: { user: ww_tracee_bridge, password: ${PG_TRACEE_BRIDGE_PASSWORD} }
    anomaly: { user: ww_anomaly, password: ${PG_ANOMALY_PASSWORD} }

ui:
  ingress:
    enabled: false                        # standalone only; edges are viewed from the hub
  advertiseURL: https://10.20.0.10:30443  # where the hub reaches this cluster
  federation:
    nodePort: 30443
    allowedSources: [10.20.0.1/32]        # the hub address

kafka:
  replicaCount: 3                         # 1 on a single node, with replicationFactor and minIsr 1
  replicationFactor: 3
  minIsr: 2

networkPolicy:
  nodeCIDRs: [10.0.0.0/8]                 # where Tracee and the API server reach the cluster from
```

**Explanation:**

1. `global.clusterId` names the cluster everywhere: rows, client certificates and the UI switcher.
2. `global.internalPushSecret` authenticates `/internal/push/*`; the chart refuses to render without it.
3. `postgres.external` points the edge at its database; with `sslMode: verify-ca` the `caBundle` is mounted into every pod.
4. `serviceCredentials` give each writer its own role; the passwords come from `hub.env` or from `add-cluster-db.sh`.
5. `ui.ingress` is off unless set, so a cluster connected to a hub exposes no UI.
6. `networkPolicy.nodeCIDRs` is required outside Cilium; on Cilium the chart allows node entities and also restricts egress.

The full reference with every value is in [`DEPLOY.md`](DEPLOY.md) and [`helm/values.yaml`](helm/values.yaml).

## FSTEC Database

The FSTEC BDU database is not included in this repository. To enable BDU enrichment, download the
latest database file from the official FSTEC website and make it available to `scanner-agent`.

## Production Notes

- **Own your CA.** The test CA in `deploy/certs/` has its key committed: development only.
- **mTLS is mandatory.** There is no plaintext fallback; pods refuse to start without CA material.
- **Install with Helm only, without `--wait`.** The `central-migrate` hook and the pods'
  `wait-for-schema` init containers deadlock under `--wait`.
- **The schema belongs to `central-migrate`.** It applies the DDL, seeds `admin` and creates one role
  per service; only `kvisior` and `anomaly-detector` hold broad database access, and `tracee-bridge`
  writes directly only when Central is down.
- **Network policies are on by default.** Every component accepts traffic only from its callers. On
  Cilium egress is limited to DNS, the namespace, the API server and PostgreSQL; `kvisior-ui` and
  `anomaly-detector` may reach integrations on `networkPolicy.cilium.integrations.ports` and
  `global.integrations.allowedCIDRs`. Add anything else with `networkPolicy.cilium.extraEgress.<component>`.
- **Size Kafka and PostgreSQL** for the event rate: three Kafka brokers with `minIsr: 2` survive a
  broker restart, and busy clusters belong in a dedicated database.

> **Warning:** on a hub set `ADMIN_BOOTSTRAP_PASSWORD` in `hub.env` before the first `up`, or read the
> generated one-time password from the first migration log.

## Documentation

- [`DEPLOY.md`](DEPLOY.md) — deployment reference, step by step
- [`deploy/hub/README.md`](deploy/hub/README.md) — hub host, edges and dedicated cluster databases
- [`docs/multicluster.md`](docs/multicluster.md) — cluster identity and database scaling
- [`docs/audit-logs.md`](docs/audit-logs.md) — Kubernetes audit sources, rules and retention
- [`docs/audit-delivery.md`](docs/audit-delivery.md) — durable audit event delivery
- [`docs/logging.md`](docs/logging.md) — structured logs and alert context
- [`docs/api/tracee-events-query.md`](docs/api/tracee-events-query.md) — runtime event query API
- [`helm/UPGRADE.md`](helm/UPGRADE.md) — upgrade notes

## Contributing

Each service is its own Go module and the React UI ships inside `kvisior`. Build, layout and
conventions are in [`CONTRIBUTING.md`](CONTRIBUTING.md). Please report vulnerabilities privately as
described in [`SECURITY.md`](SECURITY.md).

---

## License

Wolfee-Watcher is licensed under the Apache License 2.0. See [`LICENSE`](LICENSE).
