# Deploying Wolfee-Watcher from scratch

This guide describes how to stand up the full platform on a fresh cluster.

The deployment is built for a **single-node cluster running containerd**: the
`1.sh` script builds every image with `podman` and imports it straight into
containerd (`ctr -n k8s.io images import`), and the Helm chart references those
images as `localhost/wolfee-watcher/*:latest` with `pullPolicy: Never`.

## 0. Prerequisites

- A **Kubernetes cluster on containerd**, ideally single-node — **k3s** works best.
  `kind`/`minikube` are harder because `tracee` is a **privileged eBPF DaemonSet
  with `hostPID`** and needs real host-kernel access.
- Tools on the build host: `podman`, `ctr`, `helm`, `kubectl`, `go`, `openssl`.
- Outbound network for images that are pulled (not pre-imported): `postgres:16-alpine`,
  `apache/kafka`, and the grype vulnerability DB used by `scanner-agent`.

## 1. Build and import the images

```bash
cd /path/to/evil-watcher
./1.sh        # builds 12 localhost/wolfee-watcher/*:latest images and imports them into containerd
```

> Multi-node note: `pullPolicy: Never` means the images must exist on every node.
> For more than one node, push to a real registry and override
> `image.repository` / `image.pullPolicy` in `helm/values.yaml`.

### Shared Go modules (`pkg/`)

The mTLS service mesh is implemented once in the shared module
**`pkg/mtls`** (TLS 1.3, `RequireAndVerifyClientCert`, dynamic cert rotation
via `cert-server`, identity-pinned clients, graceful shutdown). Every service
depends on it through `require … pkg/mtls` + `replace => ../pkg/mtls`, mirroring
`pkg/alerts`. There are no per-service copies.

Because the binaries import `../pkg/mtls`, their **Docker build context is the
repo root** (not the service directory): each `Dockerfile` copies `<svc>/` plus
`pkg/` and a `go.work.docker` workspace file. `1.sh` already passes the repo
root as the context — keep that if you add or re-wire a service.

## 2. mTLS / CA

Services fetch their certificates dynamically from `cert-server` (the default
`global.certServerAddr` is already set). `cert-server` only needs a Secret named
`wolfee-watcher-ca` holding the CA cert+key. Pick **one** path:

### Path A — generate your own CA (recommended)

`pkg/certgen` is a **separate Go module**, so run it from inside its directory
and point `-out` at the repo's `deploy/certs`:

```bash
cd pkg/certgen
go run . -out ../../deploy/certs -namespace wolfee-watcher
cd ../..          # back to repo root — the paths below are relative to it
kubectl create namespace wolfee-watcher
kubectl apply -f deploy/certs/00-ca-key-secret.yaml -n wolfee-watcher
```

This regenerates `deploy/certs/`:
- `00-ca-key-secret.yaml` → Secret `wolfee-watcher-ca` (cert **+ key**) — the only
  one `cert-server` needs;
- `00-ca-secret.yaml` → Secret `wolfee-watcher-ca-pub` (cert only);
- `01-*` … `09-*` → per-service Secrets, used **only** for static mTLS
  (`MTLS_CA_FILE`, no cert-server). With dynamic issuance you can ignore them.

### Path B — quick test only

Apply the test CA already committed in `deploy/certs/`. **Local/dev only — never
production** (the key is public in git):

```bash
kubectl create namespace wolfee-watcher
kubectl apply -f deploy/certs/00-ca-key-secret.yaml -n wolfee-watcher
```

> The in-cluster `caBootstrap` Job (`--set caBootstrap.enabled=true`) is **not
> wired up** in this repo yet: there is no `certgen` image build, and `certgen`
> currently writes Secret YAML to disk rather than creating them via the K8s API.
> Use Path A or B until that Job is finished.

## 3. Install with Helm

The namespace was already created in step 2 (so the CA Secret could be applied
before install), so tell Helm to use it without trying to own it —
`namespace.create=false` and no `--create-namespace`:

```bash
cd helm
helm install wolfee-watcher . -n wolfee-watcher \
  --set namespace.create=false \
  --set global.internalPushSecret="$(openssl rand -hex 32)"
# grype DB IP pinning (if required):  -f overrides.yaml
cd ..
```

`global.internalPushSecret` is **required** — an empty value would disable
authentication on the `/internal/push/*` ingestion endpoints, so the chart fails
the install on purpose. For development you can bypass with
`--set global.internalPushSecretSkipValidation=true`.

Pod ordering is handled automatically: services have a `wait-for-deps`
initContainer that waits for Postgres and Kafka, and DB-using services
additionally have a `wait-for-schema` initContainer that blocks until the
`central-migrate` Job (see below) has applied the schema and created their
database role.

### Database schema & per-service roles (`central-migrate`)

The PostgreSQL schema is owned by a single component, StackRox-style: the
**`central-migrate`** Job (module `central/`) runs on every install/upgrade
as a `post-install,post-upgrade` hook. It applies all DDL
(`central/internal/schema/schema.go`), seeds the default `admin` UI account,
and creates one login role per service with least-privilege table grants
(`central/internal/schema/grants.go`). Services no longer execute any
`CREATE TABLE` themselves and connect with their own credentials
(`postgres.serviceCredentials` in `values.yaml` — override the default
passwords for anything beyond a dev cluster). The database-owner DSN
(`global.postgresDSN`) is used only by Postgres itself and this Job.

The initial UI admin password comes from `centralMigrate.adminBootstrapPassword`;
when left empty a one-shot password is generated and printed once in the Job
log: `kubectl logs -n wolfee-watcher job/central-migrate`.

The `wait-for-schema` gates check the exact schema version
(`centralMigrate.schemaVersion`, must match `central/internal/schema.Version`
— the Job fails fast on a mismatch), so on upgrades new pods wait for the
post-upgrade Job instead of starting against the previous schema or grants.

> **Do not install/upgrade with `helm --wait`.** The migrate Job runs as a
> `post-install,post-upgrade` hook, while pods block in `wait-for-schema`
> until it completes; `--wait` makes Helm wait for pod readiness *before*
> running post hooks — a mutual deadlock until the Helm timeout. Plain
> `helm install` / `helm upgrade` (as used throughout this guide) is fine.

Four agents hold **no database credentials at all**: `sentry-audit` pushes
audit events, `forensic-watcher` pushes file diffs and its node's container
logs, `sensor` pushes its snapshot cache, and `scanner-agent` pulls its Harbor
credentials — all through the UI backend's `/internal/push|pull/*` endpoints
(authenticated by `global.internalPushSecret`); kvisior persists everything
and serves the history to the UI. Agent alert rules are distributed by
kvisior (`/internal/pull/alert-rules`) and alerts delivered via
`/internal/alert-log` with `persist=true` over a bounded retry queue.
Direct PostgreSQL access remains only in kvisior (Central) and
anomaly-detector — each under its own least-privilege role. `tracee-bridge`
writes to Postgres directly only as a fallback when kvisior is unavailable.

## 4. Verify

```bash
kubectl get pods -n wolfee-watcher -w
kubectl logs -n wolfee-watcher deploy/cert-server     # issuing certs
kubectl logs -n wolfee-watcher deploy/kvisior-ui      # mTLS enabled, push endpoints
```

## 5. Access the UI

Via the Ingress (`kvisior8.<...>.nip.io` — edit the host in the chart) or directly:

```bash
kubectl port-forward -n wolfee-watcher svc/kvisior-ui 8080:80
# open http://localhost:8080
```

## Important notes

1. **mTLS is mandatory.** There is no plaintext-HTTP fallback: if
   `CERT_SERVER_ADDR` / CA material is not configured, pods refuse to start
   (CrashLoop). Installing via Helm is fine (`certServerAddr` is set by default) —
   just make sure `cert-server` comes up with its CA Secret (step 2).
2. **Install through Helm only.** The per-service raw manifests have been removed;
   `helm/` is the single source of truth. The UI's `/internal/push/*` auth comes
   from `global.internalPushSecret` (the chart fails the install if it is empty).
3. **Operator-tuned defaults** to override before real use: Postgres password and
   `sslmode`, image registry/tags, Kafka replication, and HA (replicas, PDBs).

## Minimal happy-path (k3s, own CA)

```bash
./1.sh
cd pkg/certgen && go run . -out ../../deploy/certs -namespace wolfee-watcher && cd ../..
kubectl create ns wolfee-watcher
kubectl apply -f deploy/certs/00-ca-key-secret.yaml -n wolfee-watcher
helm install wolfee-watcher ./helm -n wolfee-watcher \
  --set namespace.create=false \
  --set global.internalPushSecret="$(openssl rand -hex 32)"
kubectl port-forward -n wolfee-watcher svc/kvisior-ui 8080:80
```

## Troubleshooting

**`... exists and cannot be imported into the current release: invalid ownership
metadata`** (on the Namespace or on a Secret like `postgres-credentials`).

A previous attempt left resources behind, or you mixed Helm release names. Use
**one** release name consistently (this guide uses `wolfee-watcher`). To reset on
a test cluster:

```bash
helm uninstall wolfee-watcher -n wolfee-watcher 2>/dev/null
helm uninstall kvisior        -n wolfee-watcher 2>/dev/null   # if you tried that name earlier
kubectl delete ns wolfee-watcher                              # also deletes the CA Secret
# then redo step 2 (recreate ns + apply CA) and step 3 (install)
```

Do **not** pass `--create-namespace`: step 2 already creates the namespace, and
`--set namespace.create=false` tells the chart not to own it.

