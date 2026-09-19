# External hub: kvisior and PostgreSQL outside Kubernetes

The hub is the kvisior users open. It runs in containers next to PostgreSQL on
a plain host and has no agents of its own. Every cluster runs the Helm chart as
an **edge**: its own kvisior writes that cluster's data into the hub's database
and answers the hub's live requests.

```
hub host (podman or docker)
  kvisior  KVISIOR_MODE=hub   https://<hub-ip>:8443
  postgres 5432, TLS, allowlisted
     ▲ SQL over TLS (verify-ca)          │ HTTPS :30443 + federation token
     │                                   ▼
cluster A: agents + kvisior edge     cluster B: agents + kvisior edge
```

## Hub host

```bash
cp hub.env.example hub.env        # fill in: openssl rand -hex 24 for each secret
chmod 600 hub.env
sed -e s/HUB_PUBLIC_IP/<hub-ip>/ -e s/EDGE_PUBLIC_IP/<edge-ip>/ pg_hba.conf.example > pg_hba.conf
./pki.sh /srv/wolfee <hub-ip> <edge-ip> [<edge-ip> ...]
./pg-firewall.sh <edge-ip> <hub-ip> <pod-cidr>
docker compose --env-file hub.env up -d          # or podman-compose
```

- `pki.sh` creates one private CA and issues the PostgreSQL server certificate,
  the hub's HTTPS certificate and one federation certificate per edge address.
  The CA key stays in `/srv/wolfee/pki` and never leaves the host.
- `pg-firewall.sh` installs `wolfee-pg-firewall.service`: an nftables table that
  drops 5432 from anything not listed. It does not touch other rules, so it is
  safe next to a Kubernetes CNI on the same host.
- `migrate` runs on every `up`; it is idempotent. The hub refuses to start
  without a migrated database and restarts until it is ready.
- On podman, enable `podman-restart.service` so the `restart: always`
  containers come back after a reboot.

## Each cluster (edge)

The quick way is the interactive installer, run from any machine that has
`kubectl`, `helm`, `openssl` and root SSH access to the hub:

```bash
deploy/edge/install.sh
```

It takes a kubeconfig and asks for the hub's kvisior IP, the database IP, the
cluster name and the cluster's own IP. Over SSH it runs `add-edge.sh` on the hub,
which allows the edge through the PostgreSQL firewall and `pg_hba` (reloaded,
not restarted), issues the edge's federation certificate and returns the
credentials. The installer then creates the namespace, the federation TLS and
agents' CA secrets, and runs `helm install --atomic`. When it finishes it asks
for the next kubeconfig, so several clusters can be added in one go, now or at
any later time, without touching the running ones.

A cluster that already has wolfee-watcher is never upgraded: the installer
prints what is installed there (cluster id, namespace, release revision and
status, federation URL, hub and database, pod readiness) and moves on to the
next kubeconfig. Upgrades are a separate, deliberate `helm upgrade`.
Environment overrides: `HUB_SSH_USER`, `HUB_DIR`, `CHART`, `RELEASE`,
`HELM_TIMEOUT`, and `EXTRA_VALUES` for a values file with image registries or
other site settings.

The manual way — create two secrets in the release namespace first:

```bash
kubectl create secret generic wolfee-watcher-ca --from-file=ca.crt --from-file=ca.key   # agents' CA, EC P-256
kubectl create secret tls kvisior-federation-tls --cert=edges/<edge-ip>/tls.crt --key=edges/<edge-ip>/tls.key
```

Values:

```yaml
global:
  clusterId: <unique id>
  federationToken: <FEDERATION_TOKEN from hub.env>
postgres:
  enabled: false
  external:
    enabled: true
    host: <hub-ip>
    sslMode: verify-ca
    caBundle: |
      <contents of /srv/wolfee/pki/ca.crt>
  serviceCredentials:          # PG_*_PASSWORD from hub.env
    ui: { user: ww_ui, password: ... }
    traceeBridge: { user: ww_tracee_bridge, password: ... }
    anomaly: { user: ww_anomaly, password: ... }
centralMigrate:
  enabled: false               # the hub host runs migrations
ui:
  advertiseURL: https://<edge-ip>:30443
  federation:
    nodePort: 30443
    allowedSources: [<hub-ip>/32]
  ingress:
    enabled: false
```

On k3s also set `tracee.containerdSocketDir: /run/k3s/containerd`, and for a
single node `kafka.replicaCount: 1`, `kafka.replicationFactor: 1` with
`kafka.brokers` listing only `kafka-0`.

The edge writes its address into the hub's `clusters` table on start; it shows
up in the UI switcher without any registration step.
