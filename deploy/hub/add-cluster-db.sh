#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <cluster-id> <db-ip> <db-port> <allowed-source> [allowed-source ...]" >&2
  echo "  allowed-source: the hub address, edge node addresses and the edge pod CIDR (a.b.c.d or a.b.c.d/n)" >&2
  echo "  ROTATE=1 issues new service passwords; the owner password stays, the running database was created with it" >&2
  echo "  HUB_DB_HOST is the hub database address edges use for accounts (default: the first allowed source)" >&2
  exit 1
}
[ $# -ge 4 ] || usage

CID="$1"; DBIP="$2"; PORT="$3"; shift 3
HUB_DIR="${HUB_DIR:-/opt/wolfee-hub}"

[[ "$CID" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] && [ "$CID" != default ] || { echo "invalid cluster id: $CID" >&2; exit 1; }
[[ "$DBIP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "invalid db ip: $DBIP" >&2; exit 1; }
[[ "$PORT" =~ ^[0-9]+$ ]] || { echo "invalid db port: $PORT" >&2; exit 1; }
for src in "$@"; do
  [[ "$src" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] || { echo "invalid source: $src" >&2; exit 1; }
done
[ -f "$HUB_DIR/hub.env" ] || { echo "$HUB_DIR/hub.env not found, set HUB_DIR" >&2; exit 1; }

set -a; . "$HUB_DIR/hub.env"; set +a
HUB_UI_PASSWORD="$PG_UI_PASSWORD"
HUB_DB_HOST="${HUB_DB_HOST:-${1%%/*}}"
DATA="${WOLFEE_DATA:-/srv/wolfee}"
PKI="$DATA/pki"
[ -f "$PKI/ca.key" ] || { echo "$PKI/ca.key not found, run pki.sh first" >&2; exit 1; }

log() { echo "$*" >&2; }
out() { printf 'WW_%s=%s\n' "$1" "$(printf '%s' "$2" | base64 -w0)"; }

umask 077
BUNDLE="$DATA/dbs/$CID"
mkdir -p "$BUNDLE/tls"

if [ -f "$BUNDLE/db.env" ]; then
  set -a; . "$BUNDLE/db.env"; set +a
fi
if [ ! -f "$BUNDLE/db.env" ]; then
  PG_OWNER_PASSWORD=$(openssl rand -hex 24)
fi
if [ ! -f "$BUNDLE/db.env" ] || [ "${ROTATE:-0}" = "1" ]; then
  PG_UI_PASSWORD=$(openssl rand -hex 24)
  PG_TRACEE_BRIDGE_PASSWORD=$(openssl rand -hex 24)
  PG_ANOMALY_PASSWORD=$(openssl rand -hex 24)
  log "passwords: generated service passwords; apply them with the migrate service on the database host"
else
  log "passwords: reusing $BUNDLE/db.env"
fi
cat > "$BUNDLE/db.env" <<ENV
CLUSTER_ID=$CID
DB_PORT=$PORT
DB_DATA=/srv/wolfee-db/$CID
PG_OWNER_PASSWORD=$PG_OWNER_PASSWORD
PG_UI_PASSWORD=$PG_UI_PASSWORD
PG_TRACEE_BRIDGE_PASSWORD=$PG_TRACEE_BRIDGE_PASSWORD
PG_ANOMALY_PASSWORD=$PG_ANOMALY_PASSWORD
ENV

crt="$BUNDLE/tls/server.crt"; key="$BUNDLE/tls/server.key"
if [ -f "$crt" ] && openssl x509 -in "$crt" -noout -checkend 2592000 >/dev/null 2>&1 \
   && openssl x509 -in "$crt" -noout -ext subjectAltName 2>/dev/null | grep -q "IP Address:$DBIP\b"; then
  log "certificate: reusing $crt"
else
  openssl req -newkey rsa:2048 -nodes -keyout "$key" -out "$BUNDLE/tls/server.csr" \
    -subj "/O=wolfee-watcher/CN=wolfee-postgres-$CID" >/dev/null 2>&1
  printf 'subjectAltName=IP:%s,IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n' "$DBIP" > "$BUNDLE/tls/ext.cnf"
  openssl x509 -req -in "$BUNDLE/tls/server.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" -CAcreateserial \
    -days 825 -sha256 -extfile "$BUNDLE/tls/ext.cnf" -out "$crt" >/dev/null 2>&1
  rm -f "$BUNDLE/tls/server.csr" "$BUNDLE/tls/ext.cnf"
  log "certificate: issued $crt for $DBIP"
fi
cp "$PKI/ca.crt" "$BUNDLE/tls/ca.crt"
chown 70:70 "$crt" "$key"
chmod 600 "$key"
chmod 644 "$crt" "$BUNDLE/tls/ca.crt"
chmod 755 "$BUNDLE/tls"

{
  echo "local   all  all                    trust"
  echo "host    all  all  127.0.0.1/32      scram-sha-256"
  echo "host    all  all  ::1/128           scram-sha-256"
  for src in "$@"; do
    [[ "$src" == */* ]] || src="$src/32"
    echo "hostssl all  all  $src  scram-sha-256"
  done
} > "$BUNDLE/pg_hba.conf"
chmod 644 "$BUNDLE/pg_hba.conf"
printf '%s\n' "$@" > "$BUNDLE/allowed-sources"

ROUTES_DIR="$HUB_DIR/clusters"
ROUTES="$ROUTES_DIR/databases.conf"
mkdir -p "$ROUTES_DIR"
touch "$ROUTES"
tmp=$(mktemp)
grep -vE "^$CID[[:space:]]" "$ROUTES" > "$tmp" || true
echo "$CID postgres://ww_ui:$PG_UI_PASSWORD@$DBIP:$PORT/wolfee-watcher?sslmode=verify-ca&sslrootcert=/etc/wolfee/ca.crt" >> "$tmp"
install -m 600 -o 65534 -g 65534 "$tmp" "$ROUTES"
rm -f "$tmp"
chown 65534:65534 "$ROUTES_DIR"
chmod 700 "$ROUTES_DIR"
log "hub: $CID now routes to $DBIP:$PORT (picked up within 15s)"

log "bundle for the database host: $BUNDLE"
log "  copy it with deploy/cluster-db/compose.yaml into a directory named wolfee-db-$CID on that host, then there:"
log "    podman-compose --env-file db.env up -d postgres"
log "    podman-compose --env-file db.env run --rm migrate"
log "    PG_PORT=$PORT deploy/hub/pg-firewall.sh $*"

out PG_HOST "$DBIP"
out PG_PORT "$PORT"
out PG_CA "$(cat "$PKI/ca.crt")"
out PG_UI_PASSWORD "$PG_UI_PASSWORD"
out PG_TRACEE_BRIDGE_PASSWORD "$PG_TRACEE_BRIDGE_PASSWORD"
out PG_ANOMALY_PASSWORD "$PG_ANOMALY_PASSWORD"
out PG_CONTROL_DSN "postgres://ww_ui:$HUB_UI_PASSWORD@$HUB_DB_HOST:5432/wolfee-watcher?sslmode=verify-ca&sslrootcert=/etc/wolfee-watcher/pg-ca/ca.crt"
