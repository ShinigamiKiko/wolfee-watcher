#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 [--db] [--kvisior] <cluster-id> <edge-ip>" >&2
  echo "  --db       allow the edge to reach PostgreSQL (firewall, pg_hba) and print its credentials" >&2
  echo "  --kvisior  issue the edge's federation certificate and print the federation token" >&2
  echo "  neither    both" >&2
  exit 1
}

DO_DB=0; DO_KV=0
while [ $# -gt 0 ]; do
  case "$1" in
    --db) DO_DB=1; shift ;;
    --kvisior) DO_KV=1; shift ;;
    -h|--help) usage ;;
    *) break ;;
  esac
done
[ $# -eq 2 ] || usage
[ $DO_DB -eq 0 ] && [ $DO_KV -eq 0 ] && { DO_DB=1; DO_KV=1; }

CID="$1"; EIP="$2"
HUB_DIR="${HUB_DIR:-/opt/wolfee-hub}"

[[ "$CID" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || { echo "invalid cluster id: $CID" >&2; exit 1; }
[[ "$EIP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "invalid edge ip: $EIP" >&2; exit 1; }
[ -f "$HUB_DIR/hub.env" ] || { echo "$HUB_DIR/hub.env not found, set HUB_DIR" >&2; exit 1; }

set -a; . "$HUB_DIR/hub.env"; set +a
DATA="${WOLFEE_DATA:-/srv/wolfee}"
PKI="$DATA/pki"
REG="$DATA/edges.d"
[ -f "$PKI/ca.crt" ] || { echo "$PKI/ca.crt not found, run pki.sh first" >&2; exit 1; }

log() { echo "$*" >&2; }
out() { printf 'WW_%s=%s\n' "$1" "$(printf '%s' "$2" | base64 -w0)"; }

umask 077
mkdir -p "$REG"
if [ -f "$REG/$CID" ]; then
  prev=$(cat "$REG/$CID")
  if [ "$prev" != "$EIP" ] && [ "${FORCE:-0}" != "1" ]; then
    log "cluster $CID is already registered with $prev; rerun with FORCE=1 to move it to $EIP"
    exit 1
  fi
fi
for f in "$REG"/*; do
  [ -f "$f" ] || continue
  other=$(basename "$f")
  if [ "$other" != "$CID" ] && [ "$(cat "$f")" = "$EIP" ] && [ "${FORCE:-0}" != "1" ]; then
    log "$EIP is already registered as cluster $other; rerun with FORCE=1 to reuse it"
    exit 1
  fi
done
echo "$EIP" > "$REG/$CID"

postgres_container() {
  local rt id
  for rt in podman docker; do
    command -v "$rt" >/dev/null 2>&1 || continue
    for label in com.docker.compose.service=postgres io.podman.compose.service=postgres; do
      id=$("$rt" ps -q --filter "label=$label" --filter "label=com.docker.compose.project=wolfee-hub" 2>/dev/null | head -1)
      [ -n "$id" ] && { echo "$rt $id"; return; }
    done
  done
}

if [ $DO_DB -eq 1 ]; then
  HBA="$HUB_DIR/pg_hba.conf"
  [ -f "$HBA" ] || { log "$HBA not found"; exit 1; }
  line="hostssl all  all  $EIP/32 scram-sha-256"
  if grep -qE "^hostssl[[:space:]]+all[[:space:]]+all[[:space:]]+$EIP/32[[:space:]]" "$HBA"; then
    log "pg_hba: $EIP already allowed"
  else
    printf '%s\n' "$line" >> "$HBA"
    log "pg_hba: allowed $EIP"
    read -r rt id <<<"$(postgres_container)" || true
    if [ -n "${id:-}" ]; then
      "$rt" exec "$id" psql -qtA -U wolfee-watcher -d wolfee-watcher -c "select pg_reload_conf()" >/dev/null
      log "pg_hba: reloaded"
    else
      log "pg_hba: postgres container not found, reload it yourself"
    fi
  fi

  NFT=/etc/wolfee/pg-firewall.nft
  if [ -f "$NFT" ]; then
    if grep -q "ip saddr $EIP accept" "$NFT"; then
      log "firewall: $EIP already allowed"
    else
      mapfile -t allowed < <(grep -oE 'ip saddr [^ ]+ accept' "$NFT" | awk '{print $3}')
      allowed+=("$EIP")
      tmp=$(mktemp)
      {
        echo "table inet wolfee_pg"
        echo "delete table inet wolfee_pg"
        echo "table inet wolfee_pg {"
        echo "  chain input {"
        echo "    type filter hook input priority -10; policy accept;"
        echo "    tcp dport 5432 iif lo accept"
        for src in "${allowed[@]}"; do echo "    tcp dport 5432 ip saddr $src accept"; done
        echo "    tcp dport 5432 drop"
        echo "  }"
        echo "}"
      } > "$tmp"
      nft -c -f "$tmp"
      install -m 600 "$tmp" "$NFT"
      rm -f "$tmp"
      nft -f "$NFT"
      log "firewall: allowed $EIP"
    fi
  else
    log "firewall: $NFT not found, skipping (see pg-firewall.sh)"
  fi

  out PG_CA "$(cat "$PKI/ca.crt")"
  out PG_UI_PASSWORD "$PG_UI_PASSWORD"
  out PG_TRACEE_BRIDGE_PASSWORD "$PG_TRACEE_BRIDGE_PASSWORD"
  out PG_ANOMALY_PASSWORD "$PG_ANOMALY_PASSWORD"
fi

if [ $DO_KV -eq 1 ]; then
  [ -n "${FEDERATION_TOKEN:-}" ] || { log "FEDERATION_TOKEN is empty in hub.env"; exit 1; }
  dir="$PKI/edges/$EIP"
  mkdir -p "$dir"
  if [ -f "$dir/tls.crt" ] && [ -f "$dir/tls.key" ] \
     && openssl x509 -in "$dir/tls.crt" -noout -checkend 2592000 >/dev/null 2>&1 \
     && openssl verify -CAfile "$PKI/ca.crt" "$dir/tls.crt" >/dev/null 2>&1; then
    log "certificate: reusing $dir/tls.crt"
  else
    openssl req -newkey rsa:2048 -nodes -keyout "$dir/tls.key" -out "$dir/tls.csr" \
      -subj "/O=wolfee-watcher/CN=wolfee-edge-$EIP" >/dev/null 2>&1
    printf 'subjectAltName=IP:%s\nextendedKeyUsage=serverAuth\n' "$EIP" > "$dir/ext.cnf"
    openssl x509 -req -in "$dir/tls.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" -CAcreateserial \
      -days 825 -sha256 -extfile "$dir/ext.cnf" -out "$dir/tls.crt" >/dev/null 2>&1
    rm -f "$dir/tls.csr" "$dir/ext.cnf"
    log "certificate: issued $dir/tls.crt"
  fi
  out FEDERATION_TOKEN "$FEDERATION_TOKEN"
  out EDGE_TLS_CRT "$(cat "$dir/tls.crt")"
  out EDGE_TLS_KEY "$(cat "$dir/tls.key")"
  out SCHEMA_VERSION "${SCHEMA_VERSION:-0012-multicluster}"
fi
