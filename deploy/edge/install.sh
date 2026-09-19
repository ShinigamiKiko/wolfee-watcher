#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART="${CHART:-$HERE/../../helm}"
HUB_SCRIPT="${HUB_SCRIPT:-$HERE/../hub/add-edge.sh}"
HUB_SSH_USER="${HUB_SSH_USER:-root}"
HUB_DIR="${HUB_DIR:-/opt/wolfee-hub}"
RELEASE="${RELEASE:-wolfee-watcher}"
HELM_TIMEOUT="${HELM_TIMEOUT:-15m}"
STATE_CM=wolfee-edge-install

die() { echo "error: $*" >&2; exit 1; }
say() { echo "==> $*" >&2; }

for bin in kubectl helm ssh openssl base64; do
  command -v "$bin" >/dev/null 2>&1 || die "$bin is not installed"
done
[ -f "$CHART/Chart.yaml" ] || die "chart not found at $CHART (set CHART)"
[ -f "$HUB_SCRIPT" ] || die "hub script not found at $HUB_SCRIPT (set HUB_SCRIPT)"
[ -t 0 ] || die "run this script from an interactive terminal"

ask() {
  local prompt="$1" def="${2:-}" ans
  if [ -n "$def" ]; then read -r -p "$prompt [$def]: " ans; else read -r -p "$prompt: " ans; fi
  echo "${ans:-$def}"
}

is_ip() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
is_id() { [[ "$1" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; }

ask_ip() {
  local prompt="$1" def="${2:-}" v
  while :; do
    v=$(ask "$prompt" "$def")
    is_ip "$v" && { echo "$v"; return; }
    echo "  not an IPv4 address: '$v'" >&2
  done
}

ask_id() {
  local prompt="$1" def="${2:-}" v
  while :; do
    v=$(ask "$prompt" "$def")
    is_id "$v" && { echo "$v"; return; }
    echo "  use lowercase letters, digits and dashes, 1-63 chars" >&2
  done
}

sanitize_id() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9-]+/-/g; s/^-+//; s/-+$//' | cut -c1-63 | sed -E 's/-+$//'
}

k() { kubectl --kubeconfig "$KCFG" "$@"; }
h() { helm --kubeconfig "$KCFG" "$@"; }

state_get() { k -n "$NS" get configmap "$STATE_CM" -o "jsonpath={.data.$1}" 2>/dev/null || true; }

hub_call() {
  local host="$1"; shift
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$HUB_SSH_USER@$host" \
    "HUB_DIR='$HUB_DIR' bash -s -- $*" < "$HUB_SCRIPT"
}

field() { printf '%s\n' "$BUNDLE" | sed -n "s/^WW_$1=//p" | head -1 | base64 -d; }

indent() { sed "s/^/$1/"; }

detect_edge_ip() {
  local ip
  ip=$(k get nodes -o jsonpath='{range .items[*]}{.status.addresses[?(@.type=="ExternalIP")].address}{"\n"}{end}' 2>/dev/null | grep -m1 -E '^[0-9.]+$' || true)
  [ -z "$ip" ] && ip=$(k config view --minify -o jsonpath='{.clusters[0].cluster.server}' | sed -E 's#^[a-z]+://##; s#[:/].*$##')
  if ! is_ip "$ip" || [ "${ip%%.*}" = "127" ]; then
    ip=$(k get nodes -o jsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}' 2>/dev/null | grep -m1 -E '^[0-9.]+$' || true)
  fi
  is_ip "$ip" && [ "${ip%%.*}" != "127" ] && echo "$ip" || true
}

containerd_dir() {
  local rt kv
  rt=$(k get nodes -o jsonpath='{.items[0].status.nodeInfo.containerRuntimeVersion}')
  kv=$(k get nodes -o jsonpath='{.items[0].status.nodeInfo.kubeletVersion}')
  case "$rt" in containerd://*) ;; *) say "container runtime is '$rt'; tracee expects containerd" ;; esac
  case "$kv" in *k3s*|*rke2*) echo /run/k3s/containerd ;; *) echo /run/containerd ;; esac
}

node_cidrs() {
  {
    k get nodes -o jsonpath='{range .items[*]}{range .status.addresses[?(@.type=="InternalIP")]}{.address}{"/32\n"}{end}{end}'
    k get nodes -o jsonpath='{range .items[*]}{range .status.addresses[?(@.type=="ExternalIP")]}{.address}{"/32\n"}{end}{end}'
    k get nodes -o jsonpath='{range .items[*]}{range .spec.podCIDRs[*]}{@}{"\n"}{end}{end}'
  } | grep -E '^[0-9.]+/[0-9]+$' | sort -u
}

ensure_cluster_ca() {
  if k -n "$NS" get secret wolfee-watcher-ca >/dev/null 2>&1; then
    say "cluster CA: keeping existing secret wolfee-watcher-ca"
    return
  fi
  local d
  d=$(mktemp -d)
  openssl ecparam -name prime256v1 -genkey -noout -out "$d/ca.key" 2>/dev/null
  openssl req -x509 -new -key "$d/ca.key" -sha256 -days 3650 -out "$d/ca.crt" \
    -subj "/O=wolfee-watcher/CN=wolfee-watcher $CID CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  k -n "$NS" create secret generic wolfee-watcher-ca --from-file=ca.crt="$d/ca.crt" --from-file=ca.key="$d/ca.key" >/dev/null
  rm -rf "$d"
  say "cluster CA: created secret wolfee-watcher-ca"
}

report_existing() {
  local rel ns ui
  rel=$(h list -A --all --filter "^${RELEASE}\$" -o json 2>/dev/null | tr -d '[]' || true)
  ui=$(k get deploy -A -l app.kubernetes.io/name=kvisior-ui \
    -o jsonpath='{range .items[*]}{.metadata.namespace}{"\n"}{end}' 2>/dev/null | head -1 || true)
  [ -n "$rel" ] || [ -n "$ui" ] || return 1

  jget() { printf '%s' "$rel" | sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"; }
  ns=$(jget namespace); ns="${ns:-$ui}"
  NS="$ns"

  local cid adv env
  env='{.spec.template.spec.containers[0].env[?(@.name=="%s")].value}'
  cid=$(k -n "$ns" get deploy kvisior-ui -o "jsonpath=$(printf "$env" CLUSTER_ID)" 2>/dev/null || true)
  adv=$(k -n "$ns" get deploy kvisior-ui -o "jsonpath=$(printf "$env" KVISIOR_ADVERTISE_URL)" 2>/dev/null || true)

  echo
  echo "  already installed, nothing changed"
  echo "  cluster     ${cid:-$(state_get clusterId)}"
  echo "  namespace   $ns"
  if [ -n "$rel" ]; then
    echo "  release     $RELEASE, revision $(jget revision), $(jget status), chart $(jget chart)"
    echo "  updated     $(jget updated)"
  else
    echo "  release     kvisior-ui found, but no helm release named $RELEASE"
  fi
  [ -n "$adv" ] && echo "  federation  $adv"
  local kv db
  kv=$(state_get kvisiorIP); db=$(state_get dbIP)
  [ -n "$kv" ] && echo "  kvisior     $kv"
  [ -n "$db" ] && echo "  database    $db:5432"
  echo "  pods        $(k -n "$ns" get pods --no-headers 2>/dev/null | awk '{split($2,a,"/"); if ($3=="Running" && a[1]==a[2]) ok++; else if ($3!="Completed") bad++} END {printf "%d ready, %d not ready", ok, bad}')"
  return 0
}

install_one() {
  local ctx server
  ctx=$(k config current-context 2>/dev/null) || die "cannot read kubeconfig $KCFG"
  server=$(k config view --minify -o jsonpath='{.clusters[0].cluster.server}')
  say "kubeconfig $KCFG, context '$ctx', server $server"
  k get nodes >/dev/null || die "cannot reach the cluster with $KCFG"

  report_existing && return

  NS=$(ask_id "Namespace" "${NS:-wolfee-watcher}")
  KV_IP=$(ask_ip "kvisior (hub) IP" "${KV_IP:-}")
  DB_IP=$(ask_ip "Database IP" "${DB_IP:-$KV_IP}")
  CID=$(ask_id "Cluster name" "$(sanitize_id "$ctx")")
  EDGE_IP=$(ask_ip "This cluster's IP, reachable from the hub" "$(detect_edge_ip)")

  echo
  echo "  cluster     $CID"
  echo "  namespace   $NS"
  echo "  edge IP     $EDGE_IP  (federation on :30443)"
  echo "  kvisior     $KV_IP"
  echo "  database    $DB_IP:5432"
  echo
  [ "$(ask "Install? (y/n)" y)" = "y" ] || { say "skipped"; return; }

  say "registering on the hub"
  if [ "$KV_IP" = "$DB_IP" ]; then
    BUNDLE=$(hub_call "$KV_IP" "$CID" "$EDGE_IP")
  else
    BUNDLE=$(hub_call "$DB_IP" --db "$CID" "$EDGE_IP")$'\n'$(hub_call "$KV_IP" --kvisior "$CID" "$EDGE_IP")
  fi

  local tmp
  tmp=$(mktemp -d)
  TMPDIRS+=("$tmp")
  chmod 700 "$tmp"
  for f in FEDERATION_TOKEN PG_CA PG_UI_PASSWORD PG_TRACEE_BRIDGE_PASSWORD PG_ANOMALY_PASSWORD; do
    [ -n "$(field "$f")" ] || die "the hub did not return $f"
  done
  field EDGE_TLS_CRT > "$tmp/tls.crt"
  field EDGE_TLS_KEY > "$tmp/tls.key"
  [ -s "$tmp/tls.crt" ] && [ -s "$tmp/tls.key" ] || die "the hub did not return the federation certificate"

  say "namespace $NS"
  k get namespace "$NS" >/dev/null 2>&1 || k create namespace "$NS" >/dev/null
  k -n "$NS" create secret tls kvisior-federation-tls --cert="$tmp/tls.crt" --key="$tmp/tls.key" \
    --dry-run=client -o yaml | k apply -f - >/dev/null
  ensure_cluster_ca

  local push nodes brokers sock i kafka_n
  push=$(openssl rand -hex 32)
  nodes=$(k get nodes --no-headers | wc -l | tr -d ' ')
  kafka_n=$(( nodes >= 2 ? 2 : 1 ))
  brokers=""
  for ((i = 0; i < kafka_n; i++)); do
    brokers+="${brokers:+,}kafka-$i.kafka-headless.$NS.svc.cluster.local:9092"
  done
  sock=$(containerd_dir)

  cat > "$tmp/values.yaml" <<EOF
global:
  namespace: $NS
  clusterId: $CID
  certServerAddr: https://cert-server.$NS.svc.cluster.local:8090
  internalPushSecret: $push
  federationToken: $(field FEDERATION_TOKEN)
namespace:
  create: false
postgres:
  enabled: false
  external:
    enabled: true
    host: $DB_IP
    port: 5432
    sslMode: verify-ca
    caBundle: |
$(field PG_CA | indent '      ')
  serviceCredentials:
    ui:
      user: ww_ui
      password: $(field PG_UI_PASSWORD)
    traceeBridge:
      user: ww_tracee_bridge
      password: $(field PG_TRACEE_BRIDGE_PASSWORD)
    anomaly:
      user: ww_anomaly
      password: $(field PG_ANOMALY_PASSWORD)
centralMigrate:
  enabled: false
  schemaVersion: $(field SCHEMA_VERSION)
networkPolicy:
  nodeCIDRs:
$(node_cidrs | indent '    - ')
ui:
  advertiseURL: https://$EDGE_IP:30443
  federation:
    nodePort: 30443
    tlsSecret: kvisior-federation-tls
    allowedSources:
      - $KV_IP/32
  ingress:
    enabled: false
tracee:
  containerdSocketDir: $sock
kafka:
  replicaCount: $kafka_n
  brokers: $brokers
  replicationFactor: $kafka_n
  minIsr: 1
EOF
  chmod 600 "$tmp/values.yaml"

  local extra=()
  [ -n "${EXTRA_VALUES:-}" ] && extra=(-f "$EXTRA_VALUES")

  say "helm install $RELEASE (atomic, timeout $HELM_TIMEOUT)"
  h install "$RELEASE" "$CHART" -n "$NS" \
    -f "$tmp/values.yaml" "${extra[@]}" \
    --atomic --wait --timeout "$HELM_TIMEOUT"

  k -n "$NS" create configmap "$STATE_CM" \
    --from-literal=clusterId="$CID" --from-literal=kvisiorIP="$KV_IP" \
    --from-literal=dbIP="$DB_IP" --from-literal=edgeIP="$EDGE_IP" \
    --dry-run=client -o yaml | k apply -f - >/dev/null

  say "cluster '$CID' is installed; it shows up in the hub's cluster switcher within a minute"
}

TMPDIRS=()
trap 'for d in "${TMPDIRS[@]:-}"; do [ -n "$d" ] && rm -rf "$d"; done' EXIT

KCFG="${KUBECONFIG:-$HOME/.kube/config}"
KCFG="${KCFG%%:*}"
prompt="Kubeconfig"
while :; do
  KCFG=$(ask "$prompt" "$KCFG")
  [ -n "$KCFG" ] || break
  [ -f "$KCFG" ] || { echo "  file not found: $KCFG" >&2; KCFG=""; continue; }
  install_one
  echo
  prompt="Kubeconfig of the next cluster (empty to finish)"
  KCFG=""
  NS=""
done
