#!/usr/bin/env bash
set -euo pipefail

REPO="localhost/wolfee-watcher"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}✓${NC} $1"; }
err()  { echo -e "${RED}✗${NC} $1"; exit 1; }
info() { echo -e "${YELLOW}→${NC} $1"; }

build() {
  local name="$1"
  local dir="$2"
  local dockerfile="${3:-Dockerfile}"
  local context="${4:-$dir}"

  info "Building $name..."
  podman build --no-cache \
    -t "${REPO}/${name}:latest" \
    -f "${context}/${dockerfile}" \
    "${context}" \
    || err "Build failed: $name"

  info "Importing $name into containerd..."
  podman save "${REPO}/${name}:latest" \
    | ctr -n k8s.io images import - \
    || err "Import failed: $name"

  ok "$name"
  echo ""
}

echo ""
echo "══════════════════════════════════════════"
echo "  Wolfee-Watcher — build & import all images"
echo "══════════════════════════════════════════"
echo ""

build "central-migrate"  "$ROOT/central"      "central/Dockerfile"      "$ROOT"
build "tracee-bridge"    "$ROOT/tracee-bridge" "tracee-bridge/Dockerfile" "$ROOT"
build "sensor"           "$ROOT/sensor"       "sensor/Dockerfile"       "$ROOT"
build "anomaly-detector" "$ROOT/anomaly"      "anomaly/Dockerfile"      "$ROOT"
build "sentry-audit"     "$ROOT/sentry-audit" "sentry-audit/Dockerfile" "$ROOT"
build "honey-operator"   "$ROOT/honey-operator" "honey-operator/Dockerfile"   "$ROOT"
build "honeypot"         "$ROOT/honeypot"     "honeypot/Dockerfile"     "$ROOT"
build "audit-runner"     "$ROOT/audit-runner"  "audit-runner/Dockerfile"     "$ROOT"
build "scanner-agent"    "$ROOT/scanner-agent" "scanner-agent/Dockerfile" "$ROOT"
build "cert-server"      "$ROOT/cert-server"   "cert-server/Dockerfile"      "$ROOT"
build "forensic-watcher" "$ROOT/forensic-watcher" "forensic-watcher/Dockerfile" "$ROOT"
build "kvisior8"         "$ROOT/kvisior"       "kvisior/Dockerfile"          "$ROOT"

echo "══════════════════════════════════════════"
ok "All images built and imported"
echo ""
echo "To restart all deployments run:"
echo "  ./restart-all.sh"
echo ""
