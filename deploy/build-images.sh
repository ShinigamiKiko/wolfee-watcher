#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 [--push <registry>] [--tag <tag>] [image ...]" >&2
  echo "  builds the wolfee-watcher images from the repo root and imports them into containerd" >&2
  echo "  --push <registry>  push to <registry>/wolfee-watcher/<image>:<tag> instead of importing" >&2
  echo "  --tag <tag>        image tag (default: latest)" >&2
  echo "  image ...          build only these images (default: all)" >&2
  exit 1
}

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TAG=latest
REGISTRY=""
ONLY=()
while [ $# -gt 0 ]; do
  case "$1" in
    --push) REGISTRY="${2:?}"; shift 2 ;;
    --tag) TAG="${2:?}"; shift 2 ;;
    -h|--help) usage ;;
    *) ONLY+=("$1"); shift ;;
  esac
done

IMAGES=(
  "central-migrate:central/Dockerfile"
  "cert-server:cert-server/Dockerfile"
  "sensor:sensor/Dockerfile"
  "tracee-bridge:tracee-bridge/Dockerfile"
  "anomaly-detector:anomaly/Dockerfile"
  "sentry-audit:sentry-audit/Dockerfile"
  "scanner-agent:scanner-agent/Dockerfile"
  "forensic-watcher:forensic-watcher/Dockerfile"
  "honey-operator:honey-operator/Dockerfile"
  "honeypot:honeypot/Dockerfile"
  "audit-runner:audit-runner/Dockerfile"
  "kvisior8:kvisior/Dockerfile"
)

BUILDER="$(command -v podman || command -v docker || true)"
[ -n "$BUILDER" ] || { echo "podman or docker is required" >&2; exit 1; }
if [ -z "$REGISTRY" ]; then
  command -v ctr >/dev/null || { echo "ctr is required to import into containerd (or use --push)" >&2; exit 1; }
fi

wanted() {
  [ ${#ONLY[@]} -eq 0 ] && return 0
  local n
  for n in "${ONLY[@]}"; do [ "$n" = "$1" ] && return 0; done
  return 1
}

cd "$ROOT"
for entry in "${IMAGES[@]}"; do
  name="${entry%%:*}"; file="${entry#*:}"
  wanted "$name" || continue
  if [ -n "$REGISTRY" ]; then
    ref="$REGISTRY/wolfee-watcher/$name:$TAG"
  else
    ref="localhost/wolfee-watcher/$name:$TAG"
  fi
  echo "### $name ($file)"
  "$BUILDER" build -t "$ref" -f "$file" "$ROOT"
  if [ -n "$REGISTRY" ]; then
    "$BUILDER" push "$ref"
  else
    "$BUILDER" save "$ref" | ctr -n k8s.io images import -
  fi
done
echo "### done"
