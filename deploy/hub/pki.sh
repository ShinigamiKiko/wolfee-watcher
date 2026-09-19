#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <data-dir> <hub-ip> [edge-ip ...]" >&2
  exit 1
}
[ $# -ge 2 ] || usage

DATA="$1"; HUB_IP="$2"; shift 2
PKI="$DATA/pki"
umask 077
mkdir -p "$PKI/pg" "$PKI/hub" "$PKI/edges"

if [ ! -f "$PKI/ca.key" ]; then
  openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
    -keyout "$PKI/ca.key" -out "$PKI/ca.crt" -subj "/O=wolfee-watcher/CN=wolfee-watcher hub CA" >/dev/null 2>&1
fi
chmod 644 "$PKI/ca.crt"

issue() {
  local dir="$1" cn="$2" san="$3"
  openssl req -newkey rsa:2048 -nodes -keyout "$dir/tls.key" -out "$dir/tls.csr" \
    -subj "/O=wolfee-watcher/CN=$cn" >/dev/null 2>&1
  printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$san" > "$dir/ext.cnf"
  openssl x509 -req -in "$dir/tls.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" -CAcreateserial \
    -days 825 -sha256 -extfile "$dir/ext.cnf" -out "$dir/tls.crt" >/dev/null 2>&1
  rm -f "$dir/tls.csr" "$dir/ext.cnf"
}

issue "$PKI/pg" "wolfee-postgres" "IP:$HUB_IP,IP:127.0.0.1,DNS:localhost"
mv -f "$PKI/pg/tls.crt" "$PKI/pg/server.crt"
mv -f "$PKI/pg/tls.key" "$PKI/pg/server.key"
chown 70:70 "$PKI/pg/server.key" "$PKI/pg/server.crt"
chmod 600 "$PKI/pg/server.key"
chmod 644 "$PKI/pg/server.crt"

issue "$PKI/hub" "wolfee-hub" "IP:$HUB_IP,DNS:wolfee-watcher.$HUB_IP.nip.io"
chown 65534:65534 "$PKI/hub/tls.key"
chmod 644 "$PKI/hub/tls.crt"

for ip in "$@"; do
  mkdir -p "$PKI/edges/$ip"
  issue "$PKI/edges/$ip" "wolfee-edge-$ip" "IP:$ip"
done

chmod 755 "$DATA" "$PKI"
chown root:70 "$PKI/pg" && chmod 750 "$PKI/pg"
chown root:65534 "$PKI/hub" && chmod 750 "$PKI/hub"

echo "CA:          $PKI/ca.crt"
echo "postgres:    $PKI/pg/server.crt"
echo "hub:         $PKI/hub/tls.crt"
for ip in "$@"; do echo "edge $ip: $PKI/edges/$ip/tls.crt"; done
