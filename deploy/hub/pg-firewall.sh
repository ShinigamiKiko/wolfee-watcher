#!/usr/bin/env bash
set -euo pipefail

[ $# -ge 1 ] || { echo "usage: [PG_PORT=5432] $0 <allowed-source> [allowed-source ...]" >&2; exit 1; }

PORT="${PG_PORT:-5432}"
[[ "$PORT" =~ ^[0-9]+$ ]] || { echo "invalid PG_PORT: $PORT" >&2; exit 1; }
if [ "$PORT" = 5432 ]; then
  NAME=wolfee_pg; UNIT=wolfee-pg-firewall
else
  NAME="wolfee_pg_$PORT"; UNIT="wolfee-pg-firewall-$PORT"
fi
RULES="/etc/wolfee/$UNIT.nft"
[ "$PORT" = 5432 ] && RULES=/etc/wolfee/pg-firewall.nft
mkdir -p /etc/wolfee
{
  echo "table inet $NAME"
  echo "delete table inet $NAME"
  echo "table inet $NAME {"
  echo "  chain input {"
  echo "    type filter hook input priority -10; policy accept;"
  echo "    tcp dport $PORT iif lo accept"
  for src in "$@"; do echo "    tcp dport $PORT ip saddr $src accept"; done
  echo "    tcp dport $PORT drop"
  echo "  }"
  echo "}"
} > "$RULES"

cat > "/etc/systemd/system/$UNIT.service" <<UNITFILE
[Unit]
Description=Restrict PostgreSQL ($PORT) to the wolfee-watcher allowlist
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f $RULES
ExecStop=/usr/sbin/nft delete table inet $NAME

[Install]
WantedBy=multi-user.target
UNITFILE

systemctl daemon-reload
systemctl enable --now "$UNIT.service"
systemctl restart "$UNIT.service"
nft list table inet "$NAME"
