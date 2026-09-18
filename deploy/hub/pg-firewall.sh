#!/usr/bin/env bash
set -euo pipefail

[ $# -ge 1 ] || { echo "usage: $0 <allowed-source> [allowed-source ...]" >&2; exit 1; }

RULES=/etc/wolfee/pg-firewall.nft
mkdir -p /etc/wolfee
{
  echo "table inet wolfee_pg"
  echo "delete table inet wolfee_pg"
  echo "table inet wolfee_pg {"
  echo "  chain input {"
  echo "    type filter hook input priority -10; policy accept;"
  echo "    tcp dport 5432 iif lo accept"
  for src in "$@"; do echo "    tcp dport 5432 ip saddr $src accept"; done
  echo "    tcp dport 5432 drop"
  echo "  }"
  echo "}"
} > "$RULES"

cat > /etc/systemd/system/wolfee-pg-firewall.service <<UNIT
[Unit]
Description=Restrict PostgreSQL (5432) to the wolfee-watcher allowlist
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f $RULES
ExecStop=/usr/sbin/nft delete table inet wolfee_pg

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now wolfee-pg-firewall.service
systemctl restart wolfee-pg-firewall.service
nft list table inet wolfee_pg
