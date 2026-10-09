#!/bin/sh
set -eu

service=""
port=""
case "${1:-}" in
  --*)                exec python3 -m honeypots "$@" ;;
  postgres)           service=postgres; port=5432 ;;
  mysqld)             service=mysql;    port=3306 ;;
  redis-server)       service=redis;    port=6379 ;;
  eswrapper)          service=elastic;  port=9200 ;;
  -conf)              service=dns;      port=5353 ;;
  /usr/sbin/sshd)     service=ssh;      port=2222 ;;
  nginx)              service=http;     port=8080 ;;
  vsftpd)             service=ftp;      port=2121 ;;
  postfix)            service=smtp;     port=2525 ;;
  *) echo "unsupported command: ${1:-}" >&2; exit 64 ;;
esac

logdir="/var/log/${service}"
mkdir -p "$logdir" 2>/dev/null || logdir=/tmp
conf="/tmp/.${service}.json"

cat > "$conf" <<EOF
{
  "logs": "file,terminal,json",
  "logs_location": "${logdir}/",
  "syslog_address": "",
  "syslog_facility": 0,
  "postgres": "",
  "sqlite_file": "",
  "db_options": [],
  "sniffer_filter": "",
  "sniffer_interface": "",
  "honeypots": {
    "${service}": {"port": ${port}, "ip": "0.0.0.0", "options": ["capture_commands"]}
  }
}
EOF

exec python3 -m honeypots --setup "$service" --config "$conf" --termination-strategy signal
