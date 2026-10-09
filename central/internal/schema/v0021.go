package schema

func init() { DDL = append(DDL, v0021DDL...) }

var v0021DDL = []string{
	`CREATE TABLE IF NOT EXISTS honeypots (
 id TEXT PRIMARY KEY,
 cluster_id TEXT NOT NULL,
 namespace TEXT NOT NULL,
 name TEXT NOT NULL,
 kind TEXT NOT NULL,
 service TEXT NOT NULL,
 port INT NOT NULL,
 target_port INT NOT NULL,
 workload_uid TEXT NOT NULL,
 service_uid TEXT NOT NULL DEFAULT '',
 policy_uid TEXT NOT NULL DEFAULT '',
 cluster_ip TEXT NOT NULL DEFAULT '',
 selector JSONB NOT NULL DEFAULT '{}',
 image TEXT NOT NULL DEFAULT '',
 created_by TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
 )`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_honeypots_name ON honeypots(cluster_id, namespace, name)`,
	`CREATE INDEX IF NOT EXISTS idx_anomaly_events_probe ON anomaly_events(cluster_id, kind, ts) WHERE kind = 'honeypot_probe'`,
}
