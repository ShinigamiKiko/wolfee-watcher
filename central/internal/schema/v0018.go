package schema

func init() { DDL = append(DDL, v0018DDL...) }

var v0018DDL = []string{
	`ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS silenced BOOLEAN NOT NULL DEFAULT FALSE`,
	`UPDATE audit_events e SET silenced = TRUE
	   FROM audit_silenced_events se
	  WHERE e.cluster_id = se.cluster_id AND e.event_uid = se.event_uid AND e.ts = se.ts AND NOT e.silenced`,
	`CREATE INDEX IF NOT EXISTS idx_audit_events_ip_prefix ON audit_events(cluster_id, source_ip text_pattern_ops, ts DESC)`,
	`CREATE TABLE IF NOT EXISTS audit_user_hourly (
 cluster_id TEXT NOT NULL,
 hour TIMESTAMPTZ NOT NULL,
 "user" TEXT NOT NULL DEFAULT '',
 allowed BOOLEAN NOT NULL DEFAULT TRUE,
 danger BOOLEAN NOT NULL DEFAULT FALSE,
 events BIGINT NOT NULL,
 last_seen TIMESTAMPTZ NOT NULL,
 ips TEXT[] NOT NULL DEFAULT '{}',
 PRIMARY KEY (cluster_id, hour, "user", allowed, danger)
 )`,
	`CREATE INDEX IF NOT EXISTS idx_audit_user_hourly_hour ON audit_user_hourly(hour)`,
	`CREATE TABLE IF NOT EXISTS platform_settings (
 key TEXT PRIMARY KEY,
 value JSONB NOT NULL,
 updated_by TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
 )`,
	`CREATE TABLE IF NOT EXISTS posture_findings (
 cluster_id TEXT NOT NULL,
 vtype TEXT NOT NULL,
 evaluated_at TIMESTAMPTZ NOT NULL,
 count INT NOT NULL DEFAULT 0,
 findings JSONB NOT NULL DEFAULT '[]',
 PRIMARY KEY (cluster_id, vtype)
 )`,
}
