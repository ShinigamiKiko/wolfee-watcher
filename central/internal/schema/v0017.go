package schema

func init() { DDL = append(DDL, v0017DDL...) }

var v0017DDL = []string{
	`CREATE TABLE IF NOT EXISTS audit_silences (
 id BIGSERIAL PRIMARY KEY,
 cluster_id TEXT NOT NULL,
 action TEXT NOT NULL DEFAULT '',
 object TEXT NOT NULL DEFAULT '',
 actor TEXT NOT NULL DEFAULT '',
 source_ip TEXT NOT NULL DEFAULT '',
 reason TEXT NOT NULL DEFAULT '',
 created_by TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 expires_at TIMESTAMPTZ,
 CHECK (action <> '' OR object <> '' OR actor <> '' OR source_ip <> '')
 )`,
	`CREATE INDEX IF NOT EXISTS idx_audit_silences_cluster ON audit_silences(cluster_id, created_at DESC)`,
	`CREATE TABLE IF NOT EXISTS audit_silenced_events (
 id BIGSERIAL PRIMARY KEY,
 cluster_id TEXT NOT NULL,
 silence_id BIGINT NOT NULL REFERENCES audit_silences(id) ON DELETE CASCADE,
 event_uid TEXT NOT NULL,
 ts TIMESTAMPTZ NOT NULL,
 kind TEXT,
 resource TEXT,
 ns TEXT,
 name TEXT,
 "user" TEXT,
 source_ip TEXT,
 origin TEXT,
 rule_id TEXT,
 sev TEXT,
 data JSONB NOT NULL,
 silenced_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE (cluster_id, event_uid)
 )`,
	`CREATE INDEX IF NOT EXISTS idx_audit_silenced_events_silence ON audit_silenced_events(silence_id, id DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_silenced_events_cluster ON audit_silenced_events(cluster_id, id DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_silenced_events_ts ON audit_silenced_events(ts)`,
}
