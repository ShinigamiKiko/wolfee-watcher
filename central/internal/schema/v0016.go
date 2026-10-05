package schema

func init() { DDL = append(DDL, v0016DDL...) }

var v0016DDL = []string{
	`CREATE TABLE IF NOT EXISTS audit_spool_status (
 cluster_id TEXT NOT NULL,
 pod TEXT NOT NULL,
 durable BOOLEAN NOT NULL DEFAULT FALSE,
 pending INTEGER NOT NULL DEFAULT 0,
 bytes BIGINT NOT NULL DEFAULT 0,
 capacity BIGINT NOT NULL DEFAULT 0,
 dead_bytes BIGINT NOT NULL DEFAULT 0,
 rejected BIGINT NOT NULL DEFAULT 0,
 shed BIGINT NOT NULL DEFAULT 0,
 quarantined BIGINT NOT NULL DEFAULT 0,
 shed_actors JSONB NOT NULL DEFAULT '{}'::jsonb,
 last_error TEXT NOT NULL DEFAULT '',
 alert_level TEXT NOT NULL DEFAULT '',
 alerted_at TIMESTAMPTZ,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (cluster_id, pod)
 )`,
	`CREATE INDEX IF NOT EXISTS idx_audit_ingest_waiting ON audit_ingest_state(created_at) WHERE NOT admitted AND pending IS NOT NULL`,
}
