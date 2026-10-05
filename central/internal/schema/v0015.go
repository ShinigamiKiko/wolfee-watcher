package schema

func init() { DDL = append(DDL, v0015DDL...) }

var v0015DDL = []string{
	`CREATE TABLE IF NOT EXISTS audit_inbox (
 id BIGSERIAL PRIMARY KEY,
 cluster_id TEXT NOT NULL,
 kind TEXT NOT NULL CHECK (kind IN ('events','log')),
 batch_key TEXT NOT NULL,
 payload JSONB NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 processed_at TIMESTAMPTZ,
 attempts INTEGER NOT NULL DEFAULT 0,
 next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 last_error TEXT NOT NULL DEFAULT '',
 UNIQUE(cluster_id,kind,batch_key)
 )`,
	`CREATE INDEX IF NOT EXISTS idx_audit_inbox_pending ON audit_inbox(cluster_id,id) WHERE processed_at IS NULL`,
	`CREATE INDEX IF NOT EXISTS idx_audit_inbox_retention ON audit_inbox(processed_at) WHERE processed_at IS NOT NULL`,
	`ALTER TABLE audit_log_nodes
	   ADD COLUMN IF NOT EXISTS backlog_bytes BIGINT NOT NULL DEFAULT 0,
	   ADD COLUMN IF NOT EXISTS backlog_files INTEGER NOT NULL DEFAULT 0,
	   ADD COLUMN IF NOT EXISTS lag_seconds BIGINT NOT NULL DEFAULT 0,
	   ADD COLUMN IF NOT EXISTS headroom INTEGER`,
}
