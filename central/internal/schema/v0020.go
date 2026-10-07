package schema

func init() { DDL = append(DDL, v0020DDL...) }

var v0020DDL = []string{
	`DROP INDEX IF EXISTS idx_audit_events_ip`,
	`DROP TABLE IF EXISTS audit_rollup_hours`,
	`CREATE TABLE IF NOT EXISTS audit_rollup_marks (
 cluster_id TEXT NOT NULL,
 hour TIMESTAMPTZ NOT NULL,
 built_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (cluster_id, hour)
 )`,
	`CREATE INDEX IF NOT EXISTS idx_audit_rollup_marks_hour ON audit_rollup_marks(hour)`,
}
