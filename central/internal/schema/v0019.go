package schema

func init() { DDL = append(DDL, v0019DDL...) }

var v0019DDL = []string{
	`CREATE INDEX IF NOT EXISTS idx_audit_events_kind ON audit_events(cluster_id, kind, ts DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_events_ns ON audit_events(cluster_id, ns, ts DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_events_resource ON audit_events(cluster_id, resource text_pattern_ops, ts DESC)`,
}
