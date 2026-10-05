package schema

func init() { DDL = append(DDL, v0014DDL...) }

var v0014DDL = []string{
	`CREATE TABLE IF NOT EXISTS audit_ingest_state (
 cluster_id TEXT NOT NULL,
 event_key TEXT NOT NULL,
 admitted BOOLEAN NOT NULL DEFAULT FALSE,
 enriched BOOLEAN NOT NULL DEFAULT FALSE,
 pending JSONB,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 PRIMARY KEY (cluster_id,event_key)
 )`,
	`CREATE INDEX IF NOT EXISTS idx_audit_ingest_retention ON audit_ingest_state(created_at)`,
	`CREATE TABLE IF NOT EXISTS audit_rule_matches (
 cluster_id TEXT NOT NULL,
 event_key TEXT NOT NULL,
 rule_id TEXT NOT NULL,
 PRIMARY KEY(cluster_id,event_key,rule_id),
 FOREIGN KEY(cluster_id,event_key) REFERENCES audit_ingest_state(cluster_id,event_key) ON DELETE CASCADE
 )`,
	`CREATE TABLE IF NOT EXISTS audit_thresholds (
 cluster_id TEXT NOT NULL,
 rule_id TEXT NOT NULL,
 revision TEXT NOT NULL,
 hit_at TIMESTAMPTZ[] NOT NULL DEFAULT '{}',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 PRIMARY KEY(cluster_id,rule_id)
 )`,
	`CREATE INDEX IF NOT EXISTS idx_audit_viol_event ON audit_violations(cluster_id, (data->>'id'))`,
	`CREATE TABLE IF NOT EXISTS audit_log_settings (
 cluster_id TEXT PRIMARY KEY,
 enabled BOOLEAN NOT NULL DEFAULT FALSE,
 path TEXT NOT NULL DEFAULT '',
 node_paths JSONB NOT NULL DEFAULT '{}',
 updated_by TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 applied_rev TEXT NOT NULL DEFAULT '',
 applied_at TIMESTAMPTZ,
 apply_error TEXT NOT NULL DEFAULT ''
 )`,
	`CREATE TABLE IF NOT EXISTS audit_log_nodes (
 cluster_id TEXT NOT NULL,
 node TEXT NOT NULL,
 api_server BOOLEAN NOT NULL DEFAULT FALSE,
 audit_enabled BOOLEAN NOT NULL DEFAULT FALSE,
 detected_path TEXT NOT NULL DEFAULT '',
 detected_at TIMESTAMPTZ,
 tail_path TEXT NOT NULL DEFAULT '',
 tail_state TEXT NOT NULL DEFAULT '',
 tail_error TEXT NOT NULL DEFAULT '',
 last_record_at TIMESTAMPTZ,
 lines BIGINT NOT NULL DEFAULT 0,
 sent BIGINT NOT NULL DEFAULT 0,
 rejected BIGINT NOT NULL DEFAULT 0,
 tail_seen_at TIMESTAMPTZ,
 PRIMARY KEY(cluster_id,node)
 )`,
	`ALTER TABLE audit_log_nodes ADD COLUMN IF NOT EXISTS probe_id TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE audit_log_nodes ADD COLUMN IF NOT EXISTS probe_requested_at TIMESTAMPTZ`,
	`ALTER TABLE audit_log_nodes ADD COLUMN IF NOT EXISTS probe_done TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE audit_log_nodes ADD COLUMN IF NOT EXISTS probe_ok BOOLEAN NOT NULL DEFAULT FALSE`,
	`ALTER TABLE audit_log_nodes ADD COLUMN IF NOT EXISTS probe_detail TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE audit_log_nodes ADD COLUMN IF NOT EXISTS probe_at TIMESTAMPTZ`,
	`CREATE TABLE IF NOT EXISTS audit_trusted_proxies (
 cluster_id TEXT PRIMARY KEY,
 proxies TEXT NOT NULL DEFAULT '',
 headers_sanitized BOOLEAN NOT NULL DEFAULT FALSE,
 updated_by TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
 )`,
	`ALTER TABLE audit_trusted_proxies ADD COLUMN IF NOT EXISTS headers_sanitized BOOLEAN NOT NULL DEFAULT FALSE`,
	`DO $$ BEGIN
 IF NOT EXISTS (
 SELECT 1 FROM pg_attrdef d JOIN pg_attribute a ON a.attrelid=d.adrelid AND a.attnum=d.adnum
 WHERE d.adrelid='audit_violations'::regclass AND a.attname='id'
 AND pg_get_expr(d.adbin,d.adrelid) LIKE '%kvisior_violations_id_seq%'
 ) THEN
 LOCK TABLE kvisior_violations,audit_violations IN ACCESS EXCLUSIVE MODE;
 PERFORM setval('kvisior_violations_id_seq', GREATEST(
 (SELECT last_value FROM kvisior_violations_id_seq),
 COALESCE((SELECT MAX(id) FROM kvisior_violations),0),
 COALESCE((SELECT MAX(id) FROM audit_violations),0),1), TRUE);
 UPDATE audit_violations SET id=nextval('kvisior_violations_id_seq');
 ALTER TABLE audit_violations ALTER COLUMN id SET DEFAULT nextval('kvisior_violations_id_seq');
 END IF;
 END $$`,
}
