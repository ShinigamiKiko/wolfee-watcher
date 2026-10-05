package schema

const AuditRulesVersion = "0013-audit-rules"

type BuiltinRuleAddition struct {
	Version string
	IDs     []string
}

var BuiltinRuleAdditions = []BuiltinRuleAddition{
	{Version: "0016-builtin-forwarded-spoof", IDs: []string{"forwarded-spoof"}},
}

func init() {
	DDL = append(DDL, v0013DDL...)
}

var v0013DDL = []string{

	`CREATE TABLE IF NOT EXISTS audit_rules (
	id         TEXT        PRIMARY KEY,
	name       TEXT        NOT NULL,
	grp        TEXT        NOT NULL DEFAULT 'Custom',
	origin     TEXT        NOT NULL DEFAULT 'custom',
	enabled    BOOLEAN     NOT NULL DEFAULT TRUE,
	alert      BOOLEAN     NOT NULL DEFAULT FALSE,
	severity   TEXT        NOT NULL DEFAULT 'high',
	spec       JSONB       NOT NULL DEFAULT '{}',
	updated_by TEXT        NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_rules_updated ON audit_rules(updated_at)`,

	`CREATE TABLE IF NOT EXISTS audit_violations (
	id               BIGSERIAL   PRIMARY KEY,
	cluster_id       TEXT        NOT NULL DEFAULT 'default',
	ts               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	last_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	hits             BIGINT      NOT NULL DEFAULT 1,
	rule_id          TEXT        NOT NULL DEFAULT '',
	rule_name        TEXT        NOT NULL DEFAULT '',
	sev              TEXT        NOT NULL DEFAULT '',
	kind             TEXT        NOT NULL DEFAULT '',
	resource         TEXT        NOT NULL DEFAULT '',
	namespace        TEXT        NOT NULL DEFAULT '',
	name             TEXT        NOT NULL DEFAULT '',
	actor            TEXT        NOT NULL DEFAULT '',
	source_ip        TEXT        NOT NULL DEFAULT '',
	fingerprint      TEXT        NOT NULL DEFAULT '',
	state            TEXT        NOT NULL DEFAULT 'ACTIVE',
	state_expires_at TIMESTAMPTZ,
	state_changed_at TIMESTAMPTZ,
	data             JSONB       NOT NULL
)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_viol_fp
	 ON audit_violations(cluster_id, fingerprint) WHERE fingerprint != ''`,
	`CREATE INDEX IF NOT EXISTS idx_audit_viol_cluster_ts ON audit_violations(cluster_id, id)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_viol_rule       ON audit_violations(cluster_id, rule_id)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_viol_state      ON audit_violations(state, state_expires_at)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_viol_last_seen  ON audit_violations(state, last_seen)`,

	`ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS event_uid TEXT`,
	`ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS name      TEXT`,
	`ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS source_ip TEXT`,
	`ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS allowed   BOOLEAN`,
	`ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS origin    TEXT`,
	`ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS rule_id   TEXT`,
	`ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS sev       TEXT`,
	`CREATE INDEX IF NOT EXISTS idx_audit_events_cluster_ts ON audit_events(cluster_id, ts DESC, id DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_events_uid        ON audit_events(cluster_id, event_uid)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_events_user       ON audit_events(cluster_id, "user", ts DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_events_ip         ON audit_events(cluster_id, source_ip, ts DESC)
	 WHERE source_ip IS NOT NULL`,
	`CREATE INDEX IF NOT EXISTS idx_audit_events_rule       ON audit_events(cluster_id, ts DESC)
	 WHERE rule_id IS NOT NULL`,
}
