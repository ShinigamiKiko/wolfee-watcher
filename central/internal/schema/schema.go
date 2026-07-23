package schema

const Version = "0009-alert-webhooks"

var DDL = []string{

	`CREATE TABLE IF NOT EXISTS schema_migrations (
	version    TEXT PRIMARY KEY,
	applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,

	`CREATE TABLE IF NOT EXISTS alerts (
	id           BIGSERIAL PRIMARY KEY,
	ts           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	source       TEXT NOT NULL,
	det_type     TEXT NOT NULL,
	rule_id      TEXT,
	rule_name    TEXT,
	severity     TEXT,
	namespace    TEXT,
	target       TEXT,
	syscall      TEXT,
	detail       TEXT,
	fingerprint  TEXT,
	data         JSONB,
	delivered_at TIMESTAMPTZ
)`,
	`CREATE INDEX IF NOT EXISTS idx_alerts_ts          ON alerts(ts DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_alerts_undelivered ON alerts(id) WHERE delivered_at IS NULL`,
	`CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint ON alerts(fingerprint, ts DESC) WHERE fingerprint IS NOT NULL`,
	`CREATE TABLE IF NOT EXISTS integrations (
	kind        TEXT PRIMARY KEY,
	enabled     BOOLEAN NOT NULL DEFAULT FALSE,
	config      JSONB NOT NULL DEFAULT '{}',
	updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE TABLE IF NOT EXISTS alert_deliveries (
	alert_id        BIGINT      NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
	integration     TEXT        NOT NULL REFERENCES integrations(kind) ON DELETE CASCADE,
	attempts        INTEGER     NOT NULL DEFAULT 0,
	delivered_at    TIMESTAMPTZ,
	next_attempt_at TIMESTAMPTZ,
	last_error      TEXT,
	PRIMARY KEY (alert_id, integration)
)`,
	`CREATE INDEX IF NOT EXISTS idx_alert_deliveries_retry
	ON alert_deliveries(next_attempt_at)
	WHERE delivered_at IS NULL`,

	`CREATE TABLE IF NOT EXISTS runtime_policies (
	id         TEXT PRIMARY KEY,
	data       JSONB NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`ALTER TABLE runtime_policies
	  ADD COLUMN IF NOT EXISTS det_type   TEXT
	  GENERATED ALWAYS AS ((data->>'detType')) STORED`,
	`ALTER TABLE runtime_policies
	  ADD COLUMN IF NOT EXISTS enabled    BOOLEAN
	  GENERATED ALWAYS AS (COALESCE((data->>'enabled')::boolean, TRUE)) STORED`,
	`ALTER TABLE runtime_policies
	  ADD COLUMN IF NOT EXISTS alert_only BOOLEAN
	  GENERATED ALWAYS AS (COALESCE((data->>'alertOnly')::boolean, FALSE)) STORED`,
	`CREATE INDEX IF NOT EXISTS idx_runtime_policies_alert_lookup
	  ON runtime_policies(alert_only, enabled, det_type)
	  WHERE alert_only = TRUE AND enabled = TRUE`,

	`CREATE TABLE IF NOT EXISTS violation_acks (
	key        TEXT PRIMARY KEY,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`ALTER TABLE violation_acks ADD COLUMN IF NOT EXISTS type       TEXT        NOT NULL DEFAULT 'silent'`,
	`ALTER TABLE violation_acks ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ`,
	`CREATE INDEX IF NOT EXISTS idx_violation_acks_expires
	ON violation_acks(expires_at) WHERE expires_at IS NOT NULL`,

	`DROP TABLE IF EXISTS policy_violations`,
	`DROP TABLE IF EXISTS violation_fps`,
	`DELETE FROM violation_acks WHERE type IN ('fp','resolved')`,

	`CREATE TABLE IF NOT EXISTS kvisior_violations (
	id          BIGSERIAL    PRIMARY KEY,
	ts          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
	vtype       TEXT         NOT NULL,
	rule_id     TEXT         NOT NULL DEFAULT '',
	rule_name   TEXT         NOT NULL DEFAULT '',
	sev         TEXT         NOT NULL DEFAULT '',
	namespace   TEXT         NOT NULL DEFAULT '',
	pod         TEXT         NOT NULL DEFAULT '',
	fingerprint TEXT         NOT NULL DEFAULT '',
	data        JSONB        NOT NULL
)`,
	`ALTER TABLE kvisior_violations ADD COLUMN IF NOT EXISTS fingerprint TEXT NOT NULL DEFAULT ''`,

	`ALTER TABLE kvisior_violations ADD COLUMN IF NOT EXISTS state            TEXT        NOT NULL DEFAULT 'ACTIVE'`,
	`ALTER TABLE kvisior_violations ADD COLUMN IF NOT EXISTS state_expires_at TIMESTAMPTZ`,
	`ALTER TABLE kvisior_violations ADD COLUMN IF NOT EXISTS state_changed_at TIMESTAMPTZ`,
	`ALTER TABLE kvisior_violations ADD COLUMN IF NOT EXISTS last_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW()`,
	`CREATE INDEX IF NOT EXISTS idx_kv_viol_ts        ON kvisior_violations(ts DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_kv_viol_type      ON kvisior_violations(vtype, ts DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_kv_viol_since     ON kvisior_violations(id)`,
	`CREATE INDEX IF NOT EXISTS idx_kv_viol_state     ON kvisior_violations(state, state_expires_at)`,
	`CREATE INDEX IF NOT EXISTS idx_kv_viol_last_seen ON kvisior_violations(state, last_seen)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_kv_viol_fp ON kvisior_violations(fingerprint)
	WHERE fingerprint != ''`,
	`CREATE TABLE IF NOT EXISTS pod_syscall_watches (
	pod_key   TEXT PRIMARY KEY,
	namespace TEXT NOT NULL,
	pod       TEXT NOT NULL,
	syscalls  TEXT NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE TABLE IF NOT EXISTS image_scans (
	image      TEXT        PRIMARY KEY,
	scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	data       JSONB       NOT NULL
)`,
	`CREATE INDEX IF NOT EXISTS idx_image_scans_scanned_at ON image_scans(scanned_at DESC)`,
	`CREATE TABLE IF NOT EXISTS image_histories (
	image      TEXT        PRIMARY KEY,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	data       JSONB       NOT NULL
)`,
	`CREATE TABLE IF NOT EXISTS scanner_state (
	key        TEXT        PRIMARY KEY,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	data       JSONB       NOT NULL
)`,
	`CREATE TABLE IF NOT EXISTS audit_runs (
	id         BIGSERIAL    PRIMARY KEY,
	tool       TEXT         NOT NULL,
	run_id     TEXT         NOT NULL DEFAULT '',
	status     TEXT         NOT NULL DEFAULT '',
	started_at TIMESTAMPTZ,
	done_at    TIMESTAMPTZ,
	created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
	data       JSONB        NOT NULL
)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_runs_tool ON audit_runs(tool, created_at DESC)`,

	`CREATE TABLE IF NOT EXISTS admin_groups (
	id          TEXT PRIMARY KEY,
	name        TEXT UNIQUE NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	role        TEXT NOT NULL DEFAULT 'ro',
	created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE TABLE IF NOT EXISTS admin_users (
	id            TEXT PRIMARY KEY,
	username      TEXT UNIQUE NOT NULL,
	email         TEXT NOT NULL DEFAULT '',
	full_name     TEXT NOT NULL DEFAULT '',
	group_id      TEXT REFERENCES admin_groups(id) ON DELETE SET NULL,
	role          TEXT NOT NULL DEFAULT 'ro',
	password_hash TEXT NOT NULL DEFAULT '',
	created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS password_hash TEXT NOT NULL DEFAULT ''`,
	`CREATE TABLE IF NOT EXISTS admin_sessions (
	id           TEXT PRIMARY KEY,
	user_id      TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
	created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	expires_at   TIMESTAMPTZ NOT NULL,
	last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE INDEX IF NOT EXISTS idx_admin_sessions_user ON admin_sessions(user_id)`,
	`CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON admin_sessions(expires_at)`,
	`CREATE TABLE IF NOT EXISTS admin_tokens (
	id           TEXT PRIMARY KEY,
	name         TEXT NOT NULL,
	token_hash   TEXT UNIQUE NOT NULL,
	role         TEXT NOT NULL DEFAULT 'ro',
	user_id      TEXT REFERENCES admin_users(id) ON DELETE CASCADE,
	created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	expires_at   TIMESTAMPTZ,
	last_used_at TIMESTAMPTZ
)`,
	`CREATE INDEX IF NOT EXISTS idx_admin_users_group ON admin_users(group_id)`,
	`CREATE INDEX IF NOT EXISTS idx_admin_tokens_user ON admin_tokens(user_id)`,

	`CREATE TABLE IF NOT EXISTS network_baselines (
	key                    TEXT PRIMARY KEY,
	ns                     TEXT NOT NULL,
	dep_name               TEXT NOT NULL,
	dep_id                 TEXT,
	observation_period_end TIMESTAMPTZ NOT NULL,
	user_locked            BOOLEAN NOT NULL DEFAULT FALSE,
	baseline_peers         JSONB NOT NULL DEFAULT '{}',
	forbidden_peers        JSONB NOT NULL DEFAULT '{}',
	updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`ALTER TABLE network_baselines ADD COLUMN IF NOT EXISTS baseline_binaries JSONB NOT NULL DEFAULT '{}'`,
	`CREATE TABLE IF NOT EXISTS anomaly_events (
	id       BIGSERIAL PRIMARY KEY,
	ts       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	kind     TEXT NOT NULL,
	data     JSONB NOT NULL
)`,
	`CREATE INDEX IF NOT EXISTS idx_anomaly_events_ts ON anomaly_events(ts)`,
	`ALTER TABLE anomaly_events ADD COLUMN IF NOT EXISTS silenced_at TIMESTAMPTZ`,
	`CREATE INDEX IF NOT EXISTS idx_anomaly_events_silenced_at ON anomaly_events(silenced_at)`,
	`ALTER TABLE anomaly_events ADD COLUMN IF NOT EXISTS ext_id TEXT`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_anomaly_events_ext_id ON anomaly_events(ext_id)`,
	`ALTER TABLE anomaly_events DROP COLUMN IF EXISTS severity`,
	`CREATE TABLE IF NOT EXISTS anomaly_silents (
	type        TEXT NOT NULL,
	key         TEXT NOT NULL,
	summary     TEXT NOT NULL DEFAULT '',
	created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (type, key)
)`,

	`CREATE TABLE IF NOT EXISTS audit_events (
	id       BIGSERIAL PRIMARY KEY,
	ts       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	"user"   TEXT,
	kind     TEXT,
	ns       TEXT,
	resource TEXT,
	data     JSONB NOT NULL
)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_events_ts ON audit_events(ts)`,

	`CREATE TABLE IF NOT EXISTS container_logs (
	id        BIGSERIAL PRIMARY KEY,
	ts        TIMESTAMPTZ NOT NULL,
	ns        TEXT NOT NULL,
	pod       TEXT NOT NULL,
	container TEXT NOT NULL,
	log       TEXT NOT NULL
)`,
	`CREATE INDEX IF NOT EXISTS idx_container_logs_lookup
	ON container_logs(ns, pod, container, ts)`,

	`CREATE INDEX IF NOT EXISTS idx_container_logs_ts ON container_logs(ts)`,
	`CREATE TABLE IF NOT EXISTS log_cursors (
	key        TEXT PRIMARY KEY,
	cursor_ts  TIMESTAMPTZ NOT NULL,
	node       TEXT,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,

	`ALTER TABLE log_cursors ADD COLUMN IF NOT EXISTS node TEXT`,
	`CREATE TABLE IF NOT EXISTS snapshot_cache (
	key        TEXT PRIMARY KEY,
	data       BYTEA NOT NULL,
	etag       TEXT NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,

	`CREATE TABLE IF NOT EXISTS forensic_watches (
	key        TEXT PRIMARY KEY,
	ns         TEXT NOT NULL,
	pod        TEXT NOT NULL,
	started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	active     BOOLEAN NOT NULL DEFAULT TRUE
)`,
	`CREATE TABLE IF NOT EXISTS forensic_events (
	id         BIGSERIAL PRIMARY KEY,
	ts         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	ns         TEXT NOT NULL,
	pod        TEXT NOT NULL,
	path       TEXT NOT NULL,
	op         TEXT NOT NULL,
	size       BIGINT,
	mtime      TEXT,
	sha256     TEXT,
	snapped_at TEXT
)`,
	`CREATE INDEX IF NOT EXISTS idx_forensic_events_ns_pod_ts ON forensic_events(ns, pod, ts)`,

	`CREATE INDEX IF NOT EXISTS idx_forensic_events_ts ON forensic_events(ts)`,

	`DELETE FROM forensic_events a USING forensic_events b
	 WHERE a.id > b.id AND a.ns = b.ns AND a.pod = b.pod AND a.path = b.path
	   AND a.op = b.op AND a.snapped_at IS NOT DISTINCT FROM b.snapped_at`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_forensic_events_dedup
	ON forensic_events(ns, pod, path, op, snapped_at)`,

	`CREATE TABLE IF NOT EXISTS honeypot_hidden_events (
	namespace  TEXT NOT NULL,
	honeypot   TEXT NOT NULL,
	event_id   TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (namespace, honeypot, event_id)
)`,

	`CREATE TABLE IF NOT EXISTS honeypot_events (
	namespace  TEXT        NOT NULL,
	honeypot   TEXT        NOT NULL,
	event_id   TEXT        NOT NULL,
	ts         TEXT        NOT NULL DEFAULT '',
	data       JSONB       NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (namespace, honeypot, event_id)
)`,
	`CREATE INDEX IF NOT EXISTS idx_honeypot_events_lookup
	ON honeypot_events(namespace, honeypot, ts)`,
	`CREATE INDEX IF NOT EXISTS idx_honeypot_events_created_at
	ON honeypot_events(created_at)`,
}
