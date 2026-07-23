package schema

const (
	RoleUI           = "ww_ui"
	RoleTraceeBridge = "ww_tracee_bridge"
	RoleAnomaly      = "ww_anomaly"
)

var PasswordEnv = map[string]string{
	RoleUI:           "SERVICE_DB_PASSWORD_UI",
	RoleTraceeBridge: "SERVICE_DB_PASSWORD_TRACEE_BRIDGE",
	RoleAnomaly:      "SERVICE_DB_PASSWORD_ANOMALY",
}

var DroppedRoles = []string{
	"ww_sentry_audit",
	"ww_forensic_watcher",
	"ww_sensor",
	"ww_scanner_agent",
}

type TableGrant struct {
	Table string
	Privs string
}

var Grants = map[string][]TableGrant{

	RoleUI: {
		{"alerts", "SELECT, INSERT, DELETE"},
		{"alert_deliveries", "SELECT, INSERT, UPDATE, DELETE"},
		{"integrations", "SELECT"},
		{"admin_groups", "SELECT, INSERT, UPDATE, DELETE"},
		{"admin_users", "SELECT, INSERT, UPDATE, DELETE"},
		{"admin_sessions", "SELECT, INSERT, UPDATE, DELETE"},
		{"admin_tokens", "SELECT, INSERT, UPDATE, DELETE"},
		{"kvisior_violations", "SELECT, INSERT, UPDATE, DELETE"},
		{"pod_syscall_watches", "SELECT, INSERT, UPDATE, DELETE"},
		{"image_scans", "SELECT, INSERT, UPDATE, DELETE"},
		{"image_histories", "SELECT, INSERT, UPDATE, DELETE"},
		{"scanner_state", "SELECT, INSERT, UPDATE"},
		{"audit_runs", "SELECT, INSERT, DELETE"},
		{"runtime_policies", "SELECT, INSERT, UPDATE, DELETE"},
		{"violation_acks", "SELECT, INSERT, UPDATE, DELETE"},
		{"audit_events", "SELECT, INSERT, DELETE"},
		{"forensic_events", "SELECT, INSERT, DELETE"},
		{"forensic_watches", "SELECT, INSERT, UPDATE, DELETE"},
		{"honeypot_hidden_events", "SELECT, INSERT, DELETE"},
		{"honeypot_events", "SELECT, INSERT, DELETE"},
		{"container_logs", "SELECT, INSERT, DELETE"},

		{"log_cursors", "SELECT, INSERT, UPDATE, DELETE"},
		{"snapshot_cache", "SELECT, INSERT, UPDATE"},
	},

	RoleTraceeBridge: {
		{"alerts", "SELECT, INSERT"},
		{"runtime_policies", "SELECT"},
	},

	RoleAnomaly: {
		{"integrations", "SELECT, INSERT, UPDATE, DELETE"},
		{"network_baselines", "SELECT, INSERT, UPDATE"},
		{"anomaly_events", "SELECT, INSERT, UPDATE, DELETE"},
		{"anomaly_silents", "SELECT, INSERT, UPDATE, DELETE"},
	},
}
