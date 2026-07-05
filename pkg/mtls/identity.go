package mtls

type ServiceType string

const (
	Sensor          ServiceType = "sensor"
	TraceeBridge    ServiceType = "tracee-bridge"
	AnomalyDetector ServiceType = "anomaly-detector"
	SentryAudit     ServiceType = "sentry-audit"
	ScannerAgent    ServiceType = "scanner-agent"
	AuditRunner     ServiceType = "audit-runner"
	HoneyOperator   ServiceType = "honey-operator"
	Kvisior         ServiceType = "kvisior"
	ForensicWatcher ServiceType = "forensic-watcher"
)
