package alerter

import (
	"testing"

	"github.com/wolfee-watcher/tracee-bridge/internal/mapper"
	"github.com/wolfee-watcher/tracee-bridge/internal/matcher"
)

func TestAlertSeverityPrefersPolicy(t *testing.T) {
	rule := matcher.Rule{Sev: "critical"}
	event := &mapper.UIEvent{Severity: "low"}
	if got := alertSeverity(rule, event); got != "CRITICAL" {
		t.Fatalf("severity = %q", got)
	}
}

func TestAlertSeverityFallsBackToEvent(t *testing.T) {
	event := &mapper.UIEvent{Severity: "medium"}
	if got := alertSeverity(matcher.Rule{}, event); got != "MEDIUM" {
		t.Fatalf("severity = %q", got)
	}
}

func TestAlertNamePrefersPolicy(t *testing.T) {
	rule := matcher.Rule{
		ID: "rule-1", Name: "Shadow file access", DetType: "LSM",
		Syscall: "security_file_open",
	}
	if got := alertName(rule); got != "Shadow file access" {
		t.Fatalf("name = %q", got)
	}
}

func TestAlertNameKeepsGeneratedFallback(t *testing.T) {
	rule := matcher.Rule{ID: "rule-1", DetType: "Tracepoint", Syscall: "module_load"}
	if got := alertName(rule); got != "Tracepoint: module_load" {
		t.Fatalf("name = %q", got)
	}
}
