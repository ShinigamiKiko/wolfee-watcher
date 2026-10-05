package store

import "testing"

func TestValidAuditLogPath(t *testing.T) {
	for _, p := range []string{"/var/log/kubernetes/audit.log", "/var/lib/rancher/k3s/server/logs/audit.log", "/data/k8s_audit/audit-1.log"} {
		if err := ValidAuditLogPath(p); err != nil {
			t.Errorf("%q rejected: %v", p, err)
		}
	}
	for _, p := range []string{
		"", "audit.log", "/audit.log", "/var/log/../etc/shadow", "/var/log//audit.log", "/var/log/audit/",
		"/var/log/a b.log", "/var/log/$(id).log", "/var/log/audit.log\n",
	} {
		if err := ValidAuditLogPath(p); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
}

func TestPlanAuditLog(t *testing.T) {
	nodes := []AuditLogNode{
		{Node: "cp-1", DetectedPath: "/var/log/kubernetes/audit.log"},
		{Node: "cp-2", DetectedPath: "/var/log/kubernetes/audit.log"},
		{Node: "cp-3", DetectedPath: "/data/audit/audit.log"},
		{Node: "cp-4"},
	}
	auto := PlanAuditLog(AuditLogSettings{Enabled: true}, true, nodes)
	if !auto.Enabled || auto.Path != "/var/log/kubernetes/audit.log" {
		t.Fatalf("the most common detected path must become the default: %+v", auto)
	}
	if len(auto.NodePaths) != 1 || auto.NodePaths["cp-3"] != "/data/audit/audit.log" {
		t.Fatalf("only nodes that differ from the default are listed: %+v", auto.NodePaths)
	}

	manual := PlanAuditLog(AuditLogSettings{
		Enabled: true, Path: "/logs/audit.log", NodePaths: map[string]string{"cp-2": "/other/audit.log", "gone": "/x/a.log"},
	}, true, nodes)
	if manual.Path != "/logs/audit.log" || manual.NodePaths["cp-2"] != "/other/audit.log" || manual.NodePaths["gone"] != "/x/a.log" {
		t.Fatalf("explicit settings win over detection: %+v", manual)
	}
	if _, listed := manual.NodePaths["cp-3"]; listed {
		t.Fatalf("an explicit default path overrides detection on every node: %+v", manual.NodePaths)
	}

	if auto.Rev == manual.Rev || auto.Rev == "" {
		t.Fatalf("revisions must differ: %q %q", auto.Rev, manual.Rev)
	}
	if again := PlanAuditLog(AuditLogSettings{Enabled: true}, true, nodes); again.Rev != auto.Rev {
		t.Fatalf("the revision must be stable: %q %q", again.Rev, auto.Rev)
	}
	if off := PlanAuditLog(AuditLogSettings{Enabled: true}, false, nodes); off.Enabled || off.Managed {
		t.Fatalf("without saved settings the reader is not managed: %+v", off)
	}
}
