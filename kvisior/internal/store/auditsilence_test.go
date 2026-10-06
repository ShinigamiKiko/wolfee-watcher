package store

import (
	"errors"
	"testing"

	"github.com/wolfee-watcher/pkg/auditrules"
)

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"configmaps/default/x", "configmaps/default/x", true},
		{"configmaps/default/x", "configmaps/default/xy", false},
		{"configmaps/default/*", "configmaps/default/pend-1", true},
		{"configmaps/*/pend-*", "configmaps/default/pend-12", true},
		{"configmaps/*/pend-*", "secrets/default/pend-12", false},
		{"*", "", true},
		{"*-admin", "kubernetes-admin", true},
		{"a*a", "a", false},
		{"system:serviceaccount:ci:*", "system:serviceaccount:ci:runner", true},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.value); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pattern, c.value, got, c.want)
		}
	}
}

func TestSilenceNormalizeAndMatch(t *testing.T) {
	s := AuditSilence{Action: " Create ", Object: "configmaps/default/*", SourceIP: "10.20.0.0/16"}
	if err := s.Normalize(); err != nil {
		t.Fatal(err)
	}
	if s.Action != "create" {
		t.Fatalf("action not normalized: %q", s.Action)
	}
	hit := auditSilenceTarget{action: "create", object: "configmaps/default/a", user: "alice", ip: "10.20.14.36"}
	if !s.matches(hit) {
		t.Fatal("matching alert not silenced")
	}
	for _, miss := range []auditSilenceTarget{
		{action: "delete", object: "configmaps/default/a", ip: "10.20.14.36"},
		{action: "create", object: "configmaps/prod/a", ip: "10.20.14.36"},
		{action: "create", object: "configmaps/default/a", ip: "10.21.0.1"},
		{action: "create", object: "configmaps/default/a", ip: ""},
	} {
		if s.matches(miss) {
			t.Fatalf("silenced %+v", miss)
		}
	}
	cidr := AuditSilence{SourceIP: "10.20.14.36/16"}
	if err := cidr.Normalize(); err != nil || cidr.SourceIP != "10.20.0.0/16" {
		t.Fatalf("CIDR not normalized: %q err=%v", cidr.SourceIP, err)
	}
	for _, bad := range []AuditSilence{
		{},
		{Reason: "only a reason"},
		{Action: "create pods"},
		{SourceIP: "not-an-ip"},
		{SourceIP: "10.0.0.0/40"},
		{User: string([]byte{0xff})},
	} {
		if err := bad.Normalize(); !errors.Is(err, ErrAuditSilenceInvalid) {
			t.Errorf("Normalize(%+v) = %v, want invalid", bad, err)
		}
	}
}

func TestEventTargetUsesTheClientAddress(t *testing.T) {
	ev := &auditrules.Event{Kind: "Create", Resource: "configmaps", Namespace: "default", Name: "x", User: "alice", SourceIPs: []string{"10.0.0.1", "192.0.2.7"}}
	if got := eventTarget(ev); got != (auditSilenceTarget{action: "create", object: "configmaps/default/x", user: "alice", ip: "192.0.2.7"}) {
		t.Fatalf("target = %+v", got)
	}
	cluster := &auditrules.Event{Kind: "delete", Resource: "clusterroles", Name: "edit"}
	if got := eventTarget(cluster).object; got != "clusterroles/edit" {
		t.Fatalf("cluster-scoped object = %q", got)
	}
}
