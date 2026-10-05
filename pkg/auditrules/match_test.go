package auditrules

import "testing"

func rule(id string, mut func(*Rule)) Rule {
	r := Rule{ID: id, Name: id, Enabled: true, Severity: SevHigh, Spec: Spec{Kinds: []string{KindExec}}}
	if mut != nil {
		mut(&r)
	}
	r.Normalize()
	return r
}

func denied() *bool { f := false; return &f }

func ids(rules []Rule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.ID)
	}
	return out
}

func TestGlob(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "", true},
		{"*", "anything", true},
		{"prod-*", "prod-payments", true},
		{"prod-*", "staging", false},
		{"*-db", "payments-db", true},
		{"*-db", "payments-db-1", false},
		{"system:serviceaccount:ci:*", "system:serviceaccount:ci:deployer", true},
		{"a*a", "a", false},
		{"a*b*c", "a-x-b-y-c", true},
		{"PROD-*", "prod-api", true},
		{"exact", "exact", true},
		{"exact", "exactly", false},
	}
	for _, c := range cases {
		if got := Glob(c.pattern, c.s); got != c.want {
			t.Errorf("Glob(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}

func TestMatchConditions(t *testing.T) {
	m := NewMatcher()
	m.Replace([]Rule{
		rule("any-exec", nil),
		rule("prod-only", func(r *Rule) { r.Spec.NS = "prod-*, payments" }),
		rule("not-kube", func(r *Rule) { r.Spec.NSExclude = "kube-*" }),
		rule("people", func(r *Rule) { r.Spec.Subject = SubjectPeople }),
		rule("robots", func(r *Rule) { r.Spec.Subject = SubjectSA }),
		rule("named-user", func(r *Rule) { r.Spec.Users = "a.sokolov, m.*" }),
		rule("not-ci", func(r *Rule) { r.Spec.UsersExclude = "system:serviceaccount:ci:*" }),
		rule("shell", func(r *Rule) { r.Spec.Cmd = "/bin/sh" }),
		rule("pods-only", func(r *Rule) { r.Spec.Resources = []string{"pods"} }),
		rule("secrets-only", func(r *Rule) { r.Spec.Resources = []string{"secrets"} }),
		rule("other-kind", func(r *Rule) { r.Spec.Kinds = []string{KindCreate} }),
		rule("this-cluster", func(r *Rule) { r.Spec.Clusters = []string{"k8s-test"} }),
		rule("other-cluster", func(r *Rule) { r.Spec.Clusters = []string{"k8s-82"} }),
		rule("disabled", func(r *Rule) { r.Enabled = false }),
		rule("alert-only", func(r *Rule) { r.Enabled = false; r.Alert = true }),
	})

	ev := &Event{Kind: KindExec, Resource: "pods", Namespace: "prod-api", Name: "gateway-1",
		User: "a.sokolov", Commands: []string{"/bin/sh", "-c", "env"}}
	got := map[string]bool{}
	for _, id := range ids(m.Match("k8s-test", ev, false)) {
		got[id] = true
	}
	want := []string{"any-exec", "prod-only", "not-kube", "people", "named-user", "not-ci", "shell", "pods-only", "this-cluster", "alert-only"}
	for _, id := range want {
		if !got[id] {
			t.Errorf("expected rule %q to match", id)
		}
		delete(got, id)
	}
	for id := range got {
		t.Errorf("rule %q matched but should not", id)
	}
}

func TestMatchSourceIP(t *testing.T) {
	m := NewMatcher()
	m.Replace([]Rule{
		rule("no-ip-rule", nil),
		rule("office", func(r *Rule) { r.Spec.IPMode = IPIn; r.Spec.IPList = "10.20.0.0/16" }),
		rule("outside", func(r *Rule) { r.Spec.IPMode = IPNotIn; r.Spec.IPList = "10.*, 192.168.0.0/16" }),
	})

	noIP := &Event{Kind: KindExec, User: "a.sokolov"}
	if got := ids(m.Match("c", noIP, false)); len(got) != 1 || got[0] != "no-ip-rule" {
		t.Errorf("event without IP must match only rules without IP conditions, got %v", got)
	}

	inside := &Event{Kind: KindExec, User: "a.sokolov", SourceIPs: []string{"10.20.14.36"}}
	if got := ids(m.Match("c", inside, true)); len(got) != 1 || got[0] != "office" {
		t.Errorf("office address on the IP pass: got %v", got)
	}

	outside := &Event{Kind: KindExec, User: "d.orlov", SourceIPs: []string{"203.0.113.48"}}
	if got := ids(m.Match("c", outside, true)); len(got) != 1 || got[0] != "outside" {
		t.Errorf("external address on the IP pass: got %v", got)
	}
}

func TestMatchResult(t *testing.T) {
	m := NewMatcher()
	m.Replace([]Rule{
		rule("denied", func(r *Rule) { r.Spec.Kinds = []string{KindCreate}; r.Spec.Result = ResultDenied }),
		rule("allowed", func(r *Rule) { r.Spec.Kinds = []string{KindCreate}; r.Spec.Result = ResultAllowed }),
	})
	if got := ids(m.Match("c", &Event{Kind: KindCreate, Allowed: denied()}, false)); len(got) != 1 || got[0] != "denied" {
		t.Errorf("denied event: got %v", got)
	}
	if got := ids(m.Match("c", &Event{Kind: KindCreate}, false)); len(got) != 0 {
		t.Errorf("unknown verdict must defer result rules: got %v", got)
	}
}

func TestCatalogRulesAreValid(t *testing.T) {
	if len(Catalog) != 31 {
		t.Fatalf("catalog has %d rules, want 31", len(Catalog))
	}
	seen := map[string]bool{}
	for _, r := range BuiltinRules() {
		if seen[r.ID] {
			t.Errorf("duplicate builtin id %q", r.ID)
		}
		seen[r.ID] = true
		if err := r.Validate(); err != nil {
			t.Errorf("builtin %q is invalid: %v", r.ID, err)
		}
		if r.Origin != OriginBuiltin || r.Alert {
			t.Errorf("builtin %q must be origin builtin with alerts off", r.ID)
		}
	}
}

func TestValidate(t *testing.T) {
	bad := []func(*Rule){
		func(r *Rule) { r.Name = "" },
		func(r *Rule) { r.Spec.Kinds = nil },
		func(r *Rule) { r.Spec.Kinds = []string{"watch"} },
		func(r *Rule) { r.Severity = "urgent" },
		func(r *Rule) { r.Spec.IPMode = IPIn },
		func(r *Rule) { r.Spec.IPMode = IPIn; r.Spec.IPList = "10.0.0.0/99" },
		func(r *Rule) { r.Spec.Resources = []string{"Bad Resource"} },
		func(r *Rule) { r.Spec.Subject = "robots" },
	}
	for i, mut := range bad {
		r := rule("r", nil)
		mut(&r)
		if r.Name != "" {
			r.Normalize()
		}
		if err := r.Validate(); err == nil {
			t.Errorf("case %d: expected a validation error", i)
		}
	}
	if err := rule("ok", func(r *Rule) { r.Spec.IPMode = IPNotIn; r.Spec.IPList = "10.*, 192.168.0.0/16" }).Validate(); err != nil {
		t.Errorf("valid rule rejected: %v", err)
	}
}

func TestNeedsAPILog(t *testing.T) {
	if rule("r", nil).NeedsAPILog() {
		t.Error("exec rule does not need the API log")
	}
	if !rule("r", func(r *Rule) { r.Spec.Kinds = []string{KindGet, KindList} }).NeedsAPILog() {
		t.Error("read-only rule needs the API log")
	}
	if !rule("r", func(r *Rule) { r.Spec.IPMode = IPIn; r.Spec.IPList = "10.*" }).NeedsAPILog() {
		t.Error("rule with an IP condition needs the API log")
	}
}

func TestSystemAdminIsAPerson(t *testing.T) {
	m := NewMatcher()
	m.Replace([]Rule{
		rule("people", func(r *Rule) { r.Spec.Subject = SubjectPeople }),
		rule("robots", func(r *Rule) { r.Spec.Subject = SubjectSA }),
	})
	cases := map[string]string{
		"system:admin":                      "people",
		"kubernetes-admin":                  "people",
		"system:serviceaccount:ci:deployer": "robots",
		"system:node:w1":                    "robots",
		"system:kube-controller-manager":    "robots",
	}
	for user, want := range cases {
		got := ids(m.Match("c", &Event{Kind: KindExec, User: user}, false))
		if len(got) != 1 || got[0] != want {
			t.Errorf("user %q matched %v, want [%s]", user, got, want)
		}
	}
}

func TestMixedKindsNeedAPILog(t *testing.T) {
	for _, kinds := range [][]string{{KindCreate, KindGet}, {KindList, KindUpdate}, {KindCreate, KindList}} {
		if !rule("mixed", func(r *Rule) { r.Spec.Kinds = kinds }).NeedsAPILog() {
			t.Errorf("mixed kinds %v require API log", kinds)
		}
	}
	if !rule("result", func(r *Rule) { r.Spec.Result = ResultDenied }).NeedsAPILog() {
		t.Fatal("final result requires API log")
	}
}
