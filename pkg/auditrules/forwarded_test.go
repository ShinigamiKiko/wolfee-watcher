package auditrules

import (
	"net"
	"testing"
)

func TestForwardedClaims(t *testing.T) {
	balancer, err := ParseProxies("203.0.113.48")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		chain   []string
		trusted []*net.IPNet
		want    []string
	}{
		{"no record", nil, nil, nil},
		{"direct", []string{"203.0.113.9"}, nil, nil},
		{"forged header", []string{"10.20.14.36", "203.0.113.9"}, nil, []string{"10.20.14.36"}},
		{"forged chain", []string{"10.0.0.1", "10.20.14.36", "203.0.113.9"}, nil, []string{"10.0.0.1", "10.20.14.36"}},
		{"client repeats its own address", []string{"203.0.113.9", "203.0.113.9"}, nil, nil},
		{"through a trusted balancer", []string{"10.20.14.36", "203.0.113.48"}, balancer, nil},
		{"forged in front of the balancer", []string{"192.0.2.66", "10.20.14.36", "203.0.113.48"}, balancer, []string{"192.0.2.66"}},
	}
	for _, c := range cases {
		ev := &Event{SourceIPs: c.chain, ClientIP: ClientIP(c.chain, c.trusted)}
		got := ev.ForwardedClaims()
		if len(got) != len(c.want) {
			t.Errorf("%s: claims %q, want %q", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: claims %q, want %q", c.name, got, c.want)
				break
			}
		}
	}
}

func TestForwardedSpoofBuiltinRule(t *testing.T) {
	var spoof Rule
	for _, r := range BuiltinRules() {
		if r.ID == "forwarded-spoof" {
			spoof = r
		}
	}
	if spoof.ID == "" || !spoof.Enabled || !spoof.Spec.Forwarded {
		t.Fatalf("built-in forwarded-spoof rule missing or disabled: %+v", spoof)
	}
	if err := spoof.Validate(); err != nil {
		t.Fatalf("built-in rule is invalid: %v", err)
	}
	if len(spoof.Spec.Kinds) != len(Kinds) {
		t.Fatalf("rule must cover every action, got %v", spoof.Spec.Kinds)
	}

	m := NewMatcher()
	m.Replace([]Rule{spoof})
	clean := &Event{Kind: KindGet, Resource: "secrets", SourceIPs: []string{"203.0.113.9"}}
	admission := &Event{Kind: KindCreate, Resource: "pods"}
	forged := &Event{Kind: KindGet, Resource: "secrets", SourceIPs: []string{"10.20.14.36", "203.0.113.9"}}

	if got := ids(m.Match("c", clean, false)); len(got) != 0 {
		t.Errorf("direct request matched %v", got)
	}
	if got := ids(m.Match("c", admission, false)); len(got) != 0 {
		t.Errorf("admission event without addresses matched %v", got)
	}
	for _, onlyIPRules := range []bool{false, true} {
		if got := ids(m.Match("c", forged, onlyIPRules)); len(got) != 1 || got[0] != "forwarded-spoof" {
			t.Errorf("forged header (onlyIPRules=%v) matched %v", onlyIPRules, got)
		}
	}
}

func TestForwardedConditionNarrowsCustomRules(t *testing.T) {
	rules := []Rule{
		{ID: "secrets-read", Name: "secrets read", Enabled: true, Severity: SevLow, Spec: Spec{Kinds: []string{KindGet}, Resources: []string{"secrets"}}},
		{ID: "secrets-read-forged", Name: "secrets read, forged", Enabled: true, Severity: SevHigh, Spec: Spec{Kinds: []string{KindGet}, Resources: []string{"secrets"}, Forwarded: true}},
	}
	for i := range rules {
		rules[i].Normalize()
	}
	m := NewMatcher()
	m.Replace(rules)
	forged := &Event{Kind: KindGet, Resource: "secrets", SourceIPs: []string{"10.20.14.36", "203.0.113.9"}}
	direct := &Event{Kind: KindGet, Resource: "secrets", SourceIPs: []string{"203.0.113.9"}}

	if got := ids(m.Match("c", direct, false)); len(got) != 1 || got[0] != "secrets-read" {
		t.Errorf("direct read matched %v", got)
	}
	if got := ids(m.Match("c", forged, false)); len(got) != 2 {
		t.Errorf("forged read matched %v, want both rules", got)
	}
}
