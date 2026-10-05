package auditrules

import (
	"net"
	"testing"
)

func TestClientIPIgnoresWhatTheClientForwards(t *testing.T) {
	office, err := ParseProxies("")
	if err != nil || len(office) != 0 {
		t.Fatalf("an empty list trusts nothing: %v %v", office, err)
	}
	balancer, err := ParseProxies("203.0.113.48, 198.51.100.0/24 , fd00::1")
	if err != nil || len(balancer) != 3 {
		t.Fatalf("proxies: %v %v", balancer, err)
	}
	cases := []struct {
		name    string
		chain   []string
		trusted bool
		want    string
	}{
		{"no record", nil, false, ""},
		{"direct", []string{"203.0.113.9"}, false, "203.0.113.9"},
		{"forged header, direct connection", []string{"10.20.14.36", "203.0.113.9"}, false, "203.0.113.9"},
		{"forged header, proxies configured", []string{"10.20.14.36", "203.0.113.9"}, true, "203.0.113.9"},
		{"through the balancer", []string{"10.20.14.36", "203.0.113.48"}, true, "10.20.14.36"},
		{"forged header in front of the balancer", []string{"10.20.14.36", "192.0.2.77", "203.0.113.48"}, true, "192.0.2.77"},
		{"two trusted hops", []string{"192.0.2.77", "198.51.100.5", "203.0.113.48"}, true, "192.0.2.77"},
		{"ipv6 proxy", []string{"192.0.2.77", "fd00::1"}, true, "192.0.2.77"},
		{"only proxies", []string{"198.51.100.5", "203.0.113.48"}, true, "198.51.100.5"},
	}
	for _, c := range cases {
		trusted := office
		if c.trusted {
			trusted = balancer
		}
		if got := ClientIP(c.chain, trusted); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestParseProxiesRejectsWhatWouldTrustTooMuch(t *testing.T) {
	for _, bad := range []string{"0.0.0.0/0", "::/0", "::ffff:0:0/96", "balancer.example.com", "10.0.0.300", "10.0.0.0/33"} {
		if _, err := ParseProxies(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestMappedProxyCIDRSurvivesSavingAndLoading(t *testing.T) {
	networks, err := ParseProxies("::ffff:192.0.2.0/120")
	if err != nil {
		t.Fatal(err)
	}
	saved := networks[0].String()
	if saved != "192.0.2.0/24" {
		t.Fatalf("saved network %q", saved)
	}
	loaded, err := ParseProxies(saved)
	if err != nil || len(loaded) != 1 {
		t.Fatalf("saved network cannot be loaded: %v %v", loaded, err)
	}
	if !loaded[0].Contains(net.ParseIP("192.0.2.77")) || loaded[0].Contains(net.ParseIP("203.0.113.48")) {
		t.Fatal("normalizing the mapped CIDR changed which proxies are trusted")
	}
}

func TestSourceIPRuleCannotBePassedWithAHeader(t *testing.T) {
	m := NewMatcher()
	m.Replace([]Rule{
		rule("outside-office", func(r *Rule) {
			r.Spec.Kinds = []string{KindDelete}
			r.Spec.IPMode, r.Spec.IPList = IPNotIn, "10.20.0.0/16"
		}),
		rule("from-office", func(r *Rule) {
			r.Spec.Kinds = []string{KindDelete}
			r.Spec.IPMode, r.Spec.IPList = IPIn, "10.20.0.0/16"
		}),
	})
	forged := &Event{Kind: KindDelete, Resource: "secrets", Namespace: "prod", Name: "db", User: "d.orlov",
		SourceIPs: []string{"10.20.14.36", "203.0.113.9"}}
	if got := ids(m.Match("c1", forged, false)); len(got) != 1 || got[0] != "outside-office" {
		t.Fatalf("a forwarded address must not stand in for the real one: %v", got)
	}
	behind := *forged
	behind.ClientIP = "10.20.14.36"
	if got := ids(m.Match("c1", &behind, false)); len(got) != 1 || got[0] != "from-office" {
		t.Fatalf("the resolved client address decides: %v", got)
	}
}
