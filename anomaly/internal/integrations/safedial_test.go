package integrations

import (
	"net"
	"testing"
)

func TestPermitsNeverReExposesMetadata(t *testing.T) {
	metadata := []net.IP{
		net.ParseIP("169.254.169.254"),
		net.ParseIP("fd00:ec2::254"),
		net.ParseIP("100.100.100.200"),
	}

	_, linkLocal, _ := net.ParseCIDR("169.254.0.0/16")
	policies := map[string]internalDialPolicy{
		"allowAll":         {allowAll: true},
		"allowedLinkLocal": {allowed: []*net.IPNet{linkLocal}},
	}
	for name, p := range policies {
		for _, ip := range metadata {
			if p.permits(ip) {
				t.Errorf("policy %q permitted metadata endpoint %s", name, ip)
			}
		}
	}

	if !(internalDialPolicy{allowAll: true}).permits(net.ParseIP("10.1.2.3")) {
		t.Error("allowAll should permit an RFC1918 in-cluster target")
	}

	if !(internalDialPolicy{}).permits(net.ParseIP("1.1.1.1")) {
		t.Error("public IP should always be permitted")
	}

	if (internalDialPolicy{}).permits(net.ParseIP("10.1.2.3")) {
		t.Error("default policy must block RFC1918")
	}
}
