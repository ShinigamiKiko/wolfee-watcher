package policy

import "testing"

func TestNamespaceMatchesIsNotSubstring(t *testing.T) {
	cases := []struct {
		ns      string
		pattern string
		want    bool
	}{
		{"production", "prod", false},
		{"prod-test", "prod", false},
		{"prod", "prod", true},
		{"production", "prod*", true},
		{"prod-test", "*test", true},
		{"anything", "", true},
		{"anything", "*", true},
		{"kube-system", "kube-*", true},
		{"payments", "kube-*", false},
	}
	for _, c := range cases {
		if got := NamespaceMatches(c.ns, c.pattern); got != c.want {
			t.Errorf("NamespaceMatches(%q, %q) = %v, want %v", c.ns, c.pattern, got, c.want)
		}
	}
}

func TestPodMatches(t *testing.T) {
	cases := []struct {
		pod     string
		pattern string
		want    bool
	}{
		{"api-gateway-7d9f-xyz", "api-gateway", true},
		{"worker-1", "api-gateway", false},
		{"api-gateway-7d9f-xyz", "api-*", true},
		{"backend-api-1", "api-*", false},
		{"anything", "", true},
	}
	for _, c := range cases {
		if got := PodMatches(c.pod, c.pattern); got != c.want {
			t.Errorf("PodMatches(%q, %q) = %v, want %v", c.pod, c.pattern, got, c.want)
		}
	}
}

func TestProcessMatches(t *testing.T) {
	cases := []struct {
		pattern  string
		process  string
		execpath string
		cmdline  string
		want     bool
	}{
		{"nc", "nc", "", "", true},
		{"nc", "", "/usr/bin/nc", "", true},
		{"nc", "", "", "/bin/nc -l 4444", true},
		{"nc", "", "/opt/nc/tool", "", false},
		{"nc", "ncat", "", "", false},
		{"", "anything", "", "", true},
	}
	for _, c := range cases {
		if got := ProcessMatches(c.pattern, c.process, c.execpath, c.cmdline); got != c.want {
			t.Errorf("ProcessMatches(%q, %q, %q, %q) = %v, want %v",
				c.pattern, c.process, c.execpath, c.cmdline, got, c.want)
		}
	}
}
