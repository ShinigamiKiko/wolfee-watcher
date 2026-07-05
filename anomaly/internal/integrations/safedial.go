package integrations

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

func secureHTTPClient(timeout time.Duration) *http.Client {
	policy := loadInternalDialPolicy()
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	dialer.Control = func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("ssrf guard: unresolved address %s", address)
		}
		if !policy.permits(ip) {
			return fmt.Errorf("ssrf guard: refusing to connect to non-public address %s "+
				"(set INTEGRATIONS_ALLOW_INTERNAL=true or INTEGRATIONS_ALLOWED_CIDRS to permit)", address)
		}
		return nil
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
		},
	}
}

type internalDialPolicy struct {
	allowAll bool
	allowed  []*net.IPNet
}

func loadInternalDialPolicy() internalDialPolicy {
	var p internalDialPolicy
	switch strings.ToLower(strings.TrimSpace(os.Getenv("INTEGRATIONS_ALLOW_INTERNAL"))) {
	case "1", "true", "yes", "on":
		p.allowAll = true
	}
	for _, c := range strings.Split(os.Getenv("INTEGRATIONS_ALLOWED_CIDRS"), ",") {
		if c = strings.TrimSpace(c); c == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(c); err == nil {
			p.allowed = append(p.allowed, n)
		}
	}
	return p
}

func (p internalDialPolicy) permits(ip net.IP) bool {
	if isPublicIP(ip) {
		return true
	}
	if neverDialable(ip) {
		return false
	}
	if p.allowAll {
		return true
	}
	for _, n := range p.allowed {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

var metadataIPs = []net.IP{
	net.ParseIP("fd00:ec2::254"),
	net.ParseIP("100.100.100.200"),
}

func neverDialable(ip net.IP) bool {
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, m := range metadataIPs {
		if m != nil && ip.Equal(m) {
			return true
		}
	}
	return false
}

func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return false
	}

	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return false
	}
	return true
}
