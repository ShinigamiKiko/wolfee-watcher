package auditrules

import (
	"fmt"
	"net"
)

const maxTrustedProxies = 64

func ParseProxies(list string) ([]*net.IPNet, error) {
	items := splitList(list)
	if len(items) > maxTrustedProxies {
		return nil, fmt.Errorf("at most %d trusted proxies", maxTrustedProxies)
	}
	out := make([]*net.IPNet, 0, len(items))
	for _, item := range items {
		if ip := net.ParseIP(item); ip != nil {
			bits := 8 * net.IPv6len
			if v4 := ip.To4(); v4 != nil {
				ip, bits = v4, 8*net.IPv4len
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, network, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address or a CIDR", item)
		}
		ones, bits := network.Mask.Size()
		if v4 := network.IP.To4(); v4 != nil && bits == 8*net.IPv6len {
			ones -= 8 * (net.IPv6len - net.IPv4len)
			network = &net.IPNet{IP: v4, Mask: net.CIDRMask(ones, 8*net.IPv4len)}
		}
		if ones == 0 {
			return nil, fmt.Errorf("%q would trust every address", item)
		}
		out = append(out, network)
	}
	return out, nil
}

func trustedProxy(address string, trusted []*net.IPNet) bool {
	ip := net.ParseIP(address)
	if ip == nil {
		return false
	}
	for _, network := range trusted {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func ClientIP(chain []string, trusted []*net.IPNet) string {
	for i := len(chain) - 1; i >= 0; i-- {
		if !trustedProxy(chain[i], trusted) {
			return chain[i]
		}
	}
	if len(chain) > 0 {
		return chain[0]
	}
	return ""
}
