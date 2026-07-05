package consumer

import (
	"os"
	"strconv"
	"strings"
)

func clone(base *AnomalyEvent) *AnomalyEvent {
	cp := *base
	return &cp
}

func strVal(m map[string]interface{}, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func extractIP(ev map[string]interface{}) string {
	if ip := addrFieldIP(ev); ip != "" {
		return ip
	}
	if cmdline, _ := ev["cmdline"].(string); cmdline != "" {
		if parseIPFromAddr(cmdline) != "" {
			return cmdline
		}
	}
	return ""
}

func extractPort(ev map[string]interface{}) uint32 {
	args, _ := ev["args"].(map[string]interface{})
	if args != nil {
		for _, key := range []string{"addr", "address", "sockaddr"} {
			addr, _ := args[key].(map[string]interface{})
			if addr == nil {
				continue
			}
			switch v := addr["sin_port"].(type) {
			case string:
				if p, err := strconv.ParseUint(v, 10, 16); err == nil && p > 0 {
					return uint32(p)
				}
			case float64:
				if v > 0 && v <= 65535 {
					return uint32(v)
				}
			}
		}
	}
	return 0
}

func addrFieldIP(ev map[string]interface{}) string {
	args, _ := ev["args"].(map[string]interface{})
	if args == nil {
		return ""
	}
	for _, key := range []string{"addr", "address", "sockaddr"} {
		addr, _ := args[key].(map[string]interface{})
		if addr == nil {
			continue
		}

		if ip, ok := addr["sin_addr"].(string); ok && ip != "" {
			return ip
		}
		if ip, ok := addr["sin6_addr"].(string); ok && ip != "" {
			return ip
		}
	}
	return ""
}

func parseIPFromAddr(addr string) string {
	if addr == "" {
		return ""
	}
	if addr[0] == '[' {
		if end := strings.Index(addr, "]"); end > 0 {
			return addr[1:end]
		}
	}
	if idx := strings.LastIndex(addr, ":"); idx > 0 {
		ip := addr[:idx]
		if strings.Count(ip, ".") == 3 || strings.Contains(ip, ":") {
			return ip
		}
	}
	if strings.Count(addr, ".") == 3 {
		return addr
	}
	return ""
}

func envBool(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if v == "" {
		return def
	}
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}
