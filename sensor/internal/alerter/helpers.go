package alerter

import (
	corev1 "k8s.io/api/core/v1"
)

func capabilityDropList(c corev1.Container) []string {
	if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
		return nil
	}
	out := make([]string, 0, len(c.SecurityContext.Capabilities.Drop))
	for _, v := range c.SecurityContext.Capabilities.Drop {
		out = append(out, string(v))
	}
	return out
}

func containsCap(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func hasAny(list []string, want ...string) bool {
	for _, v := range list {
		for _, w := range want {
			if v == w {
				return true
			}
		}
	}
	return false
}

func itoa(n int) string {

	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
