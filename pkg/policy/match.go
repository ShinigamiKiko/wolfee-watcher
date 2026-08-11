package policy

import "strings"

var ExecSyscalls = map[string]bool{
	"execve": true, "execveat": true, "sched_process_exec": true,
}

func IsExecSyscall(syscall string) bool {
	return ExecSyscalls[syscall]
}

func NamespaceMatches(namespace, pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || pattern == "*" {
		return true
	}
	return globMatch(strings.ToLower(namespace), strings.ToLower(pattern))
}

func PodMatches(pod, pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || pattern == "*" {
		return true
	}
	p := strings.ToLower(pod)
	pat := strings.ToLower(pattern)
	if !strings.Contains(pat, "*") {
		return strings.Contains(p, pat)
	}
	return globMatch(p, pat)
}

func ProcessMatches(pattern, process, execpath, cmdline string) bool {
	pf := strings.ToLower(strings.TrimSpace(pattern))
	if pf == "" || pf == "*" {
		return true
	}
	cmd0 := cmdline
	if i := strings.IndexByte(cmd0, ' '); i >= 0 {
		cmd0 = cmd0[:i]
	}
	for _, candidate := range []string{process, execpath, cmd0} {
		c := strings.ToLower(strings.TrimSpace(candidate))
		if c == "" {
			continue
		}
		if c == pf || strings.HasSuffix(c, "/"+pf) {
			return true
		}
	}
	return false
}

func globMatch(s, pattern string) bool {
	if !strings.Contains(pattern, "*") {
		return s == pattern
	}
	parts := strings.Split(pattern, "*")
	anchorStart := !strings.HasPrefix(pattern, "*")
	anchorEnd := !strings.HasSuffix(pattern, "*")
	rest := s
	for i, p := range parts {
		if p == "" {
			continue
		}
		switch {
		case i == 0 && anchorStart:
			if !strings.HasPrefix(rest, p) {
				return false
			}
			rest = rest[len(p):]
		case i == len(parts)-1 && anchorEnd:
			if !strings.HasSuffix(rest, p) {
				return false
			}
			rest = rest[:len(rest)-len(p)]
		default:
			idx := strings.Index(rest, p)
			if idx < 0 {
				return false
			}
			rest = rest[idx+len(p):]
		}
	}
	return true
}
