package rules

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

type Rule struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Enabled       *bool  `json:"enabled"`
	Syscall       string `json:"syscall"`
	Category      string `json:"category"`
	DetType       string `json:"detType"`
	Namespace     string `json:"namespace"`
	PodPattern    string `json:"podPattern"`
	ProcessFilter string `json:"processFilter"`
	PathFilter    string `json:"pathFilter"`
	Sev           string `json:"sev"`
}

func (r Rule) isEnabled() bool {
	return r.Enabled == nil || *r.Enabled
}

type Violation struct {
	Rule   string          `json:"rule"`
	RuleID string          `json:"ruleId"`
	Sev    string          `json:"sev"`
	Event  json.RawMessage `json:"event"`
}

type Matcher struct {
	mu       sync.RWMutex
	rules    []Rule
	allowSet map[string]struct{}
}

func New() *Matcher { return &Matcher{} }

func (m *Matcher) Replace(rules []Rule) {
	allow := make(map[string]struct{}, len(rules))
	for _, r := range rules {
		if !r.isEnabled() {
			continue
		}

		if r.Syscall == "" || r.Syscall == "*" {
			continue
		}
		allow[r.Syscall] = struct{}{}
	}
	m.mu.Lock()
	m.rules = rules
	m.allowSet = allow
	m.mu.Unlock()
}

func (m *Matcher) AllowsSyscall(syscall string) bool {
	if syscall == "" {
		return false
	}
	m.mu.RLock()
	_, ok := m.allowSet[syscall]
	m.mu.RUnlock()
	return ok
}

var binaryExec = map[string]struct{}{
	"execve":   {},
	"execveat": {},
}

func IsBinaryExec(syscall string) bool {
	_, ok := binaryExec[syscall]
	return ok
}

func (m *Matcher) AllowsLiveStream(syscall string) bool {
	if IsBinaryExec(syscall) {
		return true
	}
	return m.AllowsSyscall(syscall)
}

func (m *Matcher) Match(ev map[string]interface{}) []Violation {
	m.mu.RLock()
	rules := m.rules
	m.mu.RUnlock()

	raw, _ := json.Marshal(ev)
	var hits []Violation
	for _, r := range rules {
		if !r.isEnabled() {
			continue
		}
		if matches(ev, r) {
			hits = append(hits, Violation{
				Rule:   r.Name,
				RuleID: r.ID,
				Sev:    r.Sev,
				Event:  raw,
			})
		}
	}
	return hits
}

func strField(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

func argsMap(ev map[string]interface{}) map[string]interface{} {
	if a, ok := ev["args"]; ok {
		if am, ok := a.(map[string]interface{}); ok {
			return am
		}
	}
	return nil
}

func matches(ev map[string]interface{}, rule Rule) bool {
	syscall := strField(ev, "syscall")
	category := strField(ev, "category")
	ns := strField(ev, "namespace")
	pod := strField(ev, "pod")

	a := argsMap(ev)
	var argsPathname, argsArgv string
	if a != nil {
		if v, ok := a["pathname"]; ok {
			argsPathname, _ = v.(string)
		}
		if v, ok := a["argv"]; ok {
			switch vt := v.(type) {
			case string:
				argsArgv = vt
			case []interface{}:
				parts := make([]string, 0, len(vt))
				for _, p := range vt {
					if s, ok := p.(string); ok {
						parts = append(parts, s)
					}
				}
				argsArgv = strings.Join(parts, " ")
			}
		}
	}

	process := strField(ev, "process")
	if process == "" && argsPathname != "" {
		parts := strings.Split(argsPathname, "/")
		process = parts[len(parts)-1]
	}
	execpath := strField(ev, "execpath")
	if execpath == "" {
		execpath = argsPathname
	}
	cmdline := strField(ev, "cmdline")
	if cmdline == "" {
		cmdline = argsArgv
	}

	if rule.Syscall != "" && rule.Syscall != "*" {
		if syscall != rule.Syscall {
			return false
		}
	}

	if rule.Category != "" && rule.Category != "*" && rule.DetType != "Binary" {
		if category != rule.Category {
			return false
		}
	}

	if rule.Namespace != "" && !strings.Contains(ns, rule.Namespace) {
		return false
	}

	if rule.PodPattern != "" && !podGlobMatch(pod, rule.PodPattern) {
		return false
	}

	if rule.ProcessFilter != "" {
		execSyscalls := map[string]bool{
			"execve": true, "execveat": true, "sched_process_exec": true,
		}
		syscallPinned := rule.Syscall != "" && rule.Syscall != "*"
		if !syscallPinned && !execSyscalls[syscall] {
			return false
		}
		pf := strings.ToLower(rule.ProcessFilter)
		proc := strings.ToLower(process)
		ep := strings.ToLower(execpath)
		cmd0 := strings.ToLower(strings.SplitN(cmdline, " ", 2)[0])
		if proc != pf &&
			!strings.HasSuffix(proc, "/"+pf) &&
			!strings.Contains(ep, "/"+pf) &&
			ep != pf &&
			cmd0 != pf &&
			!strings.HasSuffix(cmd0, "/"+pf) {
			return false
		}
	}

	if rule.PathFilter != "" {
		switch syscall {
		case "dup2", "dup3":
			allowed := splitTrim(rule.PathFilter)
			newfd := ""
			if a != nil {
				if v, ok := a["newfd"]; ok {
					newfd = fmt.Sprintf("%v", v)
				}
			}
			if !sliceContains(allowed, newfd) {
				return false
			}
		case "socket":
			allowed := splitTrim(rule.PathFilter)
			rawDomain := ""
			if a != nil {
				if v, ok := a["domain"]; ok {
					rawDomain = fmt.Sprintf("%v", v)
				}
			}
			afMap := map[string]string{
				"AF_UNSPEC": "0", "AF_UNIX": "1", "AF_INET": "2",
				"AF_INET6": "10", "AF_NETLINK": "16", "AF_PACKET": "17",
			}
			if norm, ok := afMap[rawDomain]; ok {
				rawDomain = norm
			}
			if !sliceContains(allowed, rawDomain) {
				return false
			}
		case "mmap", "mprotect":
			allowed := splitTrim(rule.PathFilter)
			prot := ""
			if a != nil {
				if v, ok := a["prot"]; ok {
					prot = fmt.Sprintf("%v", v)
				}
			}
			if !sliceContains(allowed, prot) {
				return false
			}
		default:
			pf := strings.ToLower(strings.ReplaceAll(rule.PathFilter, "*", ""))
			cmd := strings.ToLower(cmdline)
			ep := strings.ToLower(execpath)
			pn := strings.ToLower(argsPathname)
			if !strings.Contains(cmd, pf) && !strings.Contains(ep, pf) && !strings.Contains(pn, pf) &&
				!argsContain(a, pf) {
				return false
			}
		}
	}

	return true
}

func argsContain(args map[string]interface{}, needle string) bool {
	if needle == "" || len(args) == 0 {
		return false
	}
	for _, v := range args {
		if valueContains(v, needle) {
			return true
		}
	}
	return false
}

func valueContains(v interface{}, needle string) bool {
	switch t := v.(type) {
	case string:
		return strings.Contains(strings.ToLower(t), needle)
	case float64, int, int64:
		return strings.Contains(fmt.Sprintf("%v", t), needle)
	case map[string]interface{}:
		ip, _ := t["sin_addr"].(string)
		if ip == "" {
			ip, _ = t["sin6_addr"].(string)
		}
		port := ""
		if p, ok := t["sin_port"]; ok {
			port = fmt.Sprintf("%v", p)
		}
		if (ip != "" || port != "") &&
			strings.Contains(strings.ToLower(ip+":"+port), needle) {
			return true
		}
		for _, nv := range t {
			if valueContains(nv, needle) {
				return true
			}
		}
	case []interface{}:
		for _, nv := range t {
			if valueContains(nv, needle) {
				return true
			}
		}
	}
	return false
}

func podGlobMatch(pod, pattern string) bool {
	if !strings.Contains(pattern, "*") {
		return strings.Contains(pod, pattern)
	}
	parts := strings.Split(pattern, "*")
	anchorStart := !strings.HasPrefix(pattern, "*")
	anchorEnd := !strings.HasSuffix(pattern, "*")
	s := pod
	for i, p := range parts {
		if p == "" {
			continue
		}
		switch {
		case i == 0 && anchorStart:
			if !strings.HasPrefix(s, p) {
				return false
			}
			s = s[len(p):]
		case i == len(parts)-1 && anchorEnd:
			if !strings.HasSuffix(s, p) {
				return false
			}
			s = s[:len(s)-len(p)]
		default:
			idx := strings.Index(s, p)
			if idx < 0 {
				return false
			}
			s = s[idx+len(p):]
		}
	}
	return true
}

func splitTrim(s string) []string {
	parts := strings.Split(s, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return parts
}

func sliceContains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
