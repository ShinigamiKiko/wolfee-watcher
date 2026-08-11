package matcher

import (
	"fmt"
	"strings"

	"github.com/wolfee-watcher/pkg/policy"
)

type Rule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Sev     string `json:"sev"`
	Enabled bool   `json:"enabled"`

	AlertOnly     bool   `json:"alertOnly"`
	DetType       string `json:"detType"`
	Syscall       string `json:"syscall"`
	Category      string `json:"category"`
	ProcessFilter string `json:"processFilter"`
	PathFilter    string `json:"pathFilter"`
	Namespace     string `json:"namespace"`
	PodPattern    string `json:"podPattern"`
}

type Event struct {
	Syscall   string
	Category  string
	Namespace string
	Pod       string
	Process   string
	Execpath  string
	Cmdline   string
	Args      map[string]interface{}
}

func Matches(e Event, r Rule) bool {
	if !r.Enabled {
		return false
	}

	if r.Syscall != "" && r.Syscall != "*" {
		if e.Syscall != r.Syscall {
			return false
		}
	}

	if r.Category != "" && r.Category != "*" && r.DetType != "Binary" {
		if e.Category != r.Category {
			return false
		}
	}

	if !policy.NamespaceMatches(e.Namespace, r.Namespace) {
		return false
	}

	if !policy.PodMatches(e.Pod, r.PodPattern) {
		return false
	}

	if r.ProcessFilter != "" {
		syscallPinned := r.Syscall != "" && r.Syscall != "*"
		if !syscallPinned && !policy.IsExecSyscall(e.Syscall) {
			return false
		}
		if !policy.ProcessMatches(r.ProcessFilter, e.Process, e.Execpath, e.Cmdline) {
			return false
		}
	}

	if r.PathFilter != "" {
		pf := strings.ToLower(strings.ReplaceAll(r.PathFilter, "*", ""))
		if !strings.Contains(strings.ToLower(e.Cmdline), pf) &&
			!strings.Contains(strings.ToLower(e.Execpath), pf) &&
			!argsContain(e.Args, pf) {
			return false
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

func MatchesAny(e Event, rules []Rule) bool {
	for _, r := range rules {
		if Matches(e, r) {
			return true
		}
	}
	return false
}
