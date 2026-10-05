package auditrules

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

const (
	KindCreate      = "create"
	KindUpdate      = "update"
	KindDelete      = "delete"
	KindExec        = "exec"
	KindAttach      = "attach"
	KindPortForward = "portforward"
	KindGet         = "get"
	KindList        = "list"

	SevCritical = "critical"
	SevHigh     = "high"
	SevMedium   = "medium"
	SevLow      = "low"

	OriginBuiltin = "builtin"
	OriginCustom  = "custom"

	SubjectAny    = "any"
	SubjectPeople = "people"
	SubjectSA     = "sa"

	IPAny   = "any"
	IPIn    = "in"
	IPNotIn = "notin"

	ResultAny     = "any"
	ResultAllowed = "allowed"
	ResultDenied  = "denied"

	AlertEach      = "each"
	AlertThreshold = "threshold"

	maxNameLen    = 120
	maxPatternLen = 400
	maxListItems  = 64
)

var (
	Kinds      = []string{KindCreate, KindUpdate, KindDelete, KindExec, KindAttach, KindPortForward, KindGet, KindList}
	Severities = []string{SevCritical, SevHigh, SevMedium, SevLow}

	resourceRe = regexp.MustCompile(`^[a-z0-9][a-z0-9./-]{0,80}$`)
	idRe       = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,119}$`)
)

type Spec struct {
	Kinds        []string `json:"kinds"`
	Resources    []string `json:"resources"`
	NS           string   `json:"ns"`
	NSExclude    string   `json:"nsExclude"`
	ObjName      string   `json:"objName"`
	Subject      string   `json:"subject"`
	Users        string   `json:"users"`
	UsersExclude string   `json:"usersExclude"`
	IPMode       string   `json:"ipMode"`
	IPList       string   `json:"ipList"`
	Forwarded    bool     `json:"forwarded"`
	Result       string   `json:"result"`
	Cmd          string   `json:"cmd"`
	AlertEvery   string   `json:"alertEvery"`
	ThN          int      `json:"thN"`
	ThMin        int      `json:"thMin"`
	Clusters     []string `json:"clusters"`
}

type Rule struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Group     string    `json:"group"`
	Origin    string    `json:"origin"`
	Enabled   bool      `json:"enabled"`
	Alert     bool      `json:"alert"`
	Severity  string    `json:"severity"`
	Spec      Spec      `json:"spec"`
	UpdatedBy string    `json:"updatedBy,omitempty"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func cleanList(s string) string {
	return strings.Join(splitList(s), ", ")
}

func cleanSet(in []string, lower bool) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if lower {
			v = strings.ToLower(v)
		}
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func oneOf(v string, allowed ...string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

func (r *Rule) Normalize() {
	r.ID = strings.TrimSpace(r.ID)
	r.Name = strings.TrimSpace(r.Name)
	r.Group = strings.TrimSpace(r.Group)
	r.Severity = strings.ToLower(strings.TrimSpace(r.Severity))
	if r.Severity == "" {
		r.Severity = SevHigh
	}
	if r.Origin != OriginBuiltin {
		r.Origin = OriginCustom
	}
	if r.Group == "" {
		r.Group = "Custom"
	}
	s := &r.Spec
	s.Kinds = cleanSet(s.Kinds, true)
	s.Resources = cleanSet(s.Resources, true)
	s.Clusters = cleanSet(s.Clusters, false)
	s.NS = cleanList(s.NS)
	if s.NS == "" {
		s.NS = "*"
	}
	s.NSExclude = cleanList(s.NSExclude)
	s.ObjName = cleanList(s.ObjName)
	s.Users = cleanList(s.Users)
	s.UsersExclude = cleanList(s.UsersExclude)
	s.IPList = cleanList(s.IPList)
	s.Cmd = strings.TrimSpace(s.Cmd)
	if s.Subject == "" {
		s.Subject = SubjectAny
	}
	if s.IPMode == "" {
		s.IPMode = IPAny
	}
	if s.IPMode == IPAny {
		s.IPList = ""
	}
	if s.Result == "" {
		s.Result = ResultAny
	}
	if s.AlertEvery == "" {
		s.AlertEvery = AlertEach
	}
	if s.ThN < 2 {
		s.ThN = 3
	}
	if s.ThMin < 1 {
		s.ThMin = 10
	}
}

func (r Rule) Validate() error {
	if !idRe.MatchString(r.ID) {
		return errors.New("rule id must be 1-120 characters: letters, digits, dot, colon, dash or underscore")
	}
	if r.Name == "" {
		return errors.New("rule name is required")
	}
	if len(r.Name) > maxNameLen {
		return fmt.Errorf("rule name is longer than %d characters", maxNameLen)
	}
	if !oneOf(r.Severity, Severities...) {
		return fmt.Errorf("unknown severity %q", r.Severity)
	}
	s := r.Spec
	if len(s.Kinds) == 0 {
		return errors.New("pick at least one action")
	}
	for _, k := range s.Kinds {
		if !oneOf(k, Kinds...) {
			return fmt.Errorf("unknown action %q", k)
		}
	}
	if len(s.Resources) > maxListItems || len(s.Clusters) > maxListItems {
		return fmt.Errorf("at most %d resources and clusters per rule", maxListItems)
	}
	for _, res := range s.Resources {
		if !resourceRe.MatchString(res) {
			return fmt.Errorf("invalid resource %q", res)
		}
	}
	for label, v := range map[string]string{
		"namespaces": s.NS, "excluded namespaces": s.NSExclude, "object name": s.ObjName,
		"users": s.Users, "excluded users": s.UsersExclude, "addresses": s.IPList, "command": s.Cmd,
	} {
		if len(v) > maxPatternLen {
			return fmt.Errorf("%s is longer than %d characters", label, maxPatternLen)
		}
	}
	if !oneOf(s.Subject, SubjectAny, SubjectPeople, SubjectSA) {
		return fmt.Errorf("unknown subject %q", s.Subject)
	}
	if !oneOf(s.Result, ResultAny, ResultAllowed, ResultDenied) {
		return fmt.Errorf("unknown result filter %q", s.Result)
	}
	if !oneOf(s.IPMode, IPAny, IPIn, IPNotIn) {
		return fmt.Errorf("unknown source IP mode %q", s.IPMode)
	}
	if s.IPMode != IPAny {
		items := splitList(s.IPList)
		if len(items) == 0 {
			return errors.New("enter at least one address when filtering by source IP")
		}
		for _, it := range items {
			if strings.Contains(it, "/") {
				if _, _, err := net.ParseCIDR(it); err != nil {
					return fmt.Errorf("invalid network %q", it)
				}
			}
		}
	}
	if !oneOf(s.AlertEvery, AlertEach, AlertThreshold) {
		return fmt.Errorf("unknown alert mode %q", s.AlertEvery)
	}
	if s.AlertEvery == AlertThreshold && (s.ThN < 2 || s.ThN > 1000 || s.ThMin < 1 || s.ThMin > 1440) {
		return errors.New("repeat alerts need 2-1000 times within 1-1440 minutes")
	}
	return nil
}

func (r Rule) NeedsAPILog() bool {
	if r.Spec.IPMode != IPAny || (r.Spec.Result != "" && r.Spec.Result != ResultAny) {
		return true
	}
	for _, k := range r.Spec.Kinds {
		if k == KindGet || k == KindList {
			return true
		}
	}
	return false
}
