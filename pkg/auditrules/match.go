package auditrules

import (
	"net"
	"strings"
	"sync"
	"time"
)

type Event struct {
	ID                  string     `json:"id"`
	Timestamp           time.Time  `json:"timestamp"`
	User                string     `json:"user"`
	ImpersonatedUser    string     `json:"impersonatedUser,omitempty"`
	ImpersonatedGroups  []string   `json:"impersonatedGroups,omitempty"`
	ServiceAccount      string     `json:"serviceAccount,omitempty"`
	Groups              []string   `json:"groups,omitempty"`
	SourceIPs           []string   `json:"sourceIPs,omitempty"`
	ClientIP            string     `json:"clientIP,omitempty"`
	UserAgent           string     `json:"userAgent,omitempty"`
	Kind                string     `json:"kind"`
	Resource            string     `json:"resource"`
	WebhookType         string     `json:"webhookType,omitempty"`
	Namespace           string     `json:"namespace"`
	Name                string     `json:"name"`
	UID                 string     `json:"uid,omitempty"`
	ResourceVersion     string     `json:"resourceVersion,omitempty"`
	PrevResourceVersion string     `json:"prevResourceVersion,omitempty"`
	Unchanged           bool       `json:"unchanged,omitempty"`
	DryRun              bool       `json:"dryRun,omitempty"`
	CompletedAt         *time.Time `json:"completedAt,omitempty"`
	Source              string     `json:"source,omitempty"`
	Attribution         string     `json:"attribution,omitempty"`
	Container           string     `json:"container,omitempty"`
	Commands            []string   `json:"commands,omitempty"`
	Ports               []int32    `json:"ports,omitempty"`
	Allowed             *bool      `json:"allowed,omitempty"`
	StatusCode          int32      `json:"statusCode,omitempty"`
	AuditID             string     `json:"auditID,omitempty"`
}

const AttributionUnconfirmed = "unconfirmed"

func (e *Event) IsAllowed() bool {
	return e.Allowed == nil || *e.Allowed
}

func (e *Event) SourceIP() string {
	if e.ClientIP != "" {
		return e.ClientIP
	}
	return ClientIP(e.SourceIPs, nil)
}

func (e *Event) ForwardedClaims() []string {
	client := e.SourceIP()
	if client == "" {
		return nil
	}
	end := -1
	for i := len(e.SourceIPs) - 1; i >= 0; i-- {
		if e.SourceIPs[i] == client {
			end = i
			break
		}
	}
	if end <= 0 {
		return nil
	}
	var claims []string
	for _, ip := range e.SourceIPs[:end] {
		if ip != client {
			claims = append(claims, ip)
		}
	}
	return claims
}

var humanSystemUsers = map[string]bool{"system:admin": true}

func IsServiceIdentity(user string) bool {
	return strings.HasPrefix(user, "system:") && !humanSystemUsers[user]
}

func IsPerson(user string) bool {
	return user != "" && user != "unknown" && !IsServiceIdentity(user)
}

func Glob(pattern, s string) bool {
	pattern, s = strings.ToLower(pattern), strings.ToLower(s)
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, p := range parts[1 : len(parts)-1] {
		i := strings.Index(s, p)
		if i < 0 {
			return false
		}
		s = s[i+len(p):]
	}
	return strings.HasSuffix(s, last)
}

func globAny(patterns []string, s string) bool {
	for _, p := range patterns {
		if Glob(p, s) {
			return true
		}
	}
	return false
}

type ipPattern struct {
	net  *net.IPNet
	glob string
}

type compiled struct {
	rule         Rule
	kinds        map[string]bool
	resources    map[string]bool
	clusters     map[string]bool
	ns           []string
	nsExclude    []string
	objName      []string
	users        []string
	usersExclude []string
	ips          []ipPattern
	cmd          string
}

func compile(r Rule) *compiled {
	c := &compiled{
		rule:         r,
		kinds:        map[string]bool{},
		nsExclude:    splitList(r.Spec.NSExclude),
		objName:      splitList(r.Spec.ObjName),
		users:        splitList(r.Spec.Users),
		usersExclude: splitList(r.Spec.UsersExclude),
		cmd:          strings.ToLower(r.Spec.Cmd),
	}
	for _, k := range r.Spec.Kinds {
		c.kinds[k] = true
	}
	if len(r.Spec.Resources) > 0 {
		c.resources = map[string]bool{}
		for _, v := range r.Spec.Resources {
			c.resources[v] = true
		}
	}
	if len(r.Spec.Clusters) > 0 {
		c.clusters = map[string]bool{}
		for _, v := range r.Spec.Clusters {
			c.clusters[v] = true
		}
	}
	if r.Spec.NS != "" && r.Spec.NS != "*" {
		c.ns = splitList(r.Spec.NS)
	}
	for _, it := range splitList(r.Spec.IPList) {
		if strings.Contains(it, "/") {
			if _, n, err := net.ParseCIDR(it); err == nil {
				c.ips = append(c.ips, ipPattern{net: n})
			}
			continue
		}
		c.ips = append(c.ips, ipPattern{glob: it})
	}
	return c
}

func (c *compiled) ipHit(ip string) bool {
	parsed := net.ParseIP(ip)
	for _, p := range c.ips {
		if p.net != nil {
			if parsed != nil && p.net.Contains(parsed) {
				return true
			}
			continue
		}
		if Glob(p.glob, ip) {
			return true
		}
	}
	return false
}

func (c *compiled) matches(cluster string, ev *Event) bool {
	s := c.rule.Spec
	if c.clusters != nil && !c.clusters[cluster] {
		return false
	}
	if c.resources != nil && !c.resources[ev.Resource] {
		return false
	}
	if c.ns != nil && !globAny(c.ns, ev.Namespace) {
		return false
	}
	if len(c.nsExclude) > 0 && globAny(c.nsExclude, ev.Namespace) {
		return false
	}
	if len(c.objName) > 0 && !globAny(c.objName, ev.Name) {
		return false
	}
	switch s.Subject {
	case SubjectPeople:
		if !IsPerson(ev.User) {
			return false
		}
	case SubjectSA:
		if !IsServiceIdentity(ev.User) {
			return false
		}
	}
	if len(c.users) > 0 && !globAny(c.users, ev.User) {
		return false
	}
	if len(c.usersExclude) > 0 && globAny(c.usersExclude, ev.User) {
		return false
	}
	if s.Forwarded && len(ev.ForwardedClaims()) == 0 {
		return false
	}
	if s.IPMode != IPAny {
		ip := ev.SourceIP()
		if ip == "" {
			return false
		}
		if hit := c.ipHit(ip); (s.IPMode == IPIn) != hit {
			return false
		}
	}
	switch s.Result {
	case ResultAllowed:
		if ev.Allowed == nil || !ev.IsAllowed() {
			return false
		}
	case ResultDenied:
		if ev.Allowed == nil || ev.IsAllowed() {
			return false
		}
	}
	if c.cmd != "" && !strings.Contains(strings.ToLower(strings.Join(ev.Commands, " ")), c.cmd) {
		return false
	}
	return true
}

type Matcher struct {
	mu     sync.RWMutex
	byKind map[string][]*compiled
	count  int
}

func NewMatcher() *Matcher {
	return &Matcher{byKind: map[string][]*compiled{}}
}

func (m *Matcher) Replace(rules []Rule) {
	byKind := map[string][]*compiled{}
	n := 0
	for _, r := range rules {
		if !r.Enabled && !r.Alert {
			continue
		}
		c := compile(r)
		n++
		for k := range c.kinds {
			byKind[k] = append(byKind[k], c)
		}
	}
	m.mu.Lock()
	m.byKind, m.count = byKind, n
	m.mu.Unlock()
}

func (m *Matcher) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.count
}

func (m *Matcher) Match(cluster string, ev *Event, onlyIPRules bool) []Rule {
	m.mu.RLock()
	candidates := m.byKind[ev.Kind]
	m.mu.RUnlock()

	var hits []Rule
	for _, c := range candidates {
		if onlyIPRules && c.rule.Spec.IPMode == IPAny && !c.rule.Spec.Forwarded {
			continue
		}
		if c.matches(cluster, ev) {
			hits = append(hits, c.rule)
		}
	}
	return hits
}
