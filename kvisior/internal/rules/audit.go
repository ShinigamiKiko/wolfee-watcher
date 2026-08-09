package rules

import (
	"strings"
	"sync"
)

type auditCheck struct {
	kind     string
	resource string
}

var auditChecks = map[string]auditCheck{

	"exec-pod":        {kind: "exec"},
	"attach-pod":      {kind: "attach"},
	"portforward-pod": {kind: "portforward"},

	"pod-create":       {kind: "create", resource: "pods"},
	"pod-delete":       {kind: "delete", resource: "pods"},
	"deploy-create":    {kind: "create", resource: "deployments"},
	"deploy-update":    {kind: "update", resource: "deployments"},
	"daemonset-create": {kind: "create", resource: "daemonsets"},
	"daemonset-update": {kind: "update", resource: "daemonsets"},
	"job-create":       {kind: "create", resource: "jobs"},
	"cronjob-create":   {kind: "create", resource: "cronjobs"},

	"secret-create":    {kind: "create", resource: "secrets"},
	"secret-delete":    {kind: "delete", resource: "secrets"},
	"configmap-update": {kind: "update", resource: "configmaps"},

	"role-create":        {kind: "create", resource: "roles"},
	"clusterrole-create": {kind: "create", resource: "clusterroles"},
	"rolebinding-create": {kind: "create", resource: "rolebindings"},
	"rolebinding-delete": {kind: "delete", resource: "rolebindings"},
	"crb-create":         {kind: "create", resource: "clusterrolebindings"},
	"crb-delete":         {kind: "delete", resource: "clusterrolebindings"},

	"mwh-create": {kind: "create", resource: "mutatingwebhookconfigurations"},
	"mwh-update": {kind: "update", resource: "mutatingwebhookconfigurations"},
	"mwh-delete": {kind: "delete", resource: "mutatingwebhookconfigurations"},
	"vwh-create": {kind: "create", resource: "validatingwebhookconfigurations"},
	"vwh-update": {kind: "update", resource: "validatingwebhookconfigurations"},
	"vwh-delete": {kind: "delete", resource: "validatingwebhookconfigurations"},

	"ns-create":   {kind: "create", resource: "namespaces"},
	"ns-delete":   {kind: "delete", resource: "namespaces"},
	"node-create": {kind: "create", resource: "nodes"},
	"sa-create":   {kind: "create", resource: "serviceaccounts"},
	"sa-delete":   {kind: "delete", resource: "serviceaccounts"},
}

type AuditRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Enabled     *bool    `json:"enabled"`
	Namespace   string   `json:"namespace"`
	Sev         string   `json:"sev"`
	Action      string   `json:"action"`
	AuditChecks []string `json:"auditChecks"`
}

func (r AuditRule) isEnabled() bool {
	return r.Enabled == nil || *r.Enabled
}

type AuditViolation struct {
	Policy          string `json:"policy"`
	RuleID          string `json:"ruleId"`
	Sev             string `json:"sev"`
	Check           string `json:"check"`
	Action          string `json:"action"`
	Kind            string `json:"kind"`
	Resource        string `json:"resource"`
	WebhookType     string `json:"webhookType,omitempty"`
	Namespace       string `json:"ns"`
	Name            string `json:"name"`
	User            string `json:"user"`
	ServiceAccount  string `json:"serviceAccount,omitempty"`
	Timestamp       string `json:"timestamp"`
	UID             string `json:"uid,omitempty"`
	ResourceVersion string `json:"resourceVersion,omitempty"`
	Source          string `json:"source,omitempty"`
}

type AuditMatcher struct {
	mu    sync.RWMutex
	rules []AuditRule
}

func NewAuditMatcher() *AuditMatcher { return &AuditMatcher{} }

func (m *AuditMatcher) Replace(rules []AuditRule) {
	m.mu.Lock()
	m.rules = rules
	m.mu.Unlock()
}

func (m *AuditMatcher) Match(ev map[string]interface{}) []AuditViolation {
	m.mu.RLock()
	rules := m.rules
	m.mu.RUnlock()

	evKind := strField(ev, "kind")
	evResource := strField(ev, "resource")
	evNamespace := strField(ev, "namespace")
	evName := strField(ev, "name")
	evUser := strField(ev, "user")
	evServiceAccount := strField(ev, "serviceAccount")
	evTs := strField(ev, "timestamp")
	evWebhookType := strField(ev, "webhookType")
	evUID := strField(ev, "uid")
	evResourceVersion := strField(ev, "resourceVersion")
	evSource := strField(ev, "source")
	connectKind := evKind == "exec" || evKind == "attach" || evKind == "portforward"

	var hits []AuditViolation
	for _, rule := range rules {
		if !rule.isEnabled() {
			continue
		}
		nsFilter := rule.Namespace

		if nsFilter != "" && !connectKind && evNamespace != nsFilter {
			continue
		}
		for _, checkID := range rule.AuditChecks {
			def, ok := auditChecks[checkID]
			if !ok {
				continue
			}
			if def.kind != evKind {
				continue
			}
			if def.resource != "" && def.resource != evResource {
				continue
			}
			hits = append(hits, AuditViolation{
				Policy:          rule.Name,
				RuleID:          rule.ID,
				Sev:             sev(rule.Sev),
				Check:           checkID,
				Action:          rule.Action,
				Kind:            evKind,
				Resource:        evResource,
				WebhookType:     evWebhookType,
				Namespace:       evNamespace,
				Name:            evName,
				User:            evUser,
				ServiceAccount:  evServiceAccount,
				Timestamp:       evTs,
				UID:             evUID,
				ResourceVersion: evResourceVersion,
				Source:          evSource,
			})
		}
	}
	return hits
}

func sev(s string) string {
	if s == "" {
		return "HIGH"
	}
	return strings.ToUpper(s)
}
