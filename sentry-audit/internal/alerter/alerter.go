package alerter

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"sync"
	"time"

	alertspkg "github.com/wolfee-watcher/pkg/alerts"
	"github.com/wolfee-watcher/sentry-audit/internal/webhook"
)

const (
	ruleRefreshInterval = 30 * time.Second
	dedupTTL            = 10 * time.Minute
	dedupMaxEntries     = 20_000
	sourceTag           = "sentry-audit"
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
	"mwh-delete": {kind: "delete", resource: "mutatingwebhookconfigurations"},
	"vwh-create": {kind: "create", resource: "validatingwebhookconfigurations"},

	"ns-create":   {kind: "create", resource: "namespaces"},
	"ns-delete":   {kind: "delete", resource: "namespaces"},
	"node-create": {kind: "create", resource: "nodes"},
	"sa-create":   {kind: "create", resource: "serviceaccounts"},
	"sa-delete":   {kind: "delete", resource: "serviceaccounts"},
}

type auditRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Enabled     bool     `json:"enabled"`
	AlertOnly   bool     `json:"alertOnly"`
	DetType     string   `json:"detType"`
	Sev         string   `json:"sev"`
	Namespace   string   `json:"namespace"`
	AuditChecks []string `json:"auditChecks"`
}

type Alerter struct {
	fwd *alertspkg.Forwarder

	fetcher *alertspkg.RuleFetcher

	mu    sync.RWMutex
	rules []auditRule

	dedupMu sync.Mutex
	dedup   map[string]time.Time
}

func New(ctx context.Context) *Alerter {
	a := &Alerter{
		fwd:     alertspkg.NewForwarder(),
		fetcher: alertspkg.NewRuleFetcher("Audit"),
		dedup:   make(map[string]time.Time),
	}
	if a.fetcher == nil {
		log.Printf("[alerter] KVISIOR_URL not set — alert rules unavailable, alerting disabled")
		return a
	}
	if err := a.refresh(ctx); err != nil {
		log.Printf("[alerter] initial rule load failed: %v", err)
	} else {
		log.Printf("[alerter] loaded %d alertOnly audit rule(s)", a.RuleCount())
	}
	go a.refreshLoop(ctx)
	go a.dedupSweepLoop(ctx)
	return a
}

func (a *Alerter) RuleCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.rules)
}

func (a *Alerter) Close() {
	a.fwd.Close()
}

func (a *Alerter) Evaluate(ev webhook.AuditEvent) {
	a.mu.RLock()
	rules := a.rules
	a.mu.RUnlock()
	if len(rules) == 0 {
		return
	}
	for _, r := range rules {
		if !ruleMatches(r, ev) {
			continue
		}
		fp := strings.Join([]string{"aud", r.ID, string(ev.Kind), ev.Resource, ev.Namespace, ev.Name, ev.User}, "|")
		if !a.markFresh(fp) {
			continue
		}
		a.emit(r, ev, fp)
	}
}

func ruleMatches(r auditRule, ev webhook.AuditEvent) bool {

	isConnect := ev.Kind == webhook.EventKindExec ||
		ev.Kind == webhook.EventKindAttach ||
		ev.Kind == webhook.EventKindPortForward
	nsFilter := strings.TrimSpace(r.Namespace)
	if nsFilter != "" && ev.Namespace != "" && !isConnect && ev.Namespace != nsFilter {
		return false
	}
	for _, checkID := range r.AuditChecks {
		def, ok := auditChecks[checkID]
		if !ok {
			continue
		}
		if def.kind != "" && def.kind != string(ev.Kind) {
			continue
		}
		if def.resource != "" && def.resource != ev.Resource {
			continue
		}
		return true
	}
	return false
}

func (a *Alerter) emit(r auditRule, ev webhook.AuditEvent, fp string) {
	name := r.Name
	if name == "" {
		name = r.ID
	}
	ns := ev.Namespace
	if ns == "" {
		ns = "—"
	}
	target := ev.Name
	if target == "" {
		target = "—"
	}
	detail := buildAuditDetail(ev)
	log.Printf("[Warn] audit detected %s in %s/%s detail=%q", name, ns, target, detail)
	payload, _ := json.Marshal(ev)

	a.fwd.Send(alertspkg.AlertLog{
		DetType:     "Audit",
		Source:      sourceTag,
		RuleID:      r.ID,
		RuleName:    name,
		Severity:    r.Sev,
		Namespace:   ns,
		Target:      target,
		Detail:      detail,
		Persist:     true,
		Fingerprint: fp,
		Data:        payload,
	})
}

func buildAuditDetail(ev webhook.AuditEvent) string {
	parts := []string{string(ev.Kind)}
	if ev.Resource != "" {
		parts = append(parts, ev.Resource)
	}
	if ev.User != "" {
		parts = append(parts, "by "+ev.User)
	}
	return strings.Join(parts, " ")
}

func (a *Alerter) markFresh(fp string) bool {
	a.dedupMu.Lock()
	defer a.dedupMu.Unlock()
	now := time.Now()
	if last, ok := a.dedup[fp]; ok && now.Sub(last) < dedupTTL {
		return false
	}
	a.dedup[fp] = now
	return true
}

func (a *Alerter) refreshLoop(ctx context.Context) {
	t := time.NewTicker(ruleRefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := a.refresh(ctx); err != nil {
				log.Printf("[alerter] rule refresh failed: %v", err)
			}
		}
	}
}

func (a *Alerter) refresh(ctx context.Context) error {
	loadCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	policies, err := a.fetcher.Fetch(loadCtx)
	if err != nil {
		return err
	}
	var fresh []auditRule
	for _, raw := range policies {
		var r auditRule
		if err := json.Unmarshal(raw, &r); err != nil {
			continue
		}
		fresh = append(fresh, r)
	}
	a.mu.Lock()
	prevCount := len(a.rules)
	a.rules = fresh
	a.mu.Unlock()
	if prevCount != len(fresh) {
		log.Printf("[alerter] rule set changed: %d → %d alertOnly audit rule(s)", prevCount, len(fresh))
	}
	return nil
}

func (a *Alerter) dedupSweepLoop(ctx context.Context) {
	t := time.NewTicker(dedupTTL)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.sweep()
		}
	}
}

func (a *Alerter) sweep() {
	a.dedupMu.Lock()
	defer a.dedupMu.Unlock()
	cutoff := time.Now().Add(-dedupTTL)
	for fp, ts := range a.dedup {
		if ts.Before(cutoff) {
			delete(a.dedup, fp)
		}
	}
	if len(a.dedup) > dedupMaxEntries {
		a.dedup = make(map[string]time.Time)
	}
}
