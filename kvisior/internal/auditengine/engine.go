package auditengine

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/hub"
	"github.com/wolfee-watcher/kvisior/internal/store"
	"github.com/wolfee-watcher/pkg/auditrules"
)

const (
	refreshInterval  = 15 * time.Second
	alertDedupTTL    = 10 * time.Minute
	alertDedupMax    = 20_000
	pendingEnrichTTL = 2 * time.Minute
	pendingEnrichMax = 10_000
	alertSource      = "sentry-audit"
	alertDetType     = "Audit"
	SourceAPILog     = "apiserver-log"
)

var sevRank = map[string]int{
	auditrules.SevCritical: 4,
	auditrules.SevHigh:     3,
	auditrules.SevMedium:   2,
	auditrules.SevLow:      1,
}

type LogRecord struct {
	EventUID string           `json:"eventUid,omitempty"`
	Event    auditrules.Event `json:"event"`
}

type pendingEnrich struct {
	en store.AuditEnrichment
	at time.Time
}

type Engine struct {
	matcher *auditrules.Matcher
	store   *store.Store
	hub     hub.Publisher

	mu      sync.Mutex
	stamp   string
	repeats map[string][]time.Time
	alerted map[string]time.Time
	pending map[string]pendingEnrich
}

func New(st *store.Store, pub hub.Publisher) *Engine {
	return &Engine{
		matcher: auditrules.NewMatcher(),
		store:   st,
		hub:     pub,
		repeats: map[string][]time.Time{},
		alerted: map[string]time.Time{},
		pending: map[string]pendingEnrich{},
	}
}

func (e *Engine) Reload(ctx context.Context) error {
	if e.store == nil {
		return nil
	}
	rules, err := e.store.ListAuditRules(ctx)
	if err != nil {
		return err
	}
	stamp, err := e.store.AuditRulesStamp(ctx)
	if err != nil {
		return err
	}
	e.matcher.Replace(rules)
	e.mu.Lock()
	changed := e.stamp != stamp
	e.stamp = stamp
	e.mu.Unlock()
	if changed {
		slog.Info("audit_rules_loaded",
			"component", "kvisior/audit",
			"rules", len(rules),
			"active", e.matcher.Len())
	}
	return nil
}

func (e *Engine) Run(ctx context.Context) {
	if e.store == nil {
		return
	}
	if err := e.Reload(ctx); err != nil {
		slog.Warn("audit_rules_load_failed", "component", "kvisior/audit", "error", err)
	}
	t := time.NewTicker(refreshInterval)
	defer t.Stop()
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			stamp, err := e.store.AuditRulesStamp(ctx)
			if err == nil {
				e.mu.Lock()
				same := stamp == e.stamp
				e.mu.Unlock()
				if same {
					failures = 0
					e.sweep()
					continue
				}
				err = e.Reload(ctx)
			}
			if err != nil {
				failures++
				if failures == 1 || failures%20 == 0 {
					slog.Warn("audit_rules_refresh_failed",
						"component", "kvisior/audit",
						"consecutive", failures,
						"error", err)
				}
				continue
			}
			failures = 0
		}
	}
}

func (e *Engine) sweep() {
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, t := range e.alerted {
		if now.Sub(t) > alertDedupTTL {
			delete(e.alerted, k)
		}
	}
	for k, p := range e.pending {
		if now.Sub(p.at) > pendingEnrichTTL {
			delete(e.pending, k)
		}
	}
}

func topRule(hits []auditrules.Rule) (auditrules.Rule, bool) {
	var best auditrules.Rule
	found := false
	for _, r := range hits {
		if !r.Enabled {
			continue
		}
		if !found || sevRank[r.Severity] > sevRank[best.Severity] {
			best, found = r, true
		}
	}
	return best, found
}

type violationEvent struct {
	Policy          string   `json:"policy"`
	RuleID          string   `json:"ruleId"`
	Sev             string   `json:"sev"`
	Check           string   `json:"check,omitempty"`
	Kind            string   `json:"kind"`
	Resource        string   `json:"resource"`
	WebhookType     string   `json:"webhookType,omitempty"`
	Namespace       string   `json:"ns"`
	Name            string   `json:"name"`
	User            string   `json:"user"`
	ServiceAccount  string   `json:"serviceAccount,omitempty"`
	Groups          []string `json:"groups,omitempty"`
	SourceIPs       []string `json:"sourceIPs,omitempty"`
	UserAgent       string   `json:"userAgent,omitempty"`
	Commands        []string `json:"commands,omitempty"`
	Container       string   `json:"container,omitempty"`
	Ports           []int32  `json:"ports,omitempty"`
	Timestamp       string   `json:"timestamp"`
	UID             string   `json:"uid,omitempty"`
	ResourceVersion string   `json:"resourceVersion,omitempty"`
	Source          string   `json:"source,omitempty"`
	EventID         string   `json:"eventId,omitempty"`
	Fingerprint     string   `json:"fingerprint"`
}

func fingerprint(cluster string, r auditrules.Rule, ev *auditrules.Event) string {
	return store.Fingerprint(cluster, r.ID, ev.Namespace, ev.Kind+"/"+ev.Resource+"/"+ev.Name+"/"+ev.User)
}

func objectText(ev *auditrules.Event) string {
	parts := []string{ev.Resource}
	if ev.Namespace != "" {
		parts = append(parts, ev.Namespace)
	}
	if ev.Name != "" {
		parts = append(parts, ev.Name)
	}
	return strings.Join(parts, "/")
}

func alertDetail(ev *auditrules.Event, r auditrules.Rule) string {
	detail := fmt.Sprintf("%s %s %s", ev.User, ev.Kind, objectText(ev))
	if ip := ev.SourceIP(); ip != "" {
		detail += " from " + ip
	}
	if len(ev.Commands) > 0 {
		detail += " command " + strings.Join(ev.Commands, " ")
	}
	if !ev.IsAllowed() {
		detail += " (denied)"
	}
	if r.Spec.AlertEvery == auditrules.AlertThreshold {
		detail += fmt.Sprintf(", %d times in %d min", r.Spec.ThN, r.Spec.ThMin)
	}
	return detail
}

func (e *Engine) shouldAlert(cluster string, r auditrules.Rule, ev *auditrules.Event, fp string) bool {
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	if r.Spec.AlertEvery == auditrules.AlertThreshold {
		key := cluster + "|" + r.ID
		window := time.Duration(r.Spec.ThMin) * time.Minute
		kept := e.repeats[key][:0]
		for _, t := range e.repeats[key] {
			if now.Sub(t) < window {
				kept = append(kept, t)
			}
		}
		kept = append(kept, now)
		if len(kept) < r.Spec.ThN {
			e.repeats[key] = kept
			return false
		}
		delete(e.repeats, key)
		return true
	}
	if t, ok := e.alerted[fp]; ok && now.Sub(t) < alertDedupTTL {
		return false
	}
	if len(e.alerted) >= alertDedupMax {
		for k, t := range e.alerted {
			if now.Sub(t) > alertDedupTTL {
				delete(e.alerted, k)
			}
		}
		if len(e.alerted) >= alertDedupMax {
			e.alerted = map[string]time.Time{}
		}
	}
	e.alerted[fp] = now
	return true
}

func (e *Engine) act(ctx context.Context, cluster string, ev *auditrules.Event, raw json.RawMessage, hits []auditrules.Rule) ([]store.IncomingAlert, error) {
	var alerts []store.IncomingAlert
	scoped := e.store.Cluster(cluster)
	for _, r := range hits {
		fp := fingerprint(cluster, r, ev)
		sev := strings.ToUpper(r.Severity)
		if r.Enabled {
			if err := scoped.WriteAuditViolation(ctx, store.AuditViolationWrite{
				RuleID: r.ID, RuleName: r.Name, Sev: sev,
				Kind: ev.Kind, Resource: ev.Resource, Namespace: ev.Namespace, Name: ev.Name,
				Actor: ev.User, SourceIP: ev.SourceIP(), Fingerprint: fp, Data: raw,
			}); err != nil {
				return alerts, fmt.Errorf("audit violation: %w", err)
			}
			v := violationEvent{
				Policy: r.Name, RuleID: r.ID, Sev: sev,
				Kind: ev.Kind, Resource: ev.Resource, WebhookType: ev.WebhookType,
				Namespace: ev.Namespace, Name: ev.Name, User: ev.User, ServiceAccount: ev.ServiceAccount,
				Groups: ev.Groups, SourceIPs: ev.SourceIPs, UserAgent: ev.UserAgent,
				Commands: ev.Commands, Container: ev.Container, Ports: ev.Ports,
				Timestamp: ev.Timestamp.UTC().Format(time.RFC3339Nano),
				UID:       ev.UID, ResourceVersion: ev.ResourceVersion, Source: ev.Source,
				EventID: ev.ID, Fingerprint: fp,
			}
			if r.Origin == auditrules.OriginBuiltin {
				v.Check = r.ID
			}
			if data, err := json.Marshal(v); err == nil {
				e.hub.Publish(hub.Event{Cluster: cluster, Type: "audit_violation", Data: data})
			}
		}
		if r.Alert && e.shouldAlert(cluster, r, ev, fp) {
			ns, target := ev.Namespace, ev.Name
			if ns == "" {
				ns = "—"
			}
			if target == "" {
				target = ev.Resource
			}
			alerts = append(alerts, store.IncomingAlert{
				Timestamp: ev.Timestamp, Source: alertSource, DetType: alertDetType,
				RuleID: r.ID, RuleName: r.Name, Severity: sev,
				Namespace: ns, Target: target, Detail: alertDetail(ev, r),
				Fingerprint: "aud|" + fp, Data: raw,
			})
		}
	}
	return alerts, nil
}

func withRule(raw json.RawMessage, r auditrules.Rule, marked bool) json.RawMessage {
	if !marked {
		return raw
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return raw
	}
	m["ruleId"], _ = json.Marshal(r.ID)
	m["ruleName"], _ = json.Marshal(r.Name)
	m["sev"], _ = json.Marshal(strings.ToUpper(r.Severity))
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}

type prepared struct {
	ev     *auditrules.Event
	raw    json.RawMessage
	hits   []auditrules.Rule
	top    auditrules.Rule
	marked bool
}

func (e *Engine) prepare(cluster string, ev *auditrules.Event, raw json.RawMessage) prepared {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	p := prepared{ev: ev, raw: raw, hits: e.matcher.Match(cluster, ev, false)}
	p.top, p.marked = topRule(p.hits)
	return p
}

func (e *Engine) persist(ctx context.Context, cluster, origin string, batch []prepared) error {
	if len(batch) == 0 {
		return nil
	}
	e.store.EnsureClusterCached(cluster)
	scoped := e.store.Cluster(cluster)
	items := make([]store.AuditEventInsert, 0, len(batch))
	for _, p := range batch {
		it := store.AuditEventInsert{Raw: p.raw, Event: p.ev, Origin: origin}
		if p.marked {
			it.RuleID, it.Sev = p.top.ID, strings.ToUpper(p.top.Severity)
		}
		items = append(items, it)
	}
	if err := scoped.InsertAuditEvents(ctx, items); err != nil {
		return fmt.Errorf("audit events: %w", err)
	}
	var alerts []store.IncomingAlert
	for _, p := range batch {
		e.hub.Publish(hub.Event{Cluster: cluster, Type: "audit_event", Data: withRule(p.raw, p.top, p.marked)})
		got, err := e.act(ctx, cluster, p.ev, p.raw, p.hits)
		alerts = append(alerts, got...)
		if err != nil {
			return err
		}
	}
	if err := scoped.InsertAlerts(ctx, alerts); err != nil {
		return fmt.Errorf("audit alerts: %w", err)
	}
	return nil
}

func (e *Engine) IngestEvents(ctx context.Context, cluster string, raws []json.RawMessage) error {
	batch := make([]prepared, 0, len(raws))
	for _, raw := range raws {
		ev := &auditrules.Event{}
		if err := json.Unmarshal(raw, ev); err != nil {
			slog.Warn("audit_event_unreadable", "component", "kvisior/audit", "error", err)
			continue
		}
		batch = append(batch, e.prepare(cluster, ev, append(json.RawMessage(nil), raw...)))
	}
	if err := e.persist(ctx, cluster, store.AuditOriginAdmission, batch); err != nil {
		return err
	}
	for _, p := range batch {
		if p.ev.ID == "" {
			continue
		}
		key := cluster + "|" + p.ev.ID
		e.mu.Lock()
		pe, waiting := e.pending[key]
		delete(e.pending, key)
		e.mu.Unlock()
		if waiting {
			if _, err := e.enrich(ctx, cluster, pe.en); err != nil {
				return err
			}
		}
	}
	return nil
}

func (e *Engine) enrich(ctx context.Context, cluster string, en store.AuditEnrichment) (bool, error) {
	scoped := e.store.Cluster(cluster)
	row, ok, err := scoped.EnrichAuditEvent(ctx, en)
	if err != nil {
		return false, fmt.Errorf("audit enrichment: %w", err)
	}
	if !ok {
		return false, nil
	}
	ev := &auditrules.Event{}
	if err := json.Unmarshal(row.Data, ev); err != nil {
		return true, nil
	}
	if err := scoped.AttachAuditViolationSource(ctx, en.EventUID, ev.SourceIP(), row.Data); err != nil {
		return true, fmt.Errorf("audit violation source: %w", err)
	}
	hits := e.matcher.Match(cluster, ev, true)
	update := map[string]interface{}{
		"id": en.EventUID, "sourceIPs": en.SourceIPs, "userAgent": en.UserAgent,
		"statusCode": en.StatusCode, "allowed": en.Allowed, "auditID": en.AuditID,
	}
	if top, marked := topRule(hits); marked && sevRank[top.Severity] > sevRank[strings.ToLower(row.Sev)] {
		sev := strings.ToUpper(top.Severity)
		if err := scoped.MarkAuditEventRule(ctx, row.ID, row.Ts, top.ID, sev); err != nil {
			return true, fmt.Errorf("audit event mark: %w", err)
		}
		update["ruleId"], update["ruleName"], update["sev"] = top.ID, top.Name, sev
	}
	if data, err := json.Marshal(update); err == nil {
		e.hub.Publish(hub.Event{Cluster: cluster, Type: "audit_event_update", Data: data})
	}
	alerts, err := e.act(ctx, cluster, ev, row.Data, hits)
	if err != nil {
		return true, err
	}
	if err := scoped.InsertAlerts(ctx, alerts); err != nil {
		return true, fmt.Errorf("audit alerts: %w", err)
	}
	return true, nil
}

func (e *Engine) IngestLog(ctx context.Context, cluster string, records []LogRecord) error {
	e.store.EnsureClusterCached(cluster)
	var standalone []prepared
	for i := range records {
		rec := &records[i]
		ev := &rec.Event
		if rec.EventUID == "" {
			ev.Source = SourceAPILog
			raw, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			standalone = append(standalone, e.prepare(cluster, ev, raw))
			continue
		}
		en := store.AuditEnrichment{
			EventUID: rec.EventUID, SourceIPs: ev.SourceIPs, UserAgent: ev.UserAgent,
			AuditID: ev.AuditID, StatusCode: ev.StatusCode, Allowed: ev.IsAllowed(),
		}
		found, err := e.enrich(ctx, cluster, en)
		if err != nil {
			return err
		}
		if !found {
			e.mu.Lock()
			if len(e.pending) < pendingEnrichMax {
				e.pending[cluster+"|"+rec.EventUID] = pendingEnrich{en: en, at: time.Now()}
			}
			e.mu.Unlock()
		}
	}
	return e.persist(ctx, cluster, store.AuditOriginAPILog, standalone)
}
