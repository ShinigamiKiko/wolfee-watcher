package auditengine

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/hub"
	"github.com/wolfee-watcher/kvisior/internal/store"
	"github.com/wolfee-watcher/pkg/auditrules"
)

const (
	refreshInterval = 15 * time.Second
	alertSource     = "sentry-audit"
	alertDetType    = "Audit"
	SourceAPILog    = "apiserver-log"
	sourceInformer  = "kubernetes-informer"
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

type Engine struct {
	matcher *auditrules.Matcher
	store   *store.Store
	hub     hub.Publisher
	mu      sync.Mutex
	stamp   string
	loaded  bool
	loadMu  sync.Mutex
	proxyMu sync.Mutex
	proxies map[string]trustedProxies
	started time.Time
}

type trustedProxies struct {
	networks []*net.IPNet
	until    time.Time
}

const trustedProxiesRefresh = 30 * time.Second

func New(st *store.Store, pub hub.Publisher) *Engine {
	return &Engine{matcher: auditrules.NewMatcher(), store: st, hub: pub, proxies: map[string]trustedProxies{}, started: time.Now()}
}

func (e *Engine) trusted(ctx context.Context, cluster string) ([]*net.IPNet, error) {
	e.proxyMu.Lock()
	cached, ok := e.proxies[cluster]
	e.proxyMu.Unlock()
	if ok && time.Now().Before(cached.until) {
		return cached.networks, nil
	}
	settings, err := e.store.Cluster(cluster).AuditTrustedProxies(ctx)
	if err != nil {
		return nil, fmt.Errorf("audit trusted proxies: %w", err)
	}
	networks, err := trustedProxyNetworks(settings)
	if err != nil {
		slog.Warn("audit_trusted_proxies_invalid",
			"component", "kvisior/audit",
			"cluster", cluster, "error", err)
		networks = nil
	}
	e.proxyMu.Lock()
	e.proxies[cluster] = trustedProxies{networks: networks, until: time.Now().Add(trustedProxiesRefresh)}
	e.proxyMu.Unlock()
	return networks, nil
}

func trustedProxyNetworks(settings store.AuditProxySettings) ([]*net.IPNet, error) {
	if !settings.HeadersSanitized {
		return nil, nil
	}
	return auditrules.ParseProxies(settings.Proxies)
}

type eventBuffer []hub.Event

func (b *eventBuffer) Publish(ev hub.Event) { *b = append(*b, ev) }
func (e *Engine) publish(events eventBuffer) {
	if e.hub != nil {
		for _, ev := range events {
			e.hub.Publish(ev)
		}
	}
}

func (e *Engine) Reload(ctx context.Context) error {
	if e.store == nil {
		return nil
	}
	stamp, err := e.store.AuditRulesStamp(ctx)
	if err != nil {
		return err
	}
	rules, err := e.store.ListAuditRules(ctx)
	if err != nil {
		return err
	}
	e.matcher.Replace(rules)
	e.mu.Lock()
	changed := e.stamp != stamp
	e.stamp = stamp
	e.loaded = true
	e.mu.Unlock()
	if changed {
		slog.Info("audit_rules_loaded",
			"component", "kvisior/audit",
			"rules", len(rules),
			"active", e.matcher.Len())
	}
	return nil
}

func (e *Engine) ensureRules(ctx context.Context) error {
	if e.store == nil {
		return fmt.Errorf("audit store unavailable")
	}
	e.loadMu.Lock()
	defer e.loadMu.Unlock()
	e.mu.Lock()
	loaded := e.loaded
	e.mu.Unlock()
	if loaded {
		return nil
	}
	return e.Reload(ctx)
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
	sweep := time.NewTicker(pendingSweep)
	defer sweep.Stop()
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-sweep.C:
			if n, err := e.MaterializePending(ctx, PendingGrace); err != nil {
				slog.Warn("audit_pending_materialize_failed", "component", "kvisior/audit", "error", err)
			} else if n > 0 {
				slog.Info("audit_pending_materialized", "component", "kvisior/audit", "events", n)
			}
		case <-t.C:
			stamp, err := e.store.AuditRulesStamp(ctx)
			if err == nil {
				e.mu.Lock()
				same := stamp == e.stamp
				e.mu.Unlock()
				if same {
					failures = 0
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

func (e *Engine) act(ctx context.Context, scoped *store.Scoped, cluster, key string, ev *auditrules.Event, raw json.RawMessage, hits []auditrules.Rule, pub hub.Publisher) ([]store.IncomingAlert, error) {
	var alerts []store.IncomingAlert
	sort.Slice(hits, func(i, j int) bool { return hits[i].ID < hits[j].ID })
	for _, r := range hits {
		claimed, err := scoped.ClaimAuditRule(ctx, key, r.ID)
		if err != nil {
			return nil, err
		}
		if !claimed {
			continue
		}
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
				pub.Publish(hub.Event{Cluster: cluster, Type: "audit_violation", Data: data})
			}
		}
		fire := false
		if r.Alert {
			var err error
			fire, err = scoped.AuditThreshold(ctx, r)
			if err != nil {
				return nil, err
			}
		}
		if fire {
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
				Fingerprint: "aud|" + store.Fingerprint(cluster, r.ID, key, ""), Data: raw,
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
	if ev.ID == "" {
		ev.ID = fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	raw, _ = json.Marshal(ev)
	p := prepared{ev: ev, raw: raw, hits: e.matcher.Match(cluster, ev, false)}
	p.top, p.marked = topRule(p.hits)
	return p
}

func (e *Engine) persist(ctx context.Context, scoped *store.Scoped, cluster, origin, key string, p prepared, pub hub.Publisher) error {
	it := store.AuditEventInsert{Raw: p.raw, Event: p.ev, Origin: origin}
	if p.marked {
		it.RuleID, it.Sev = p.top.ID, strings.ToUpper(p.top.Severity)
	}
	if err := scoped.InsertAuditEvents(ctx, []store.AuditEventInsert{it}); err != nil {
		return fmt.Errorf("audit events: %w", err)
	}
	pub.Publish(hub.Event{Cluster: cluster, Type: "audit_event", Data: withRule(p.raw, p.top, p.marked)})
	alerts, err := e.act(ctx, scoped, cluster, key, p.ev, p.raw, p.hits, pub)
	if err != nil {
		return err
	}
	if err = scoped.InsertAlerts(ctx, alerts); err != nil {
		return fmt.Errorf("audit alerts: %w", err)
	}
	return nil
}

func clean(s string) string {
	if strings.IndexByte(s, 0) < 0 {
		return s
	}
	return strings.ReplaceAll(s, "\x00", "�")
}

func cleanAll(list []string) {
	for i := range list {
		list[i] = clean(list[i])
	}
}

func sanitize(ev *auditrules.Event) {
	for _, s := range []*string{
		&ev.ID, &ev.User, &ev.ImpersonatedUser, &ev.ServiceAccount, &ev.UserAgent, &ev.Kind, &ev.Resource, &ev.WebhookType,
		&ev.Namespace, &ev.Name, &ev.UID, &ev.ResourceVersion, &ev.PrevResourceVersion, &ev.Source, &ev.Container, &ev.AuditID,
	} {
		*s = clean(*s)
	}
	cleanAll(ev.Groups)
	cleanAll(ev.ImpersonatedGroups)
	cleanAll(ev.SourceIPs)
	cleanAll(ev.Commands)
}

const twinClockSkew = 5 * time.Second

func differ(a, b string) bool { return a != "" && b != "" && a != b }

func laterRevision(a, b string) bool {
	x, errA := strconv.ParseUint(a, 10, 64)
	y, errB := strconv.ParseUint(b, 10, 64)
	return errA == nil && errB == nil && x > y
}

const twinWatchLag = 15 * time.Second

func completion(ev *auditrules.Event) time.Time {
	if ev.CompletedAt != nil {
		return *ev.CompletedAt
	}
	return ev.Timestamp
}

func observedAfter(watch, received, completed time.Time) bool {
	return !watch.Before(received.Add(-twinClockSkew)) && !watch.After(completed.Add(twinWatchLag+twinClockSkew))
}

func earlierChange(a, b *store.AuditTwin) bool {
	if laterRevision(b.ResourceVersion, a.ResourceVersion) {
		return true
	}
	if laterRevision(a.ResourceVersion, b.ResourceVersion) {
		return false
	}
	return a.At.Before(b.At)
}

type twinMatch struct {
	uid       string
	confirmed bool
}

func (m twinMatch) attribution() string {
	if m.confirmed {
		return ""
	}
	return auditrules.AttributionUnconfirmed
}

func chosen(exact, chained, ordered *store.AuditTwin, candidates int) (twinMatch, bool) {
	switch {
	case exact != nil:
		return twinMatch{exact.EventUID, true}, true
	case chained != nil:
		return twinMatch{chained.EventUID, true}, true
	case ordered != nil:
		return twinMatch{ordered.EventUID, candidates == 1}, true
	}
	return twinMatch{}, false
}

func informerTwin(ev *auditrules.Event, twins []store.AuditTwin) (twinMatch, bool) {
	var exact, chained, ordered *store.AuditTwin
	candidates := 0
	inOrder := func(t *store.AuditTwin) {
		if !observedAfter(t.At, ev.Timestamp, completion(ev)) {
			return
		}
		candidates++
		if ordered == nil || earlierChange(t, ordered) {
			ordered = t
		}
	}
	for i := range twins {
		t := &twins[i]
		if t.Source != sourceInformer || t.Origin != store.AuditOriginAdmission || differ(ev.UID, t.ObjectUID) {
			continue
		}
		switch {
		case ev.ResourceVersion != "" && t.ResourceVersion != "":
			if exact == nil && ev.ResourceVersion == t.ResourceVersion {
				exact = t
			}
		case ev.Kind != auditrules.KindUpdate:
			if ev.UID != "" && t.ObjectUID != "" {
				if exact == nil {
					exact = t
				}
			} else {
				inOrder(t)
			}
		case ev.PrevResourceVersion == "" || t.PrevResourceVersion == "":
			inOrder(t)
		case ev.PrevResourceVersion == t.PrevResourceVersion:
			if exact == nil {
				exact = t
			}
		case laterRevision(t.PrevResourceVersion, ev.PrevResourceVersion):
			if chained == nil || laterRevision(chained.PrevResourceVersion, t.PrevResourceVersion) {
				chained = t
			}
		}
	}
	return chosen(exact, chained, ordered, candidates)
}

func logTwin(ev *auditrules.Event, twins []store.AuditTwin) (twinMatch, bool) {
	var exact, chained, ordered *store.AuditTwin
	candidates := 0
	inOrder := func(t *store.AuditTwin) {
		if !observedAfter(ev.Timestamp, t.At, t.CompletedAt) {
			return
		}
		candidates++
		if ordered == nil || t.CompletedAt.Before(ordered.CompletedAt) {
			ordered = t
		}
	}
	for i := range twins {
		t := &twins[i]
		if t.Origin != store.AuditOriginAPILog || differ(ev.UID, t.ObjectUID) {
			continue
		}
		switch {
		case ev.ResourceVersion != "" && t.ResourceVersion != "":
			if exact == nil && ev.ResourceVersion == t.ResourceVersion {
				exact = t
			}
		case ev.Kind != auditrules.KindUpdate:
			if ev.UID != "" && t.ObjectUID != "" {
				if exact == nil {
					exact = t
				}
			} else {
				inOrder(t)
			}
		case ev.PrevResourceVersion == "" || t.PrevResourceVersion == "":
			inOrder(t)
		case ev.PrevResourceVersion == t.PrevResourceVersion || laterRevision(ev.PrevResourceVersion, t.PrevResourceVersion):
			started := !t.At.After(ev.Timestamp.Add(twinClockSkew))
			if started && (chained == nil || t.CompletedAt.Before(chained.CompletedAt)) {
				chained = t
			}
		}
	}
	return chosen(exact, chained, ordered, candidates)
}

func objectTwins(ctx context.Context, scoped *store.Scoped, ev *auditrules.Event) ([]store.AuditTwin, error) {
	if err := scoped.LockAuditObject(ctx, ev.Kind, ev.Resource, ev.Name); err != nil {
		return nil, fmt.Errorf("audit object lock: %w", err)
	}
	twins, err := scoped.FindAuditTwins(ctx, ev.Kind, ev.Resource, ev.Name, ev.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("audit twin lookup: %w", err)
	}
	return twins, nil
}

func rejected(err error, cluster, key string) bool {
	if !store.IsDataError(err) {
		return false
	}
	slog.Error("audit_event_rejected",
		"component", "kvisior/audit",
		"cluster", cluster, "event", key, "error", err)
	return true
}

func (e *Engine) IngestEvents(ctx context.Context, cluster string, raws []json.RawMessage) error {
	if err := e.ensureRules(ctx); err != nil {
		return err
	}
	e.store.EnsureClusterCached(cluster)
	type item struct {
		key string
		p   prepared
	}
	items := make([]item, 0, len(raws))
	keys := make([]string, 0, len(raws))
	scope := e.store.Cluster(cluster)
	trusted, err := e.trusted(ctx, cluster)
	if err != nil {
		return err
	}
	for _, raw := range raws {
		ev := &auditrules.Event{}
		if err := json.Unmarshal(raw, ev); err != nil {
			slog.Warn("audit_event_unreadable", "component", "kvisior/audit", "error", err)
			continue
		}
		sanitize(ev)
		ev.ClientIP = auditrules.ClientIP(ev.SourceIPs, trusted)
		ev.Allowed = nil
		ev.StatusCode = 0
		p := e.prepare(cluster, ev, raw)
		if ev.Timestamp.Before(time.Now().Add(-store.AuditRetention)) {
			continue
		}
		key := "admission:" + ev.ID
		items = append(items, item{key: key, p: p})
		keys = append(keys, key)
	}
	progress, err := scope.AuditProgress(ctx, keys)
	if err != nil {
		return err
	}
	for _, it := range items {
		if done := progress[it.key]; done.Admitted && (done.Enriched || !done.Pending) {
			continue
		}
		key, p, ev := it.key, it.p, it.p.ev
		var events eventBuffer
		err := scope.WithAuditEvent(ctx, key, func(scoped *store.Scoped, state *store.AuditState) error {
			if !state.Admitted {
				var err error
				state.Admitted, state.Enriched, err = scoped.ExistingAuditEvent(ctx, ev.ID, ev.Timestamp)
				if err != nil {
					return err
				}
				if !state.Admitted && ev.Source == sourceInformer && store.AuditInformerResource(ev.Resource) {
					twins, err := objectTwins(ctx, scoped, ev)
					if err != nil {
						return err
					}
					if match, ok := logTwin(ev, twins); ok {
						if err := scoped.MergeAuditObjectMeta(ctx, match.uid, ev.Timestamp, map[string]string{
							"uid": ev.UID, "resourceVersion": ev.ResourceVersion,
							"prevResourceVersion": ev.PrevResourceVersion, "webhookType": ev.WebhookType,
							"attribution": match.attribution(),
						}); err != nil {
							return fmt.Errorf("audit twin merge: %w", err)
						}
						if attribution := match.attribution(); attribution != "" {
							if data, err := json.Marshal(map[string]string{"id": match.uid, "attribution": attribution}); err == nil {
								events.Publish(hub.Event{Cluster: cluster, Type: "audit_event_update", Data: data})
							}
						}
						state.Admitted = true
						return nil
					}
				}
				if !state.Admitted {
					if err = e.persist(ctx, scoped, cluster, store.AuditOriginAdmission, key, p, &events); err != nil {
						return err
					}
					state.Admitted = true
				}
			}
			if state.Pending != nil && state.Pending.Materialized {
				if err := e.mergeAdmission(ctx, scoped, cluster, key, ev, state.Pending.At, &events); err != nil {
					return err
				}
				state.Enriched = true
				state.Pending = nil
				return nil
			}
			if state.Pending != nil && !state.Enriched {
				en := *state.Pending
				en.At = ev.Timestamp
				ok, err := e.enrich(ctx, scoped, cluster, key, en, &events)
				if err != nil {
					return err
				}
				if ok {
					state.Enriched = true
					state.Pending = nil
				}
			}
			return nil
		})
		if err != nil {
			if rejected(err, cluster, key) {
				continue
			}
			return err
		}
		e.publish(events)
	}
	return nil
}

func (e *Engine) enrich(ctx context.Context, scoped *store.Scoped, cluster, key string, en store.AuditEnrichment, pub hub.Publisher) (bool, error) {
	row, ok, err := scoped.EnrichAuditEvent(ctx, en)
	if err != nil {
		return false, fmt.Errorf("audit enrichment: %w", err)
	}
	if !ok {
		return false, nil
	}
	ev := &auditrules.Event{}
	if err := json.Unmarshal(row.Data, ev); err != nil {
		return false, fmt.Errorf("decode stored audit event: %w", err)
	}
	if row.RuleID != "" {
		if err := scoped.AttachAuditViolationSource(ctx, en.EventUID, ev.SourceIP(), en.User, row.Data); err != nil {
			return true, fmt.Errorf("audit violation source: %w", err)
		}
	}
	if err := scoped.AttachAuditAlertActor(ctx, en.EventUID, row.Ts, en.User, row.Data); err != nil {
		slog.Warn("audit_alert_actor_not_updated",
			"component", "kvisior/audit",
			"cluster", cluster, "event", en.EventUID, "error", err)
	}
	hits := e.matcher.Match(cluster, ev, false)
	update := map[string]interface{}{
		"id": en.EventUID, "sourceIPs": en.SourceIPs, "clientIP": en.ClientIP, "userAgent": en.UserAgent,
		"statusCode": en.StatusCode, "allowed": en.Allowed, "auditID": en.AuditID,
	}
	if en.User != "" {
		update["user"], update["groups"], update["serviceAccount"] = en.User, en.Groups, ""
		if en.ImpersonatedUser != "" {
			update["impersonatedUser"], update["impersonatedGroups"] = en.ImpersonatedUser, en.ImpersonatedGroups
		}
		if en.Attribution != "" {
			update["attribution"] = en.Attribution
		}
	}
	if top, marked := topRule(hits); marked && sevRank[top.Severity] > sevRank[strings.ToLower(row.Sev)] {
		sev := strings.ToUpper(top.Severity)
		if err := scoped.MarkAuditEventRule(ctx, row.ID, row.Ts, top.ID, sev); err != nil {
			return true, fmt.Errorf("audit event mark: %w", err)
		}
		update["ruleId"], update["ruleName"], update["sev"] = top.ID, top.Name, sev
	}
	if data, err := json.Marshal(update); err == nil {
		pub.Publish(hub.Event{Cluster: cluster, Type: "audit_event_update", Data: data})
	}
	alerts, err := e.act(ctx, scoped, cluster, key, ev, row.Data, hits, pub)
	if err != nil {
		return true, err
	}
	if err := scoped.InsertAlerts(ctx, alerts); err != nil {
		return true, fmt.Errorf("audit alerts: %w", err)
	}
	return true, nil
}

func (e *Engine) IngestLog(ctx context.Context, cluster string, records []LogRecord) error {
	if err := e.ensureRules(ctx); err != nil {
		return err
	}
	e.store.EnsureClusterCached(cluster)
	type item struct {
		key     string
		legacy  string
		rec     *LogRecord
		p       prepared
		watched bool
	}
	enrichment := func(uid string, ev *auditrules.Event, actor bool) store.AuditEnrichment {
		en := store.AuditEnrichment{
			EventUID: uid, SourceIPs: ev.SourceIPs, ClientIP: ev.ClientIP, UserAgent: ev.UserAgent, AuditID: ev.AuditID,
			StatusCode: ev.StatusCode, Allowed: ev.IsAllowed(), At: ev.Timestamp,
		}
		if actor {
			en.User, en.Groups = ev.User, ev.Groups
			en.ImpersonatedUser, en.ImpersonatedGroups = ev.ImpersonatedUser, ev.ImpersonatedGroups
		}
		return en
	}
	items := make([]item, 0, len(records))
	keys := make([]string, 0, len(records))
	scope := e.store.Cluster(cluster)
	trusted, err := e.trusted(ctx, cluster)
	if err != nil {
		return err
	}
	for i := range records {
		record := records[i]
		rec := &record
		ev := &rec.Event
		if !ev.Timestamp.IsZero() && ev.Timestamp.Before(time.Now().Add(-store.AuditRetention)) {
			continue
		}
		sanitize(ev)
		ev.ClientIP = auditrules.ClientIP(ev.SourceIPs, trusted)
		rec.EventUID = clean(rec.EventUID)
		it := item{rec: rec, key: "admission:" + rec.EventUID}
		if rec.EventUID == "" {
			it.watched = ev.IsAllowed() && !ev.Unchanged && store.AuditInformerResource(ev.Resource)
			ev.Source = SourceAPILog
			if ev.AuditID == "" {
				ev.AuditID = ev.ID
			}
			if ev.AuditID != "" && ev.Timestamp.Before(e.started) {
				it.legacy = "apilog:" + ev.AuditID
			}
			ev.ID = apiLogEventID(ev)
			raw, err := json.Marshal(ev)
			if err != nil {
				slog.Warn("audit_event_unreadable", "component", "kvisior/audit", "error", err)
				continue
			}
			it.p = e.prepare(cluster, ev, raw)
			it.key = "apilog:" + ev.ID
		}
		items = append(items, it)
		keys = append(keys, it.key)
		if it.legacy != "" {
			keys = append(keys, it.legacy)
		}
	}
	progress, err := scope.AuditProgress(ctx, keys)
	if err != nil {
		return err
	}
	for _, it := range items {
		key, rec, ev := it.key, it.rec, &it.rec.Event
		done := progress[key]
		if it.legacy != "" && progress[it.legacy].Admitted {
			continue
		}
		var events eventBuffer
		var err error
		if rec.EventUID == "" {
			if done.Admitted {
				continue
			}
			p := it.p
			err = scope.WithAuditEvent(ctx, key, func(scoped *store.Scoped, state *store.AuditState) error {
				if state.Admitted {
					return nil
				}
				if it.watched {
					twins, err := objectTwins(ctx, scoped, ev)
					if err != nil {
						return err
					}
					if match, ok := informerTwin(ev, twins); ok {
						en := enrichment(match.uid, ev, true)
						en.Attribution = match.attribution()
						merged, err := e.enrich(ctx, scoped, cluster, "admission:"+match.uid, en, &events)
						if err != nil {
							return err
						}
						if merged {
							state.Admitted = true
							return nil
						}
					}
				}
				if err := e.persist(ctx, scoped, cluster, store.AuditOriginAPILog, key, p, &events); err != nil {
					return err
				}
				state.Admitted = true
				return nil
			})
		} else {
			if done.Enriched || (done.Pending && !done.Admitted) {
				continue
			}
			en := enrichment(rec.EventUID, ev, ev.ImpersonatedUser != "")
			err = scope.WithAuditEvent(ctx, key, func(scoped *store.Scoped, state *store.AuditState) error {
				if state.Enriched || (state.Pending != nil && state.Pending.Materialized) {
					return nil
				}
				if !state.Admitted {
					var err error
					state.Admitted, state.Enriched, err = scoped.ExistingAuditEvent(ctx, rec.EventUID, ev.Timestamp)
					if err != nil {
						return err
					}
					if state.Enriched {
						return nil
					}
				}
				if !state.Admitted {
					logged := *ev
					en.Event = &logged
					state.Pending = &en
					return nil
				}
				ok, err := e.enrich(ctx, scoped, cluster, key, en, &events)
				if err != nil {
					return err
				}
				state.Enriched = ok
				if ok {
					state.Pending = nil
				} else {
					state.Pending = &en
				}
				return nil
			})
		}
		if err != nil {
			if rejected(err, cluster, key) {
				continue
			}
			return err
		}
		e.publish(events)
	}
	return nil
}
