package auditengine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/hub"
	"github.com/wolfee-watcher/kvisior/internal/store"
	"github.com/wolfee-watcher/pkg/auditrules"
)

const (
	PendingGrace = 5 * time.Minute
	pendingSweep = 30 * time.Second
	pendingBatch = 200
)

func (e *Engine) MaterializePending(ctx context.Context, grace time.Duration) (int, error) {
	return e.materializePending(ctx, "", grace)
}

func (e *Engine) materializePending(ctx context.Context, cluster string, grace time.Duration) (int, error) {
	if err := e.ensureRules(ctx); err != nil {
		return 0, err
	}
	stale, err := e.store.StaleAuditPending(ctx, cluster, grace, pendingBatch)
	if err != nil {
		return 0, err
	}
	created := 0
	for _, k := range stale {
		ok, err := e.materialize(ctx, k.Cluster, k.Key)
		if err != nil {
			if rejected(err, k.Cluster, k.Key) {
				if err := e.dropPendingEvent(ctx, k.Cluster, k.Key); err != nil {
					return created, err
				}
				continue
			}
			return created, err
		}
		if ok {
			created++
		}
	}
	return created, nil
}

func (e *Engine) dropPendingEvent(ctx context.Context, cluster, key string) error {
	return e.store.Cluster(cluster).WithAuditEvent(ctx, key, func(_ *store.Scoped, state *store.AuditState) error {
		if state.Pending != nil && state.Pending.Event != nil {
			en := *state.Pending
			en.Event = nil
			state.Pending = &en
		}
		return nil
	})
}

func (e *Engine) materialize(ctx context.Context, cluster, key string) (bool, error) {
	e.store.EnsureClusterCached(cluster)
	var events eventBuffer
	created := false
	err := e.store.Cluster(cluster).WithAuditEvent(ctx, key, func(scoped *store.Scoped, state *store.AuditState) error {
		if state.Admitted || state.Pending == nil || state.Pending.Event == nil {
			return nil
		}
		en := *state.Pending
		logged := *en.Event
		en.Event = nil
		admitted, enriched, err := scoped.ExistingAuditEvent(ctx, en.EventUID, logged.Timestamp)
		if err != nil {
			return err
		}
		if admitted {
			state.Admitted, state.Enriched = true, enriched
			state.Pending = &en
			if enriched {
				state.Pending = nil
				return nil
			}
			ok, err := e.enrich(ctx, scoped, cluster, key, en, &events)
			if err != nil {
				return err
			}
			if ok {
				state.Enriched = true
				state.Pending = nil
			}
			return nil
		}
		logged.ID = en.EventUID
		logged.Source = SourceAPILog
		if logged.AuditID == "" {
			logged.AuditID = en.AuditID
		}
		raw, err := json.Marshal(&logged)
		if err != nil {
			return err
		}
		p := e.prepare(cluster, &logged, raw)
		if err := e.persist(ctx, scoped, cluster, store.AuditOriginAPILog, key, p, &events); err != nil {
			return err
		}
		state.Admitted = true
		state.Pending = &store.AuditEnrichment{EventUID: en.EventUID, At: logged.Timestamp, Materialized: true}
		created = true
		return nil
	})
	if err != nil {
		return false, err
	}
	e.publish(events)
	return created, nil
}

func admissionDetails(ev *auditrules.Event) map[string]interface{} {
	details := map[string]interface{}{}
	set := func(name, value string) {
		if value != "" {
			details[name] = value
		}
	}
	set("source", ev.Source)
	set("webhookType", ev.WebhookType)
	set("uid", ev.UID)
	set("resourceVersion", ev.ResourceVersion)
	set("prevResourceVersion", ev.PrevResourceVersion)
	set("container", ev.Container)
	if len(ev.Commands) > 0 {
		details["commands"] = ev.Commands
	}
	if len(ev.Ports) > 0 {
		details["ports"] = ev.Ports
	}
	if ev.Unchanged {
		details["unchanged"] = true
	}
	if ev.CompletedAt != nil {
		details["completedAt"] = ev.CompletedAt
	}
	set("serviceAccount", ev.ServiceAccount)
	return details
}

func (e *Engine) mergeAdmission(ctx context.Context, scoped *store.Scoped, cluster, key string, ev *auditrules.Event, at time.Time, pub hub.Publisher) error {
	details := admissionDetails(ev)
	row, ok, err := scoped.MergeAdmissionDetails(ctx, ev.ID, at, details)
	if err != nil {
		return fmt.Errorf("audit admission merge: %w", err)
	}
	if !ok {
		return nil
	}
	merged := &auditrules.Event{}
	if err := json.Unmarshal(row.Data, merged); err != nil {
		return fmt.Errorf("decode stored audit event: %w", err)
	}
	hits := e.matcher.Match(cluster, merged, false)
	update := map[string]interface{}{"id": ev.ID, "origin": store.AuditOriginBoth}
	for name, value := range details {
		update[name] = value
	}
	if top, marked := topRule(hits); marked && sevRank[top.Severity] > sevRank[strings.ToLower(row.Sev)] {
		sev := strings.ToUpper(top.Severity)
		if err := scoped.MarkAuditEventRule(ctx, row, ev.ID, top.ID, sev); err != nil {
			return fmt.Errorf("audit event mark: %w", err)
		}
		update["ruleId"], update["ruleName"], update["sev"] = top.ID, top.Name, sev
	}
	publishUpdate(pub, cluster, ev.ID, row, update)
	alerts, err := e.act(ctx, scoped, cluster, key, merged, row.Data, hits, pub)
	if err != nil {
		return err
	}
	if err := scoped.InsertAlerts(ctx, alerts); err != nil {
		return fmt.Errorf("audit alerts: %w", err)
	}
	return nil
}

func publishUpdate(pub hub.Publisher, cluster, uid string, row store.AuditEventRow, update map[string]interface{}) {
	if row.NewlySilenced {
		if data, err := json.Marshal(map[string]string{"id": uid}); err == nil {
			pub.Publish(hub.Event{Cluster: cluster, Type: "audit_event_silenced", Data: data})
		}
		return
	}
	if row.Silenced {
		return
	}
	if data, err := json.Marshal(update); err == nil {
		pub.Publish(hub.Event{Cluster: cluster, Type: "audit_event_update", Data: data})
	}
}
