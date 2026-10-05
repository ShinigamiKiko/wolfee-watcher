package auditengine

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/store"
	"github.com/wolfee-watcher/pkg/auditrules"
)

func execRules() []auditrules.Rule {
	exec := auditrules.Rule{ID: "exec", Name: "Exec", Enabled: true, Alert: true, Severity: auditrules.SevMedium,
		Spec: auditrules.Spec{Kinds: []string{auditrules.KindExec}, AlertEvery: auditrules.AlertEach}}
	shell := auditrules.Rule{ID: "shell", Name: "Shell", Enabled: true, Alert: true, Severity: auditrules.SevCritical,
		Spec: auditrules.Spec{Kinds: []string{auditrules.KindExec}, Cmd: "sh", AlertEvery: auditrules.AlertEach}}
	return []auditrules.Rule{exec, shell}
}

func execLog(uid string) LogRecord {
	yes := true
	ev := auditrules.Event{ID: "audit-" + uid, AuditID: "audit-" + uid, Timestamp: time.Now().UTC(),
		Kind: auditrules.KindExec, Resource: "pods", Namespace: "prod", Name: "api-0", User: "alice",
		SourceIPs: []string{"10.20.14.36"}, UserAgent: "kubectl", Allowed: &yes, StatusCode: 101}
	return LogRecord{EventUID: uid, Event: ev}
}

func execAdmission(uid string) json.RawMessage {
	return rawEvent(auditrules.Event{ID: uid, Timestamp: time.Now().UTC(), Kind: auditrules.KindExec, Resource: "pods",
		Namespace: "prod", Name: "api-0", User: "alice", Container: "app", Commands: []string{"sh", "-c", "id"}})
}

func (f *fixture) ledger(t *testing.T, key string) (admitted, enriched, pending bool) {
	t.Helper()
	if err := f.pool.QueryRow(f.ctx, `SELECT admitted, enriched, pending IS NOT NULL FROM audit_ingest_state WHERE cluster_id=$1 AND event_key=$2`,
		f.cluster, key).Scan(&admitted, &enriched, &pending); err != nil {
		t.Fatal(err)
	}
	return
}

func TestLostAdmissionIsRecoveredFromTheLog(t *testing.T) {
	f := database(t)
	e := f.engine(execRules()...)
	rec := execLog("lost-1")
	if err := e.IngestLog(f.ctx, f.cluster, []LogRecord{rec}); err != nil {
		t.Fatal(err)
	}
	if n, err := e.materializePending(f.ctx, f.cluster, time.Hour); err != nil || n != 0 {
		t.Fatalf("materialized %d before the grace period, err=%v", n, err)
	}
	f.counts(t, 0, 0, 0)
	if n, err := e.materializePending(f.ctx, f.cluster, 0); err != nil || n != 1 {
		t.Fatalf("materialized %d after the grace period, err=%v", n, err)
	}
	f.counts(t, 1, 1, 1)
	var origin, uid, ip, source string
	if err := f.pool.QueryRow(f.ctx, `SELECT origin, event_uid, source_ip, data->>'source' FROM audit_events WHERE cluster_id=$1`, f.cluster).Scan(&origin, &uid, &ip, &source); err != nil {
		t.Fatal(err)
	}
	if origin != store.AuditOriginAPILog || uid != "lost-1" || ip != "10.20.14.36" || source != SourceAPILog {
		t.Fatalf("materialized event origin=%s uid=%s ip=%s source=%s", origin, uid, ip, source)
	}
	for i := 0; i < 2; i++ {
		if err := f.engine(execRules()...).IngestLog(f.ctx, f.cluster, []LogRecord{rec}); err != nil {
			t.Fatal(err)
		}
		if n, err := e.materializePending(f.ctx, f.cluster, 0); err != nil || n != 0 {
			t.Fatalf("materialized again: %d, err=%v", n, err)
		}
	}
	f.counts(t, 1, 1, 1)
	if admitted, enriched, pending := f.ledger(t, "admission:lost-1"); !admitted || enriched || !pending {
		t.Fatalf("ledger after materialization admitted=%v enriched=%v pending=%v", admitted, enriched, pending)
	}

	for i := 0; i < 2; i++ {
		if err := f.engine(execRules()...).IngestEvents(f.ctx, f.cluster, []json.RawMessage{execAdmission("lost-1")}); err != nil {
			t.Fatal(err)
		}
	}
	f.counts(t, 1, 2, 2)
	var container, rule, sev string
	if err := f.pool.QueryRow(f.ctx, `SELECT origin, source_ip, data->>'container', rule_id, sev FROM audit_events WHERE cluster_id=$1`, f.cluster).Scan(&origin, &ip, &container, &rule, &sev); err != nil {
		t.Fatal(err)
	}
	if origin != store.AuditOriginBoth || ip != "10.20.14.36" || container != "app" || rule != "shell" || sev != "CRITICAL" {
		t.Fatalf("merged event origin=%s ip=%s container=%s rule=%s sev=%s", origin, ip, container, rule, sev)
	}
	if admitted, enriched, pending := f.ledger(t, "admission:lost-1"); !admitted || !enriched || pending {
		t.Fatalf("ledger after merge admitted=%v enriched=%v pending=%v", admitted, enriched, pending)
	}
}

func TestPromptAdmissionIsNotMaterialized(t *testing.T) {
	f := database(t)
	e := f.engine(execRules()...)
	if err := e.IngestLog(f.ctx, f.cluster, []LogRecord{execLog("prompt")}); err != nil {
		t.Fatal(err)
	}
	if err := e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{execAdmission("prompt")}); err != nil {
		t.Fatal(err)
	}
	if n, err := e.materializePending(f.ctx, f.cluster, 0); err != nil || n != 0 {
		t.Fatalf("materialized %d events that had arrived, err=%v", n, err)
	}
	f.counts(t, 1, 2, 2)
	var origin string
	if err := f.pool.QueryRow(f.ctx, `SELECT origin FROM audit_events WHERE cluster_id=$1`, f.cluster).Scan(&origin); err != nil {
		t.Fatal(err)
	}
	if origin != store.AuditOriginBoth {
		t.Fatalf("origin=%s", origin)
	}
}

func TestPendingFromBeforeTheUpgradeIsLeftAlone(t *testing.T) {
	f := database(t)
	e := f.engine(execRules()...)
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO audit_ingest_state(cluster_id, event_key, pending, created_at) VALUES ($1, 'admission:old', '{"EventUID":"old"}', NOW() - INTERVAL '1 hour')`, f.cluster); err != nil {
		t.Fatal(err)
	}
	if n, err := e.materializePending(f.ctx, f.cluster, 0); err != nil || n != 0 {
		t.Fatalf("materialized %d legacy rows, err=%v", n, err)
	}
	f.counts(t, 0, 0, 0)
}
