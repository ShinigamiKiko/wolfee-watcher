package auditengine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wolfee-watcher/kvisior/internal/hub"
	"github.com/wolfee-watcher/kvisior/internal/store"
	"github.com/wolfee-watcher/pkg/auditrules"
)

type testPublisher struct{ events []hub.Event }

func (p *testPublisher) Publish(e hub.Event) { p.events = append(p.events, e) }

type fixture struct {
	ctx     context.Context
	pool    *pgxpool.Pool
	st      *store.Store
	cluster string
	pub     *testPublisher
}

func database(t *testing.T) *fixture {
	t.Helper()
	dsn := os.Getenv("AUDIT_TEST_DSN")
	if dsn == "" {
		t.Skip("set AUDIT_TEST_DSN to a disposable database migrated with central-migrate")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	st, err := store.NewFromPool(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{ctx: ctx, pool: pool, st: st, cluster: fmt.Sprintf("audit-test-%d", time.Now().UnixNano()), pub: &testPublisher{}}
	if err := st.EnsureCluster(ctx, f.cluster); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, table := range []string{"audit_ingest_state", "audit_thresholds", "audit_events", "audit_violations", "alerts", "kvisior_violations", "clusters"} {
			column := "cluster_id"
			if table == "clusters" {
				column = "id"
			}
			if _, err := pool.Exec(ctx, "DELETE FROM "+table+" WHERE "+column+"=$1", f.cluster); err != nil {
				t.Error(err)
			}
		}
	})
	return f
}
func (f *fixture) engine(rules ...auditrules.Rule) *Engine {
	for i := range rules {
		rules[i].Normalize()
	}
	e := New(f.st, f.pub)
	e.matcher.Replace(rules)
	e.loaded = true
	return e
}
func (f *fixture) counts(t *testing.T, events, hits, alerts int) {
	t.Helper()
	var nEvents, nHits, nAlerts int
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT COUNT(*) FROM audit_events WHERE cluster_id=$1),(SELECT COALESCE(SUM(hits),0) FROM audit_violations WHERE cluster_id=$1),(SELECT COUNT(*) FROM alerts WHERE cluster_id=$1)`, f.cluster).Scan(&nEvents, &nHits, &nAlerts); err != nil {
		t.Fatal(err)
	}
	if nEvents != events || nHits != hits || nAlerts != alerts {
		t.Fatalf("events/hits/alerts=%d/%d/%d, want %d/%d/%d", nEvents, nHits, nAlerts, events, hits, alerts)
	}
}
func event(id string) auditrules.Event {
	return auditrules.Event{ID: id, Timestamp: time.Now().UTC(), Kind: auditrules.KindCreate, Resource: "configmaps", Namespace: "prod", Name: "api", User: "alice"}
}
func rawEvent(ev auditrules.Event) json.RawMessage { raw, _ := json.Marshal(ev); return raw }
func eachRule() auditrules.Rule {
	return auditrules.Rule{ID: "each", Name: "Each", Enabled: true, Alert: true, Severity: auditrules.SevHigh, Spec: auditrules.Spec{Kinds: []string{auditrules.KindCreate}, AlertEvery: auditrules.AlertEach}}
}

func TestEachDistinctEventsAndConcurrentReplay(t *testing.T) {
	f := database(t)
	r := eachRule()
	replicas := []*Engine{f.engine(r), f.engine(r)}
	raws := []json.RawMessage{rawEvent(event("one")), rawEvent(event("two"))}
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for _, e := range replicas {
		e.hub = nil
	}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); errs <- replicas[i%2].IngestEvents(f.ctx, f.cluster, raws) }(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	f.counts(t, 2, 2, 2)
	var fingerprints int
	if err := f.pool.QueryRow(f.ctx, `SELECT COUNT(DISTINCT fingerprint) FROM alerts WHERE cluster_id=$1`, f.cluster).Scan(&fingerprints); err != nil {
		t.Fatal(err)
	}
	if fingerprints != 2 {
		t.Fatalf("each alerts have %d distinct fingerprints", fingerprints)
	}
}

func TestThresholdAcrossReplicasAndRestart(t *testing.T) {
	f := database(t)
	r := eachRule()
	r.ID = "threshold"
	r.Spec.AlertEvery = auditrules.AlertThreshold
	r.Spec.ThN = 3
	r.Spec.ThMin = 10
	a, b := f.engine(r), f.engine(r)
	for i, e := range []*Engine{a, b, f.engine(r)} {
		raw := rawEvent(event(fmt.Sprint(i)))
		if err := e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{raw, raw}); err != nil {
			t.Fatal(err)
		}
	}
	f.counts(t, 3, 3, 1)
}

func TestPendingEnrichmentSurvivesReplicaAndRestart(t *testing.T) {
	f := database(t)
	r := eachRule()
	r.Spec.IPMode = auditrules.IPIn
	r.Spec.IPList = "10.20.0.0/16"
	a, b := f.engine(r), f.engine(r)
	final := event("audit-1")
	final.SourceIPs = []string{"10.20.14.36"}
	final.UserAgent = "kubectl"
	yes := true
	final.Allowed = &yes
	final.StatusCode = 201
	rec := LogRecord{EventUID: "admission-1", Event: final}
	if err := a.IngestLog(f.ctx, f.cluster, []LogRecord{rec}); err != nil {
		t.Fatal(err)
	}
	f.counts(t, 0, 0, 0)
	raw := rawEvent(event("admission-1"))
	if err := b.IngestEvents(f.ctx, f.cluster, []json.RawMessage{raw}); err != nil {
		t.Fatal(err)
	}
	if err := f.engine(r).IngestLog(f.ctx, f.cluster, []LogRecord{rec}); err != nil {
		t.Fatal(err)
	}
	if err := a.IngestEvents(f.ctx, f.cluster, []json.RawMessage{raw}); err != nil {
		t.Fatal(err)
	}
	f.counts(t, 1, 1, 1)
	var origin, ip string
	var pending bool
	if err := f.pool.QueryRow(f.ctx, `SELECT origin,source_ip FROM audit_events WHERE cluster_id=$1`, f.cluster).Scan(&origin, &ip); err != nil {
		t.Fatal(err)
	}
	if origin != store.AuditOriginBoth || ip != "10.20.14.36" {
		t.Fatalf("enrichment=%s/%s", origin, ip)
	}
	if err := f.pool.QueryRow(f.ctx, `SELECT pending IS NOT NULL FROM audit_ingest_state WHERE cluster_id=$1`, f.cluster).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending {
		t.Fatal("pending enrichment not consumed")
	}
}

func (f *fixture) failAlerts(t *testing.T) {
	t.Helper()
	_, err := f.pool.Exec(f.ctx, `CREATE TABLE IF NOT EXISTS audit_test_failures(cluster_id text PRIMARY KEY);
 CREATE OR REPLACE FUNCTION audit_test_reject_alert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF EXISTS(SELECT 1 FROM audit_test_failures WHERE cluster_id=NEW.cluster_id) THEN RAISE EXCEPTION 'injected alert failure'; END IF;
 RETURN NEW; END $$;
 DROP TRIGGER IF EXISTS audit_test_reject_alert ON alerts;
 CREATE TRIGGER audit_test_reject_alert BEFORE INSERT ON alerts FOR EACH ROW EXECUTE FUNCTION audit_test_reject_alert();`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, `INSERT INTO audit_test_failures VALUES($1)`, f.cluster); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := f.pool.Exec(f.ctx, `DROP TRIGGER IF EXISTS audit_test_reject_alert ON alerts;
 DROP FUNCTION IF EXISTS audit_test_reject_alert();
 DROP TABLE IF EXISTS audit_test_failures;`); err != nil {
			t.Error(err)
		}
	})
}
func (f *fixture) allowAlerts(t *testing.T) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, `DELETE FROM audit_test_failures WHERE cluster_id=$1`, f.cluster); err != nil {
		t.Fatal(err)
	}
}

func TestAlertFailureRollsBackEventAndEffects(t *testing.T) {
	f := database(t)
	e := f.engine(eachRule())
	f.failAlerts(t)
	raw := rawEvent(event("retry"))
	if err := e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{raw}); err == nil {
		t.Fatal("expected injected failure")
	}
	f.counts(t, 0, 0, 0)
	if len(f.pub.events) != 0 {
		t.Fatal("published uncommitted effects")
	}
	f.allowAlerts(t)
	for i := 0; i < 2; i++ {
		if err := e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{raw}); err != nil {
			t.Fatal(err)
		}
	}
	f.counts(t, 1, 1, 1)
}

func TestEnrichmentFailureRollsBackOriginAndFinalRules(t *testing.T) {
	f := database(t)
	denied := eachRule()
	denied.ID = "denied"
	denied.Spec.Result = auditrules.ResultDenied
	allowed := eachRule()
	allowed.ID = "allowed"
	allowed.Spec.Result = auditrules.ResultAllowed
	e := f.engine(denied, allowed)
	raw := rawEvent(event("final"))
	if err := e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{raw}); err != nil {
		t.Fatal(err)
	}
	f.counts(t, 1, 0, 0)
	final := event("api-final")
	no := false
	final.Allowed = &no
	final.StatusCode = 403
	final.SourceIPs = []string{"203.0.113.1"}
	rec := LogRecord{EventUID: "final", Event: final}
	f.failAlerts(t)
	if err := e.IngestLog(f.ctx, f.cluster, []LogRecord{rec}); err == nil {
		t.Fatal("expected injected failure")
	}
	f.counts(t, 1, 0, 0)
	var origin string
	if err := f.pool.QueryRow(f.ctx, `SELECT origin FROM audit_events WHERE cluster_id=$1`, f.cluster).Scan(&origin); err != nil {
		t.Fatal(err)
	}
	if origin != store.AuditOriginAdmission {
		t.Fatalf("failed enrichment committed origin=%s", origin)
	}
	f.allowAlerts(t)
	for i := 0; i < 2; i++ {
		if err := f.engine(denied, allowed).IngestLog(f.ctx, f.cluster, []LogRecord{rec}); err != nil {
			t.Fatal(err)
		}
	}
	f.counts(t, 1, 1, 1)
	var rule string
	if err := f.pool.QueryRow(f.ctx, `SELECT rule_id FROM audit_violations WHERE cluster_id=$1`, f.cluster).Scan(&rule); err != nil {
		t.Fatal(err)
	}
	if rule != "denied" {
		t.Fatalf("wrong final rule %q", rule)
	}
}

func TestCombinedViolationsCursorAndLimit(t *testing.T) {
	f := database(t)
	e := f.engine(eachRule())
	f.st.Cluster(f.cluster).WriteViolation(f.ctx, "runtime", "r", "Runtime", "HIGH", "prod", "api", "runtime-1", json.RawMessage(`{}`))
	if err := e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{rawEvent(event("audit"))}); err != nil {
		t.Fatal(err)
	}
	f.st.Cluster(f.cluster).WriteViolation(f.ctx, "runtime", "r", "Runtime", "HIGH", "prod", "api", "runtime-2", json.RawMessage(`{}`))
	var since int64
	var kinds []string
	for i := 0; i < 3; i++ {
		rows, err := f.st.Cluster(f.cluster).QueryViolations(f.ctx, "", "all", since, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].ID <= since {
			t.Fatalf("invalid page %+v after %d", rows, since)
		}
		since = rows[0].ID
		kinds = append(kinds, rows[0].VType)
	}
	rows, err := f.st.Cluster(f.cluster).QueryViolations(f.ctx, "", "all", since, 1)
	if err != nil || len(rows) != 0 {
		t.Fatalf("cursor replayed rows=%+v err=%v", rows, err)
	}
	if fmt.Sprint(kinds) != "[runtime audit runtime]" {
		t.Fatalf("unstable union ordering %v", kinds)
	}
}

func TestIngestLoadsRulesBeforeAcknowledging(t *testing.T) {
	f := database(t)
	r := eachRule()
	r.ID = f.cluster
	r.Normalize()
	if err := f.st.CreateAuditRule(f.ctx, r); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.st.DeleteAuditRule(f.ctx, r.ID) })
	e := New(f.st, f.pub)
	if err := e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{rawEvent(event("startup"))}); err != nil {
		t.Fatal(err)
	}
	f.counts(t, 1, 1, 1)
}

func TestConcurrentThresholdIsGlobalAndDeduplicated(t *testing.T) {
	f := database(t)
	r := eachRule()
	r.ID = "parallel-threshold"
	r.Spec.AlertEvery = auditrules.AlertThreshold
	r.Spec.ThN = 3
	r.Spec.ThMin = 10
	replicas := []*Engine{f.engine(r), f.engine(r), f.engine(r)}
	for _, e := range replicas {
		e.hub = nil
	}
	var wg sync.WaitGroup
	errs := make(chan error, 60)
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			raw := rawEvent(event(fmt.Sprintf("parallel-%d", i)))
			errs <- replicas[i%len(replicas)].IngestEvents(f.ctx, f.cluster, []json.RawMessage{raw, raw})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	f.counts(t, 60, 60, 20)
}

func TestLateEnrichmentUpdatesExistingViolation(t *testing.T) {
	f := database(t)
	e := f.engine(eachRule())
	raw := rawEvent(event("late"))
	if err := e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{raw}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE audit_violations SET last_seen=NOW()-INTERVAL '1 hour' WHERE cluster_id=$1`, f.cluster); err != nil {
		t.Fatal(err)
	}
	final := event("late-log")
	final.SourceIPs = []string{"10.20.14.36"}
	yes := true
	final.Allowed = &yes
	final.StatusCode = 201
	if err := e.IngestLog(f.ctx, f.cluster, []LogRecord{{EventUID: "late", Event: final}}); err != nil {
		t.Fatal(err)
	}
	f.counts(t, 1, 1, 1)
	var ip string
	if err := f.pool.QueryRow(f.ctx, `SELECT source_ip FROM audit_violations WHERE cluster_id=$1`, f.cluster).Scan(&ip); err != nil {
		t.Fatal(err)
	}
	if ip != "10.20.14.36" {
		t.Fatalf("late enrichment lost violation source: %q", ip)
	}
}

func TestPendingSurvivesAdmissionRollback(t *testing.T) {
	f := database(t)
	r := eachRule()
	r.Spec.IPMode = auditrules.IPIn
	r.Spec.IPList = "10.20.0.0/16"
	e := f.engine(r)
	final := event("pending-log")
	final.SourceIPs = []string{"10.20.14.36"}
	yes := true
	final.Allowed = &yes
	final.StatusCode = 201
	if err := e.IngestLog(f.ctx, f.cluster, []LogRecord{{EventUID: "pending", Event: final}}); err != nil {
		t.Fatal(err)
	}
	f.failAlerts(t)
	raw := rawEvent(event("pending"))
	if err := e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{raw}); err == nil {
		t.Fatal("expected admission transaction failure")
	}
	f.counts(t, 0, 0, 0)
	var waiting bool
	if err := f.pool.QueryRow(f.ctx, `SELECT NOT admitted AND pending IS NOT NULL FROM audit_ingest_state WHERE cluster_id=$1`, f.cluster).Scan(&waiting); err != nil {
		t.Fatal(err)
	}
	if !waiting {
		t.Fatal("rollback discarded previously committed pending enrichment")
	}
	if len(f.pub.events) != 0 {
		t.Fatal("published rolled-back event")
	}
	f.allowAlerts(t)
	if err := f.engine(r).IngestEvents(f.ctx, f.cluster, []json.RawMessage{raw}); err != nil {
		t.Fatal(err)
	}
	f.counts(t, 1, 1, 1)
}

func TestThresholdAlertFailureDoesNotConsumeWindow(t *testing.T) {
	f := database(t)
	r := eachRule()
	r.Spec.AlertEvery = auditrules.AlertThreshold
	r.Spec.ThN = 3
	r.Spec.ThMin = 10
	e := f.engine(r)
	for _, id := range []string{"first", "second"} {
		if err := e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{rawEvent(event(id))}); err != nil {
			t.Fatal(err)
		}
	}
	f.failAlerts(t)
	raw := rawEvent(event("third"))
	if err := e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{raw}); err == nil {
		t.Fatal("expected threshold alert failure")
	}
	f.counts(t, 2, 2, 0)
	f.allowAlerts(t)
	for i := 0; i < 2; i++ {
		if err := f.engine(r).IngestEvents(f.ctx, f.cluster, []json.RawMessage{raw}); err != nil {
			t.Fatal(err)
		}
	}
	f.counts(t, 3, 3, 1)
}
