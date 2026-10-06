package auditengine

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/store"
)

func TestSilencedEventStillRunsRulesButStaysOffTheStream(t *testing.T) {
	f := database(t)
	t.Cleanup(func() { f.pool.Exec(context.Background(), "DELETE FROM audit_silences WHERE cluster_id=$1", f.cluster) })
	scope := f.st.Cluster(f.cluster)
	if _, err := scope.CreateAuditSilence(f.ctx, store.AuditSilence{User: "alice", Object: "configmaps/prod/*"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	e := f.engine(eachRule())
	if err := e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{rawEvent(event("hushed"))}); err != nil {
		t.Fatal(err)
	}
	f.counts(t, 1, 1, 1)
	for _, ev := range f.pub.events {
		if ev.Type == "audit_event" {
			t.Fatalf("silenced event was streamed: %s", ev.Data)
		}
	}
	hidden, err := scope.ListSilencedEvents(f.ctx, 0, 0, 10)
	if err != nil || len(hidden) != 1 || hidden[0].RuleID != "each" {
		t.Fatalf("silenced events %+v err=%v", hidden, err)
	}
	rows, err := scope.QueryAuditEvents(f.ctx, store.AuditEventQuery{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour)})
	if err != nil || len(rows) != 0 {
		t.Fatalf("silenced event visible in queries: %d rows err=%v", len(rows), err)
	}
}

func TestEventSilencedOnEnrichmentLeavesTheStream(t *testing.T) {
	f := database(t)
	t.Cleanup(func() { f.pool.Exec(context.Background(), "DELETE FROM audit_silences WHERE cluster_id=$1", f.cluster) })
	if _, err := f.st.Cluster(f.cluster).CreateAuditSilence(f.ctx, store.AuditSilence{SourceIP: "10.20.0.0/16"}, 0); err != nil {
		t.Fatal(err)
	}
	e := f.engine(eachRule())
	if err := e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{rawEvent(event("late-ip"))}); err != nil {
		t.Fatal(err)
	}
	streamed := false
	for _, ev := range f.pub.events {
		streamed = streamed || ev.Type == "audit_event"
	}
	if !streamed {
		t.Fatal("event without an address should be streamed")
	}
	final := event("late-ip-log")
	final.SourceIPs = []string{"10.20.14.36"}
	yes := true
	final.Allowed = &yes
	f.pub.events = nil
	if err := e.IngestLog(f.ctx, f.cluster, []LogRecord{{EventUID: "late-ip", Event: final}}); err != nil {
		t.Fatal(err)
	}
	silenced := false
	for _, ev := range f.pub.events {
		if ev.Type == "audit_event_update" {
			t.Fatalf("update streamed for a silenced event: %s", ev.Data)
		}
		silenced = silenced || ev.Type == "audit_event_silenced"
	}
	if !silenced {
		t.Fatal("no audit_event_silenced message for the stream")
	}
	f.counts(t, 1, 1, 1)
}
