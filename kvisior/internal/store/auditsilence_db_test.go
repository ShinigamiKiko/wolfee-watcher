package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/wolfee-watcher/pkg/auditrules"
)

func silenceFixture(t *testing.T) (context.Context, *pgxpool.Pool, *Store, string) {
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
	st, err := NewFromPool(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	cluster := fmt.Sprintf("silence-%d", time.Now().UnixNano())
	if err := st.EnsureCluster(ctx, cluster); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dropSilenceCluster(pool, cluster) })
	return ctx, pool, st, cluster
}

func dropSilenceCluster(pool *pgxpool.Pool, cluster string) {
	for _, q := range []string{"DELETE FROM audit_events WHERE cluster_id=$1", "DELETE FROM audit_silences WHERE cluster_id=$1", "DELETE FROM clusters WHERE id=$1"} {
		pool.Exec(context.Background(), q, cluster)
	}
}

func silenceEvent(id, name, user string, ips ...string) AuditEventInsert {
	ev := &auditrules.Event{ID: id, Timestamp: time.Now().UTC(), Kind: auditrules.KindCreate, Resource: "configmaps",
		Namespace: "default", Name: name, User: user, SourceIPs: ips}
	raw, _ := json.Marshal(ev)
	origin := AuditOriginAdmission
	if len(ips) > 0 {
		origin = AuditOriginBoth
	}
	return AuditEventInsert{Raw: raw, Event: ev, Origin: origin}
}

func visibleNames(t *testing.T, ctx context.Context, scope *Scoped) []string {
	t.Helper()
	rows, err := scope.QueryAuditEvents(ctx, AuditEventQuery{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, r := range rows {
		var ev auditrules.Event
		json.Unmarshal(r.Data, &ev)
		names = append(names, ev.Name)
	}
	return names
}

func TestSilencedEventsLeaveMonitoringAndInvestigation(t *testing.T) {
	ctx, _, st, cluster := silenceFixture(t)
	scope := st.Cluster(cluster)
	silence, err := scope.CreateAuditSilence(ctx, AuditSilence{Object: "configmaps/default/noisy-*", User: "ci-bot", Reason: "deploy loop", CreatedBy: "admin"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !silence.Active || silence.ExpiresAt == nil || silence.CreatedBy != "admin" {
		t.Fatalf("created silence %+v", silence)
	}
	items := []AuditEventInsert{
		silenceEvent("e1", "noisy-1", "ci-bot"),
		silenceEvent("e2", "noisy-2", "ci-bot", "10.0.0.1"),
		silenceEvent("e3", "noisy-3", "alice"),
		silenceEvent("e4", "quiet", "ci-bot"),
	}
	if err := scope.InsertAuditEvents(ctx, items); err != nil {
		t.Fatal(err)
	}
	if !items[0].Silenced || !items[1].Silenced || items[2].Silenced || items[3].Silenced {
		t.Fatalf("silenced flags %v %v %v %v", items[0].Silenced, items[1].Silenced, items[2].Silenced, items[3].Silenced)
	}
	if got := fmt.Sprint(visibleNames(t, ctx, scope)); got != "[quiet noisy-3]" && got != "[noisy-3 quiet]" {
		t.Fatalf("visible events %s", got)
	}
	q := AuditEventQuery{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour)}
	if _, total, err := scope.AuditEventHistogram(ctx, q, 4); err != nil || total != 2 {
		t.Fatalf("histogram total %d err=%v", total, err)
	}
	groups, err := scope.AuditEventGroups(ctx, q, "user", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range groups {
		if g.Key == "ci-bot" && g.Events != 1 {
			t.Fatalf("ci-bot group counts %d events", g.Events)
		}
	}
	hidden, err := scope.ListSilencedEvents(ctx, silence.ID, 0, 10)
	if err != nil || len(hidden) != 2 || hidden[0].SilenceID != silence.ID || len(hidden[0].Data) == 0 {
		t.Fatalf("hidden %+v err=%v", hidden, err)
	}
	older, err := scope.ListSilencedEvents(ctx, 0, hidden[0].ID, 10)
	if err != nil || len(older) != 1 {
		t.Fatalf("older page %+v err=%v", older, err)
	}
	list, err := scope.ListAuditSilences(ctx)
	if err != nil || len(list) != 1 || list[0].Hits != 2 || list[0].LastHitAt == nil {
		t.Fatalf("silences %+v err=%v", list, err)
	}

	if found, err := scope.EndAuditSilence(ctx, silence.ID); err != nil || !found {
		t.Fatalf("end: %v %v", found, err)
	}
	after := []AuditEventInsert{silenceEvent("e5", "noisy-5", "ci-bot")}
	if err := scope.InsertAuditEvents(ctx, after); err != nil {
		t.Fatal(err)
	}
	if after[0].Silenced || len(visibleNames(t, ctx, scope)) != 3 {
		t.Fatalf("ended silence still hides new events: %v", visibleNames(t, ctx, scope))
	}

	if found, err := scope.DeleteAuditSilence(ctx, silence.ID); err != nil || !found {
		t.Fatalf("delete: %v %v", found, err)
	}
	if got := len(visibleNames(t, ctx, scope)); got != 5 {
		t.Fatalf("deleting the silence should bring its events back, %d visible", got)
	}
	if found, _ := scope.DeleteAuditSilence(ctx, silence.ID); found {
		t.Fatal("deleted twice")
	}
}

func TestEnrichedEventIsSilencedByItsSourceIP(t *testing.T) {
	ctx, pool, st, cluster := silenceFixture(t)
	scope := st.Cluster(cluster)
	if _, err := scope.CreateAuditSilence(ctx, AuditSilence{SourceIP: "203.0.113.0/24"}, 0); err != nil {
		t.Fatal(err)
	}
	items := []AuditEventInsert{silenceEvent("adm-1", "x", "bob")}
	if err := scope.InsertAuditEvents(ctx, items); err != nil {
		t.Fatal(err)
	}
	if items[0].Silenced || len(visibleNames(t, ctx, scope)) != 1 {
		t.Fatal("an event without an address was silenced")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	in := &Scoped{s: st, id: cluster, tx: tx}
	row, ok, err := in.EnrichAuditEvent(ctx, AuditEnrichment{EventUID: "adm-1", SourceIPs: []string{"203.0.113.9"}, Allowed: true, At: time.Now()})
	if err != nil || !ok || !row.Silenced || !row.NewlySilenced {
		t.Fatalf("enrichment row %+v ok=%v err=%v", row, ok, err)
	}
	if err := in.MarkAuditEventRule(ctx, row, "adm-1", "each", "HIGH"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if got := visibleNames(t, ctx, scope); len(got) != 0 {
		t.Fatalf("enriched event still visible: %v", got)
	}
	hidden, err := scope.ListSilencedEvents(ctx, 0, 0, 10)
	if err != nil || len(hidden) != 1 || hidden[0].Origin != AuditOriginBoth || hidden[0].RuleID != "each" {
		t.Fatalf("silenced copy %+v err=%v", hidden, err)
	}
	var ev auditrules.Event
	if json.Unmarshal(hidden[0].Data, &ev); ev.SourceIP() != "203.0.113.9" {
		t.Fatalf("silenced copy lacks the address: %s", hidden[0].Data)
	}
}

func TestSilencesAreScopedToTheCluster(t *testing.T) {
	ctx, pool, st, cluster := silenceFixture(t)
	other := cluster + "-other"
	if err := st.EnsureCluster(ctx, other); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dropSilenceCluster(pool, other) })
	if _, err := st.Cluster(cluster).CreateAuditSilence(ctx, AuditSilence{User: "ci-bot"}, 0); err != nil {
		t.Fatal(err)
	}
	items := []AuditEventInsert{silenceEvent("o1", "x", "ci-bot")}
	if err := st.Cluster(other).InsertAuditEvents(ctx, items); err != nil {
		t.Fatal(err)
	}
	if items[0].Silenced || len(visibleNames(t, ctx, st.Cluster(other))) != 1 {
		t.Fatal("another cluster's silence hid an event")
	}
	if list, err := st.Cluster(other).ListAuditSilences(ctx); err != nil || len(list) != 0 {
		t.Fatalf("other cluster sees %d silences, err=%v", len(list), err)
	}
	if found, _ := st.Cluster(other).DeleteAuditSilence(ctx, 1<<40); found {
		t.Fatal("deleted a missing silence")
	}
}

func TestSilenceDurationIsBounded(t *testing.T) {
	ctx, _, st, cluster := silenceFixture(t)
	if _, err := st.Cluster(cluster).CreateAuditSilence(ctx, AuditSilence{User: "x"}, AuditSilenceMaxDuration+time.Hour); err == nil {
		t.Fatal("accepted a silence longer than the limit")
	}
	s, err := st.Cluster(cluster).CreateAuditSilence(ctx, AuditSilence{User: "x"}, 0)
	if err != nil || s.ExpiresAt != nil || !s.Active {
		t.Fatalf("until-removed silence %+v err=%v", s, err)
	}
}
