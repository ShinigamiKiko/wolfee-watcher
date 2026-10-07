package store

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/wolfee-watcher/pkg/auditrules"
)

func rollupEvent(id, user, ip string, ts time.Time, allowed bool, rule string) AuditEventInsert {
	ev := &auditrules.Event{ID: id, Timestamp: ts, Kind: auditrules.KindCreate, Resource: "configmaps",
		Namespace: "default", Name: "cm-" + id, User: user, Allowed: &allowed}
	if ip != "" {
		ev.SourceIPs = []string{ip}
	}
	raw, _ := json.Marshal(ev)
	return AuditEventInsert{Raw: raw, Event: ev, Origin: AuditOriginBoth, RuleID: rule}
}

func buildRollupHours(t *testing.T, ctx context.Context, st *Store, cluster string, from, to time.Time) {
	t.Helper()
	for h := hourOf(from); h.Before(to); h = h.Add(time.Hour) {
		tx, err := st.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := rebuildRollupHour(ctx, tx, cluster, h); err != nil {
			tx.Rollback(ctx)
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

func dropRollupHours(t *testing.T, ctx context.Context, st *Store, cluster string, from, to time.Time) {
	t.Helper()
	if _, err := st.pool.Exec(ctx, `DELETE FROM audit_rollup_marks WHERE cluster_id = $1 AND hour >= $2 AND hour < $3`, cluster, hourOf(from), to); err != nil {
		t.Fatal(err)
	}
}

func rollupBuilt(t *testing.T, ctx context.Context, st *Store, cluster string, h time.Time) bool {
	t.Helper()
	var ok bool
	if err := st.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_rollup_marks WHERE cluster_id = $1 AND hour = $2)`, cluster, hourOf(h)).Scan(&ok); err != nil {
		t.Fatal(err)
	}
	return ok
}

type rollupView struct {
	total, danger int64
	groups        []AuditGroup
}

func viewOf(t *testing.T, ctx context.Context, scope *Scoped, q AuditEventQuery) rollupView {
	t.Helper()
	buckets, total, err := scope.AuditEventHistogram(ctx, q, 12)
	if err != nil {
		t.Fatal(err)
	}
	v := rollupView{total: total}
	for _, b := range buckets {
		v.danger += b.Dangerous
	}
	if v.groups, err = scope.AuditEventGroups(ctx, q, "user", 100, 0); err != nil {
		t.Fatal(err)
	}
	for i := range v.groups {
		v.groups[i].LastSeen = v.groups[i].LastSeen.UTC()
	}
	return v
}

func TestAuditRollupsMatchRawAndFollowSilences(t *testing.T) {
	ctx, _, st, cluster := silenceFixture(t)
	if ready, err := st.auditRollupsReady(ctx, st.pool); err != nil || !ready {
		t.Skip("database is not migrated to 0018")
	}
	scope := st.Cluster(cluster)
	now := time.Now().UTC()
	first := hourOf(now).Add(-10 * time.Hour)
	var items []AuditEventInsert
	for h := 0; h < 10; h++ {
		base := first.Add(time.Duration(h) * time.Hour)
		for i := 0; i < 6; i++ {
			ts := base.Add(time.Duration(i*9+1) * time.Minute)
			user := []string{"alice", "bob", "ci-bot"}[i%3]
			ip := fmt.Sprintf("10.1.%d.%d", h%3, i%4)
			rule := ""
			if i == 2 {
				rule = "r-secret"
			}
			items = append(items, rollupEvent(fmt.Sprintf("%s-%d-%d", cluster, h, i), user, ip, ts, i != 4, rule))
		}
	}
	items = append(items, rollupEvent(cluster+"-now", "alice", "10.9.9.9", now.Add(-time.Second), true, ""))
	if err := scope.InsertAuditEvents(ctx, items); err != nil {
		t.Fatal(err)
	}
	q := AuditEventQuery{From: first.Add(5 * time.Minute), To: now.Add(time.Minute)}
	dropRollupHours(t, ctx, st, cluster, first, hourOf(now))
	if _, ok := scope.rollupSpanFor(ctx, q); ok {
		t.Fatal("rollup span without built hours")
	}
	raw := viewOf(t, ctx, scope, q)
	if raw.total == 0 || len(raw.groups) != 3 {
		t.Fatalf("raw view %+v", raw)
	}

	buildRollupHours(t, ctx, st, cluster, first, hourOf(now))
	span, ok := scope.rollupSpanFor(ctx, q)
	if !ok || !span.start.Equal(first.Add(time.Hour)) || !span.end.Equal(hourOf(now)) {
		t.Fatalf("span %+v ok=%v", span, ok)
	}
	rolled := viewOf(t, ctx, scope, q)
	if !reflect.DeepEqual(raw, rolled) {
		t.Fatalf("rollup differs from raw\nraw    %+v\nrollup %+v", raw, rolled)
	}

	if _, ok := scope.rollupSpanFor(ctx, AuditEventQuery{From: q.From, To: q.To, Kind: "create"}); ok {
		t.Fatal("kind filter must read raw events")
	}
	filtered := q
	filtered.Result = auditrules.ResultDenied
	filtered.User = "a"
	dropRollupHours(t, ctx, st, cluster, first, hourOf(now))
	rawFiltered := viewOf(t, ctx, scope, filtered)
	buildRollupHours(t, ctx, st, cluster, first, hourOf(now))
	if got := viewOf(t, ctx, scope, filtered); !reflect.DeepEqual(rawFiltered, got) {
		t.Fatalf("filtered rollup differs\nraw    %+v\nrollup %+v", rawFiltered, got)
	}

	late := first.Add(3*time.Hour + 30*time.Minute)
	if err := scope.InsertAuditEvents(ctx, []AuditEventInsert{rollupEvent(cluster+"-late", "dave", "10.2.2.2", late, true, "")}); err != nil {
		t.Fatal(err)
	}
	if rollupBuilt(t, ctx, st, cluster, late) {
		t.Fatal("late insert left its hour marked as built")
	}
	buildRollupHours(t, ctx, st, cluster, late, late.Add(time.Minute))
	withLate := viewOf(t, ctx, scope, q)
	if withLate.total != raw.total+1 || len(withLate.groups) != 4 {
		t.Fatalf("late event not counted: %+v", withLate)
	}

	silence, err := scope.CreateAuditSilence(ctx, AuditSilence{User: "eve", Reason: "noise", CreatedBy: "admin"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	noisy := first.Add(5*time.Hour + 10*time.Minute)
	if err := scope.InsertAuditEvents(ctx, []AuditEventInsert{rollupEvent(cluster+"-eve", "eve", "10.3.3.3", noisy, true, "")}); err != nil {
		t.Fatal(err)
	}
	buildRollupHours(t, ctx, st, cluster, noisy, noisy.Add(time.Minute))
	if got := viewOf(t, ctx, scope, q); !reflect.DeepEqual(withLate, got) {
		t.Fatalf("silenced event leaked into rollups\nwant %+v\ngot  %+v", withLate, got)
	}
	if ok, err := scope.DeleteAuditSilence(ctx, silence.ID); err != nil || !ok {
		t.Fatalf("delete silence ok=%v err=%v", ok, err)
	}
	if rollupBuilt(t, ctx, st, cluster, noisy) {
		t.Fatal("unsilenced hour still marked as built")
	}
	buildRollupHours(t, ctx, st, cluster, noisy, noisy.Add(time.Minute))
	unsilenced := viewOf(t, ctx, scope, q)
	if unsilenced.total != withLate.total+1 || len(unsilenced.groups) != 5 {
		t.Fatalf("unsilenced event missing: %+v", unsilenced)
	}
	dropRollupHours(t, ctx, st, cluster, first, hourOf(now))
	if got := viewOf(t, ctx, scope, q); !reflect.DeepEqual(unsilenced, got) {
		t.Fatalf("raw view after unsilence differs\nrollup %+v\nraw    %+v", unsilenced, got)
	}
}

func TestAuditSourceIPPrefixFilter(t *testing.T) {
	ctx, _, st, cluster := silenceFixture(t)
	if ready, err := st.auditRollupsReady(ctx, st.pool); err != nil || !ready {
		t.Skip("database is not migrated to 0018")
	}
	scope := st.Cluster(cluster)
	now := time.Now().UTC()
	items := []AuditEventInsert{
		rollupEvent(cluster+"-a", "alice", "10.20.1.5", now.Add(-time.Minute), true, ""),
		rollupEvent(cluster+"-b", "bob", "10.21.1.5", now.Add(-time.Minute), true, ""),
		rollupEvent(cluster+"-c", "carol", "10.20.7.1", now.Add(-time.Minute), true, ""),
	}
	if err := scope.InsertAuditEvents(ctx, items); err != nil {
		t.Fatal(err)
	}
	rows, err := scope.QueryAuditEvents(ctx, AuditEventQuery{From: now.Add(-time.Hour), To: now.Add(time.Minute), SourceIP: "10.20.", Limit: 10})
	if err != nil || len(rows) != 2 {
		t.Fatalf("prefix rows %d err=%v", len(rows), err)
	}
}

func TestRollupMarksArePerCluster(t *testing.T) {
	ctx, pool, st, cluster := silenceFixture(t)
	if ready, err := st.auditRollupsReady(ctx, st.pool); err != nil || !ready {
		t.Skip("database is not migrated to 0020")
	}
	other := cluster + "-b"
	if err := st.EnsureCluster(ctx, other); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dropSilenceCluster(pool, other) })
	now := time.Now().UTC()
	h := hourOf(now).Add(-3 * time.Hour)
	buildRollupHours(t, ctx, st, cluster, h, h.Add(time.Minute))
	buildRollupHours(t, ctx, st, other, h, h.Add(time.Minute))
	if err := st.Cluster(cluster).InsertAuditEvents(ctx, []AuditEventInsert{rollupEvent(cluster+"-late", "dave", "", h.Add(10*time.Minute), true, "")}); err != nil {
		t.Fatal(err)
	}
	if rollupBuilt(t, ctx, st, cluster, h) || !rollupBuilt(t, ctx, st, other, h) {
		t.Fatal("a late event must invalidate only its own cluster's hour")
	}
	if !rollupBuildable(h, now) || rollupBuildable(hourOf(now), now) || rollupBuildable(hourOf(now).Add(-time.Hour), hourOf(now).Add(2*time.Minute)) {
		t.Fatal("only hours past the settle window can be built or invalidated")
	}
	pool.Exec(ctx, `DELETE FROM audit_rollup_marks WHERE cluster_id = ANY($1)`, []string{cluster, other})
}
