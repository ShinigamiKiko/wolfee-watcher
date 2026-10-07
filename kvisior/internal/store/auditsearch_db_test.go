package store

import (
	"fmt"
	"slices"
	"testing"
	"time"
)

func TestAuditWindowsCoverTheRangeNewestFirst(t *testing.T) {
	to := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	from := to.Add(-14 * 24 * time.Hour)
	w := auditWindows(AuditEventQuery{From: from, To: to})
	if len(w) < 3 || !w[0][1].Equal(to) || !w[len(w)-1][0].Equal(from) || w[0][1].Sub(w[0][0]) != auditWindowFirst {
		t.Fatalf("windows %v", w)
	}
	for i := 1; i < len(w); i++ {
		if !w[i][1].Equal(w[i-1][0].Add(-time.Microsecond)) {
			t.Fatalf("gap or overlap between %v and %v", w[i-1], w[i])
		}
	}
	if got := auditWindows(AuditEventQuery{From: to.Add(-6 * time.Hour), To: to}); len(got) != 1 {
		t.Fatalf("a short range must stay one query: %v", got)
	}
	cursor := to.Add(-48 * time.Hour)
	if got := auditWindows(AuditEventQuery{From: from, To: to, BeforeTs: cursor}); !got[0][1].Equal(cursor) {
		t.Fatalf("paging must start at the cursor: %v", got[0])
	}
}

func TestInvestigationSearchUsesWindowsAndKnownUsers(t *testing.T) {
	ctx, _, st, cluster := silenceFixture(t)
	if ready, err := st.auditRollupsReady(ctx, st.pool); err != nil || !ready {
		t.Skip("database is not migrated to 0018")
	}
	known := auditRetentionKnown.Load()
	auditRetentionKnown.Store(true)
	err := st.MaintainPartitions(ctx)
	auditRetentionKnown.Store(known)
	if err != nil {
		t.Fatal(err)
	}
	scope := st.Cluster(cluster)
	now := time.Now().UTC()
	var items []AuditEventInsert
	for i, age := range []time.Duration{2 * time.Hour, 20 * time.Hour, 50 * time.Hour, 90 * time.Hour, 100 * time.Hour} {
		user := []string{"oidc:alice@corp", "bob", "oidc:alice@corp", "carol", "oidc:alice@corp"}[i]
		ev := rollupEvent(fmt.Sprintf("%s-w%d", cluster, i), user, "10.4.0.1", now.Add(-age), true, "")
		ev.Event.Resource = []string{"secrets", "pods", "secrets", "configmaps", "secrets"}[i]
		items = append(items, ev)
	}
	if err := scope.InsertAuditEvents(ctx, items); err != nil {
		t.Fatal(err)
	}
	names := func(q AuditEventQuery) []string {
		rows, err := scope.QueryAuditEvents(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		out := []string{}
		for _, r := range rows {
			out = append(out, fmt.Sprint(r.Ts.Round(time.Hour).Sub(now.Round(time.Hour)).Hours()))
		}
		return out
	}
	base := AuditEventQuery{From: now.Add(-7 * 24 * time.Hour), To: now.Add(time.Minute), Limit: 10}
	buildRollupHours(t, ctx, st, cluster, base.From, hourOf(now).Add(-time.Hour))

	all := names(base)
	if !slices.Equal(all, []string{"-2", "-20", "-50", "-90", "-100"}) {
		t.Fatalf("newest first across windows: %v", all)
	}
	page := base
	page.Limit = 2
	first, err := scope.QueryAuditEvents(ctx, page)
	if err != nil || len(first) != 2 {
		t.Fatalf("first page %d err=%v", len(first), err)
	}
	page.BeforeTs, page.BeforeID = first[1].Ts, first[1].ID
	if got := names(page); !slices.Equal(got, []string{"-50", "-90"}) {
		t.Fatalf("second page %v", got)
	}

	alice := base
	alice.User = "ALICE"
	if got := names(alice); !slices.Equal(got, []string{"-2", "-50", "-100"}) {
		t.Fatalf("user substring %v", got)
	}
	users, ok, err := scope.resolveAuditUsers(ctx, alice)
	if err != nil || !ok || !slices.Equal(users, []string{"oidc:alice@corp"}) {
		t.Fatalf("resolved users %v ok=%v err=%v", users, ok, err)
	}
	nobody := base
	nobody.User = "mallory"
	if got := names(nobody); len(got) != 0 {
		t.Fatalf("unknown user %v", got)
	}
	secrets := base
	secrets.Resource = "Secr"
	if got := names(secrets); !slices.Equal(got, []string{"-2", "-50", "-100"}) {
		t.Fatalf("resource prefix %v", got)
	}
}
