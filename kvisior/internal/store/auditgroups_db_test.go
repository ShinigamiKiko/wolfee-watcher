package store

import (
	"fmt"
	"testing"
	"time"
)

func TestAuditGroupsPageWithOffset(t *testing.T) {
	ctx, _, st, cluster := silenceFixture(t)
	scope := st.Cluster(cluster)
	items := []AuditEventInsert{}
	for u := 0; u < 5; u++ {
		for n := 0; n <= u; n++ {
			items = append(items, silenceEvent(fmt.Sprintf("g-%d-%d", u, n), fmt.Sprintf("obj-%d", n), fmt.Sprintf("user-%d", u)))
		}
	}
	items = append(items, silenceEvent("tie-a", "x", "tie-a"), silenceEvent("tie-b", "x", "tie-b"))
	if err := scope.InsertAuditEvents(ctx, items); err != nil {
		t.Fatal(err)
	}
	q := AuditEventQuery{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour)}
	seen := map[string]bool{}
	var order []string
	for offset := 0; ; offset += 2 {
		page, err := scope.AuditEventGroups(ctx, q, "user", 2, offset)
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range page {
			if seen[g.Key] {
				t.Fatalf("group %s returned twice", g.Key)
			}
			seen[g.Key] = true
			order = append(order, fmt.Sprintf("%s=%d", g.Key, g.Events))
		}
		if len(page) < 2 {
			break
		}
	}
	want := "[user-4=5 user-3=4 user-2=3 user-1=2 tie-a=1 tie-b=1 user-0=1]"
	if got := fmt.Sprint(order); got != want {
		t.Fatalf("paged groups %s, want %s", got, want)
	}
	if _, err := scope.AuditEventGroups(ctx, q, "user", AuditGroupsPageMax, 0); err != nil {
		t.Fatal(err)
	}
}
