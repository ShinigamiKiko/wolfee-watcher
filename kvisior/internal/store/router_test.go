package store

import (
	"context"
	"strings"
	"testing"
)

func TestParseClusterDatabases(t *testing.T) {
	got, err := ParseClusterDatabases(strings.NewReader(`
# comment
k8s-a postgres://ww_ui:x@10.0.0.5:5432/wolfee?sslmode=disable

k8s-b   postgres://ww_ui:y@db-b:5433/wolfee
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["k8s-a"] == "" || got["k8s-b"] != "postgres://ww_ui:y@db-b:5433/wolfee" {
		t.Fatalf("unexpected routes %v", got)
	}
	for _, bad := range []string{
		"k8s-a",
		"K8S postgres://u@h/db",
		"default postgres://u@h/db",
		"k8s-a postgres://u@h/db\nk8s-a postgres://u@h/db2",
		"k8s-a postgres://u:secret@h:notaport/db",
	} {
		_, err := ParseClusterDatabases(strings.NewReader(bad))
		if err == nil {
			t.Fatalf("accepted %q", bad)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatalf("error leaks the DSN: %v", err)
		}
	}
}

func TestRouterRoutesOnlyListedClusters(t *testing.T) {
	ctx := context.Background()
	hub := &Store{}
	r := NewRouter()
	hub.SetRouter(r)
	defer r.Close()

	added, removed, err := r.Apply(ctx, map[string]string{
		"k8s-a": "postgres://u:p@127.0.0.1:1/a?sslmode=disable",
		"k8s-b": "postgres://u:p@127.0.0.1:1/b?sslmode=disable",
	})
	if err != nil || len(added) != 2 || len(removed) != 0 {
		t.Fatalf("apply: added=%v removed=%v err=%v", added, removed, err)
	}
	a := hub.Cluster("k8s-a")
	if a.s == hub || a.s != hub.Cluster("k8s-a").s {
		t.Fatal("k8s-a is not routed to a stable store of its own")
	}
	if hub.Cluster("k8s-b").s == a.s {
		t.Fatal("two clusters share one routed store")
	}
	if hub.Cluster("k8s-c").s != hub || hub.Cluster("").s != hub {
		t.Fatal("an unlisted cluster left the hub database")
	}

	before := a.s
	added, removed, err = r.Apply(ctx, map[string]string{
		"k8s-a": "postgres://u:p@127.0.0.1:1/a?sslmode=disable",
	})
	if err != nil || len(added) != 0 || len(removed) != 1 || removed[0] != "k8s-b" {
		t.Fatalf("shrink: added=%v removed=%v err=%v", added, removed, err)
	}
	if hub.Cluster("k8s-a").s != before {
		t.Fatal("an unchanged route was reopened")
	}
	if hub.Cluster("k8s-b").s != hub {
		t.Fatal("a removed route still leaves the hub database")
	}

	added, _, err = r.Apply(ctx, map[string]string{
		"k8s-a": "postgres://u:p@127.0.0.1:2/a?sslmode=disable",
	})
	if err != nil || len(added) != 1 || hub.Cluster("k8s-a").s == before {
		t.Fatalf("a changed DSN was not reopened: added=%v err=%v", added, err)
	}
	if got := r.Clusters(); len(got) != 1 || got[0] != "k8s-a" {
		t.Fatalf("clusters %v", got)
	}
}

func TestUnroutedStoreIsItself(t *testing.T) {
	st := &Store{}
	if st.Cluster("k8s-a").s != st || st.Routed("k8s-a") {
		t.Fatal("a store without a router must keep every cluster local")
	}
}
