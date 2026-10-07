package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/wolfee-watcher/kvisior/internal/hub"
	"github.com/wolfee-watcher/kvisior/internal/store"
)

func TestPostureRunnerStoresCurrentFindings(t *testing.T) {
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
	if _, err := st.Cluster("x").Posture(ctx, "deploy"); err == store.ErrPostureUnavailable {
		t.Skip("database is not migrated to 0018")
	}
	cluster := fmt.Sprintf("posture-%d", time.Now().UnixNano())
	if err := st.EnsureCluster(ctx, cluster); err != nil {
		t.Fatal(err)
	}
	policyID := cluster + "-deploy"
	t.Cleanup(func() {
		for _, q := range []string{
			`DELETE FROM runtime_policies WHERE id = $1`,
			`DELETE FROM kvisior_violations WHERE cluster_id = $1`,
			`DELETE FROM posture_findings WHERE cluster_id = $1`,
			`DELETE FROM clusters WHERE id = $1`,
		} {
			arg := cluster
			if q == `DELETE FROM runtime_policies WHERE id = $1` {
				arg = policyID
			}
			pool.Exec(context.Background(), q, arg)
		}
	})
	policy, _ := json.Marshal(map[string]any{
		"id": policyID, "name": "no host network", "detType": "Deploy", "sev": "HIGH",
		"deployChecks": []string{"no-host-net"},
	})
	if _, err := pool.Exec(ctx, `INSERT INTO runtime_policies (id, data, updated_at) VALUES ($1, $2, NOW())`, policyID, policy); err != nil {
		t.Fatal(err)
	}
	h := hub.New(16)
	h.Publish(hub.Event{Cluster: cluster, Type: "sensor_snapshot", Data: json.RawMessage(`{"deployments": [
	  {"metadata": {"name": "edge", "namespace": "net"}, "spec": {"template": {"spec": {"hostNetwork": true, "containers": [{"name": "c", "image": "a:1"}]}}}},
	  {"metadata": {"name": "app", "namespace": "net"}, "spec": {"template": {"spec": {"containers": [{"name": "c", "image": "a:1"}]}}}}
	]}`)})

	r := &postureRunner{st: st, hub: h, seen: map[string]map[string]int64{}, saved: map[string]postureSave{}}
	r.tick(ctx)
	first, err := st.Cluster(cluster).Posture(ctx, "deploy")
	if err != nil || first.EvaluatedAt == nil || first.Count != 1 {
		t.Fatalf("posture %+v err=%v", first, err)
	}
	var findings []map[string]any
	if err := json.Unmarshal(first.Findings, &findings); err != nil || len(findings) != 1 {
		t.Fatalf("findings %s err=%v", first.Findings, err)
	}
	f := findings[0]
	if f["workload"] != "edge" || f["check"] != "no-host-net" || f["_policyId"] != policyID || f["_detectedAt"] == nil {
		t.Fatalf("finding %v", f)
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM kvisior_violations WHERE cluster_id = $1 AND vtype = 'deploy' AND fingerprint = $2`,
		cluster, f["_fp"]).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("violation rows %d err=%v", rows, err)
	}

	r2 := &postureRunner{st: st, hub: h, seen: map[string]map[string]int64{}, saved: map[string]postureSave{}}
	time.Sleep(5 * time.Millisecond)
	r2.tick(ctx)
	second, err := st.Cluster(cluster).Posture(ctx, "deploy")
	if err != nil || !second.EvaluatedAt.After(*first.EvaluatedAt) {
		t.Fatalf("second evaluation %+v err=%v", second, err)
	}
	var again []map[string]any
	json.Unmarshal(second.Findings, &again)
	if len(again) != 1 || again[0]["_detectedAt"] != f["_detectedAt"] {
		t.Fatalf("a restarted runner must keep the first detection time: %v then %v", f["_detectedAt"], again)
	}

	h.Publish(hub.Event{Cluster: cluster, Type: "sensor_snapshot", Data: json.RawMessage(`{"deployments": []}`)})
	r.tick(ctx)
	cleared, err := st.Cluster(cluster).Posture(ctx, "deploy")
	if err != nil || cleared.Count != 0 || string(cleared.Findings) != "[]" {
		t.Fatalf("resolved posture %+v err=%v", cleared, err)
	}
}
