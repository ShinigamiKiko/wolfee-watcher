package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/clusterctx"
	"github.com/wolfee-watcher/kvisior/internal/hub"
	"github.com/wolfee-watcher/kvisior/internal/posture"
	"github.com/wolfee-watcher/kvisior/internal/store"
)

const (
	postureInterval     = time.Minute
	postureRefreshEvery = 5 * time.Minute
)

type postureFinding struct {
	posture.Finding
	DetectedAt int64 `json:"_detectedAt"`
}

type postureSave struct {
	sum [sha256.Size]byte
	at  time.Time
}

type postureRunner struct {
	st    *store.Store
	hub   *hub.Hub
	seen  map[string]map[string]int64
	saved map[string]postureSave
}

func runPosture(ctx context.Context, st *store.Store, h *hub.Hub) {
	r := &postureRunner{st: st, hub: h, seen: map[string]map[string]int64{}, saved: map[string]postureSave{}}
	t := time.NewTicker(postureInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.tick(ctx)
		}
	}
}

func (r *postureRunner) tick(ctx context.Context) {
	snaps := r.hub.Latest("sensor_snapshot")
	if len(snaps) == 0 {
		return
	}
	raw, err := r.st.ListPolicies(ctx)
	if err != nil {
		slog.Warn("posture_policies_failed", "component", "kvisior/posture", "error", err)
		return
	}
	policies := make([]posture.Policy, 0, len(raw))
	for _, blob := range raw {
		var p posture.Policy
		if json.Unmarshal(blob, &p) == nil && (p.DetType == "Build" || p.DetType == "Deploy") {
			policies = append(policies, p)
		}
	}
	for _, ev := range snaps {
		cluster := ev.Cluster
		if cluster == "" {
			cluster = store.DefaultCluster
		}
		if err := r.evaluate(ctx, cluster, ev.Data, policies); err != nil && ctx.Err() == nil {
			slog.Warn("posture_evaluation_failed", "component", "kvisior/posture", "cluster", cluster, "error", err)
		}
	}
}

func (r *postureRunner) evaluate(ctx context.Context, cluster string, data json.RawMessage, policies []posture.Policy) error {
	snap, err := posture.ParseSnapshot(data)
	if err != nil {
		return err
	}
	scope := r.st.Cluster(cluster)
	blobs, err := scope.ListImageHistories(ctx)
	if err != nil {
		return err
	}
	histories := make([]posture.History, 0, len(blobs))
	for _, b := range blobs {
		var h posture.History
		if json.Unmarshal(b, &h) == nil && h.Image != "" {
			histories = append(histories, h)
		}
	}
	now := time.Now()
	ev := posture.Evaluator{Cluster: cluster, Now: now}
	findings := map[string][]posture.Finding{
		"build":  ev.Build(policies, snap, histories),
		"deploy": ev.Deploy(policies, snap),
	}

	prev := r.seen[cluster]
	next := map[string]int64{}
	var fresh []string
	byFP := map[string]posture.Finding{}
	for _, list := range findings {
		for _, f := range list {
			if at, ok := prev[f.Fingerprint]; ok {
				next[f.Fingerprint] = at
				continue
			}
			fresh = append(fresh, f.Fingerprint)
			byFP[f.Fingerprint] = f
		}
	}
	known, err := scope.ViolationFirstSeen(ctx, fresh)
	if err != nil {
		return err
	}
	var writes []store.ViolationWrite
	var written []string
	for _, fp := range fresh {
		if ts, ok := known[fp]; ok {
			next[fp] = ts.UnixMilli()
			continue
		}
		f := byFP[fp]
		payload, _ := json.Marshal(postureFinding{Finding: f, DetectedAt: now.UnixMilli()})
		writes = append(writes, store.ViolationWrite{VType: f.VType, RuleID: f.PolicyID, RuleName: f.Policy, Sev: f.Sev,
			NS: f.Scope(), Pod: f.Subject(), Fingerprint: fp, Data: payload})
		written = append(written, fp)
	}
	if err := scope.WriteViolations(ctx, writes); err != nil {
		return err
	}
	stored, err := scope.ViolationFirstSeen(ctx, written)
	if err != nil {
		return err
	}
	for _, fp := range written {
		if ts, ok := stored[fp]; ok {
			next[fp] = ts.UnixMilli()
		} else {
			next[fp] = now.UnixMilli()
		}
	}
	r.seen[cluster] = next

	for vtype, list := range findings {
		out := make([]postureFinding, 0, min(len(list), store.PostureFindingsMax))
		for _, f := range list {
			if len(out) == store.PostureFindingsMax {
				break
			}
			out = append(out, postureFinding{Finding: f, DetectedAt: next[f.Fingerprint]})
		}
		payload, err := json.Marshal(out)
		if err != nil {
			return err
		}
		key := cluster + "/" + vtype
		sum := sha256.Sum256(payload)
		if last, ok := r.saved[key]; ok && last.sum == sum && now.Sub(last.at) < postureRefreshEvery {
			continue
		}
		if err := scope.SavePosture(ctx, vtype, now, len(list), payload); err != nil {
			return err
		}
		r.saved[key] = postureSave{sum: sum, at: now}
	}
	return nil
}

func postureHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		vtype := r.URL.Query().Get("type")
		if vtype != "build" && vtype != "deploy" {
			writeAPIError(w, http.StatusBadRequest, "type must be build or deploy")
			return
		}
		state, err := st.Cluster(clusterctx.ForRead(r)).Posture(r.Context(), vtype)
		if errors.Is(err, store.ErrPostureUnavailable) {
			writeJSON(w, http.StatusOK, map[string]any{"unavailable": true, "findings": []any{}})
			return
		}
		if err != nil {
			slog.Error("posture_query_failed", "component", "kvisior/posture", "error", err)
			writeAPIError(w, http.StatusInternalServerError, "query failed")
			return
		}
		writeJSON(w, http.StatusOK, state)
	}
}
