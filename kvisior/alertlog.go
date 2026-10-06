package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/clusterctx"
	"github.com/wolfee-watcher/kvisior/internal/store"
	alertspkg "github.com/wolfee-watcher/pkg/alerts"
)

type alertLogReq = alertspkg.AlertLog

func makeAlertLogHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handleAlertLog(st, w, r)
	}
}

func handleAlertLog(st *store.Store, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	var wrapper struct {
		Alerts []alertLogReq `json:"alerts"`
	}
	alerts := wrapper.Alerts
	if err := json.Unmarshal(body, &wrapper); err != nil || len(wrapper.Alerts) == 0 {
		var single alertLogReq
		if err := json.Unmarshal(body, &single); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		alerts = []alertLogReq{single}
	} else {
		alerts = wrapper.Alerts
	}

	cl := clusterctx.ForPush(r)
	if cl == "" {
		cl = store.DefaultCluster
	}
	name := st.ClusterDisplayName(r.Context(), cl)
	persist := make([]store.IncomingAlert, 0, len(alerts))
	for _, req := range alerts {
		// Identity belongs to the authenticated push context, never the JSON body.
		req.ID = 0
		if req.Timestamp.IsZero() {
			req.Timestamp = time.Now().UTC()
		}
		req.ClusterID, req.ClusterName = cl, name
		logAlert(req)
		if req.Persist {
			persist = append(persist, store.IncomingAlert{
				Timestamp: req.Timestamp,
				Source:    req.Source, DetType: req.DetType,
				RuleID: req.RuleID, RuleName: req.RuleName, Severity: req.Severity,
				Namespace: req.Namespace, Target: req.Target, Syscall: req.Syscall,
				Detail: req.Detail, Fingerprint: req.Fingerprint, Data: req.Data,
			})
		}
	}
	if len(persist) > 0 {
		if st == nil {
			log.Printf("[alert-log] persist requested for %d alert(s) but postgres not configured — not stored", len(persist))
		} else {
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()
			st.EnsureClusterCached(cl)
			if err := st.Cluster(cl).InsertAlerts(ctx, persist); err != nil {
				log.Printf("[alert-log] persist %d alert(s): %v", len(persist), err)
				http.Error(w, `{"error":"persist failed"}`, http.StatusInternalServerError)
				return
			}
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func logAlert(req alertLogReq) {
	alertspkg.LogSecurityAlert(context.Background(), "kvisior/alert-log", req)
}
