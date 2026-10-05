package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/wolfee-watcher/kvisior/internal/clusterctx"
	"github.com/wolfee-watcher/kvisior/internal/store"
)

const maxSpoolShedActors = 20

func auditSpoolStatusPush(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if st == nil {
			writeAPIError(w, http.StatusServiceUnavailable, "postgresql not configured")
			return
		}
		var body store.AuditSpoolStatus
		if json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&body) != nil || !auditLogNodeRe.MatchString(body.Pod) {
			writeAPIError(w, http.StatusBadRequest, "invalid status")
			return
		}
		body.LastError = clip(body.LastError, 300)
		actors := map[string]int64{}
		for actor, n := range body.ShedActors {
			if len(actors) == maxSpoolShedActors {
				break
			}
			actors[clip(actor, 128)] = max(n, 0)
		}
		body.ShedActors = actors
		cluster := clusterctx.ForPush(r)
		st.EnsureClusterCached(cluster)
		alert, err := st.Cluster(cluster).RecordAuditSpool(r.Context(), body)
		if err != nil {
			slog.Error("audit_spool_status_write_failed", "component", "kvisior/audit-api", "error", err)
			writeAPIError(w, http.StatusInternalServerError, "write failed")
			return
		}
		if alert != nil {
			slog.Warn("audit_delivery_alert", "component", "kvisior/audit-api", "cluster", cluster, "rule", alert.RuleID, "detail", alert.Detail)
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
