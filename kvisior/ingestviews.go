package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/wolfee-watcher/kvisior/internal/store"
)

func auditEventsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		since := r.URL.Query().Get("since")
		if since == "" {
			since = "0"
		}
		events, lastID, err := st.QueryAuditEventsSince(r.Context(), since, 200)
		if err != nil {
			http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"events": events,
			"lastId": lastID,
		})
	}
}

func forensicDiffHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/sensor/api/forensic/diff/"), "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			http.Error(w, `{"error":"use /sensor/api/forensic/diff/{ns}/{pod}"}`, http.StatusBadRequest)
			return
		}
		ns, pod := parts[0], parts[1]
		entries, err := st.QueryForensicEvents(r.Context(), ns, pod)
		if err != nil {
			http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ns":      ns,
			"pod":     pod,
			"count":   len(entries),
			"entries": entries,
		})
	}
}
