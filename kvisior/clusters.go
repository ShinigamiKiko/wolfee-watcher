package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/wolfee-watcher/kvisior/internal/clusterctx"
	"github.com/wolfee-watcher/kvisior/internal/store"
)

func clustersHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			rows, err := st.ListClusters(r.Context())
			if err != nil {
				http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"clusters": rows,
				"local":    clusterctx.Local(),
			})
		case http.MethodPost:
			var body struct {
				ID          string `json:"id"`
				Name        string `json:"name"`
				Description string `json:"description"`
				Enabled     *bool  `json:"enabled"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
				return
			}
			if !store.ValidClusterID(body.ID) {
				http.Error(w, `{"error":"id must be lowercase alphanumeric with dashes, max 63 chars"}`,
					http.StatusBadRequest)
				return
			}
			enabled := true
			if body.Enabled != nil {
				enabled = *body.Enabled
			}
			if err := st.UpsertCluster(r.Context(), body.ID, body.Name, body.Description, enabled); err != nil {
				http.Error(w, `{"error":"write failed"}`, http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func clusterItemHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/clusters/"), "/")
		if id == "" {
			http.Error(w, `{"error":"cluster id required"}`, http.StatusBadRequest)
			return
		}
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := st.DeleteCluster(r.Context(), id); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
