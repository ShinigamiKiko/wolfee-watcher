package main

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/wolfee-watcher/kvisior/internal/store"
)

type scanSummaryAgg struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
	Total    int `json:"total"`
	Fixable  int `json:"fixable"`
	InKev    int `json:"inKev"`
	HasPoc   int `json:"hasPoc"`
}

func imageScansHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		rows, err := st.ListImageScans(r.Context())
		if err != nil {
			http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
			return
		}
		agg := scanSummaryAgg{}
		for _, raw := range rows {
			var lite struct {
				Summary scanSummaryAgg `json:"summary"`
			}
			if json.Unmarshal(raw, &lite) == nil {
				agg.Critical += lite.Summary.Critical
				agg.High += lite.Summary.High
				agg.Medium += lite.Summary.Medium
				agg.Low += lite.Summary.Low
				agg.Unknown += lite.Summary.Unknown
				agg.Total += lite.Summary.Total
				agg.Fixable += lite.Summary.Fixable
				agg.InKev += lite.Summary.InKev
				agg.HasPoc += lite.Summary.HasPoc
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"results": rows,
			"total":   len(rows),
			"summary": agg,
		})
	}
}

func auditRunsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		tool := r.URL.Query().Get("tool")
		if tool != "" && tool != "bench" && tool != "hunter" {
			http.Error(w, `{"error":"tool must be bench or hunter"}`, http.StatusBadRequest)
			return
		}
		limit := 50
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				limit = n
			}
		}
		rows, err := st.ListAuditRuns(r.Context(), tool, limit)
		if err != nil {
			http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"runs":  rows,
			"total": len(rows),
		})
	}
}

func imageHistoriesHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		rows, err := st.ListImageHistories(r.Context())
		if err != nil {
			http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"histories": rows,
			"total":     len(rows),
		})
	}
}
