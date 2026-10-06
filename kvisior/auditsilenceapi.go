package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/clusterctx"
	"github.com/wolfee-watcher/kvisior/internal/store"
)

const (
	auditSilencesPath   = "/api/audit/silences"
	auditSilenceBodyMax = 16 << 10
)

func auditSilencesHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope := st.Cluster(clusterctx.ForRead(r))
		switch r.Method {
		case http.MethodGet:
			items, err := scope.ListAuditSilences(r.Context())
			if err != nil {
				writeAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"silences": items})
		case http.MethodPost:
			var body struct {
				Action   string `json:"action"`
				Object   string `json:"object"`
				User     string `json:"user"`
				SourceIP string `json:"sourceIP"`
				Reason   string `json:"reason"`
				Minutes  int64  `json:"minutes"`
			}
			r.Body = http.MaxBytesReader(w, r.Body, auditSilenceBodyMax)
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeAPIError(w, http.StatusBadRequest, "request body is not valid JSON")
				return
			}
			if body.Minutes < 0 || body.Minutes > int64(store.AuditSilenceMaxDuration/time.Minute) {
				writeAPIError(w, http.StatusBadRequest, "minutes must be between 0 (until removed) and 129600 (90 days)")
				return
			}
			silence, err := scope.CreateAuditSilence(r.Context(), store.AuditSilence{
				Action: body.Action, Object: body.Object, User: body.User, SourceIP: body.SourceIP,
				Reason: body.Reason, CreatedBy: r.Header.Get("X-Acting-User"),
			}, time.Duration(body.Minutes)*time.Minute)
			if errors.Is(err, store.ErrAuditSilenceInvalid) {
				writeAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			if err != nil {
				writeAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusCreated, silence)
		default:
			writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func auditSilenceItemHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, auditSilencesPath+"/"), "/"), "/")
		id, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil || id <= 0 || len(parts) > 2 || (len(parts) == 2 && parts[1] != "end") {
			writeAPIError(w, http.StatusNotFound, "not found")
			return
		}
		scope := st.Cluster(clusterctx.ForRead(r))
		var found bool
		switch {
		case len(parts) == 2 && r.Method == http.MethodPost:
			found, err = scope.EndAuditSilence(r.Context(), id)
		case len(parts) == 1 && r.Method == http.MethodDelete:
			found, err = scope.DeleteAuditSilence(r.Context(), id)
		default:
			writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !found {
			writeAPIError(w, http.StatusNotFound, "silence not found")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func auditSilencedEventsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		q := r.URL.Query()
		silence, _ := strconv.ParseInt(q.Get("silence"), 10, 64)
		before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
		limit, _ := strconv.Atoi(q.Get("limit"))
		items, err := st.Cluster(clusterctx.ForRead(r)).ListSilencedEvents(r.Context(), silence, before, limit)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"events": items})
	}
}
