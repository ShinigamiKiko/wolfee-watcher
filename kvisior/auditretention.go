package main

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/wolfee-watcher/kvisior/internal/store"
)

func auditRetentionHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			setting, err := st.AuditRetentionSetting(r.Context())
			if err != nil {
				slog.Error("audit_retention_query_failed", "component", "kvisior/audit-api", "error", err)
				writeAPIError(w, http.StatusInternalServerError, "query failed")
				return
			}
			writeJSON(w, http.StatusOK, setting)
		case http.MethodPut:
			var body struct {
				Hours int `json:"hours"`
			}
			if json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&body) != nil {
				writeAPIError(w, http.StatusBadRequest, "invalid json")
				return
			}
			setting, err := st.UpdateAuditRetention(r.Context(), body.Hours, r.Header.Get("X-Acting-User"))
			switch {
			case errors.Is(err, store.ErrAuditRetentionReadOnly):
				writeAPIError(w, http.StatusConflict, err.Error())
			case errors.Is(err, store.ErrAuditRetentionInvalid):
				writeAPIError(w, http.StatusBadRequest, err.Error())
			case err != nil:
				slog.Error("audit_retention_save_failed", "component", "kvisior/audit-api", "error", err)
				writeAPIError(w, http.StatusInternalServerError, "write failed")
			default:
				slog.Info("audit_retention_updated", "component", "kvisior/audit-api", "hours", setting.Hours, "by", setting.UpdatedBy)
				writeJSON(w, http.StatusOK, setting)
			}
		default:
			writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}
