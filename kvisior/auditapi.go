package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/auditengine"
	"github.com/wolfee-watcher/kvisior/internal/clusterctx"
	"github.com/wolfee-watcher/kvisior/internal/store"
	"github.com/wolfee-watcher/pkg/auditrules"
)

const auditRulesPath = "/api/audit/rules/"

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func newAuditRuleID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "custom-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return "custom-" + hex.EncodeToString(b)
}

func decodeAuditRule(r *http.Request) (auditrules.Rule, error) {
	var rule auditrules.Rule
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	if err := dec.Decode(&rule); err != nil {
		return rule, errors.New("invalid json")
	}
	return rule, nil
}

func reloadAuditRules(ctx context.Context, eng *auditengine.Engine) {
	if err := eng.Reload(ctx); err != nil {
		slog.Warn("audit_rules_reload_failed", "component", "kvisior/audit-api", "error", err)
	}
}

func auditRulesHandler(st *store.Store, eng *auditengine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			rules, err := st.ListAuditRules(r.Context())
			if err != nil {
				writeAPIError(w, http.StatusInternalServerError, "query failed")
				return
			}
			stats, err := st.Cluster(clusterctx.ForRead(r)).AuditRuleStats(r.Context())
			if err != nil {
				writeAPIError(w, http.StatusInternalServerError, "query failed")
				return
			}
			builtinMissing := 0
			present := map[string]bool{}
			for _, rule := range rules {
				present[rule.ID] = true
			}
			for _, b := range auditrules.BuiltinRules() {
				if !present[b.ID] {
					builtinMissing++
				}
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"rules": rules, "stats": stats, "builtinMissing": builtinMissing,
				"kinds": auditrules.Kinds, "severities": auditrules.Severities,
			})
		case http.MethodPost:
			rule, err := decodeAuditRule(r)
			if err != nil {
				writeAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			rule.ID = newAuditRuleID()
			rule.Origin = auditrules.OriginCustom
			rule.Group = "Custom"
			rule.UpdatedBy = r.Header.Get("X-Acting-User")
			rule.Normalize()
			if err := rule.Validate(); err != nil {
				writeAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			if err := st.CreateAuditRule(r.Context(), rule); err != nil {
				writeAPIError(w, http.StatusInternalServerError, "write failed")
				return
			}
			reloadAuditRules(r.Context(), eng)
			writeJSON(w, http.StatusCreated, rule)
		default:
			writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func auditRuleItemHandler(st *store.Store, eng *auditengine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.Trim(strings.TrimPrefix(r.URL.Path, auditRulesPath), "/")
		by := r.Header.Get("X-Acting-User")
		if id == "restore" {
			if r.Method != http.MethodPost {
				writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			n, err := st.RestoreBuiltinAuditRules(r.Context(), by)
			if err != nil {
				writeAPIError(w, http.StatusInternalServerError, "write failed")
				return
			}
			reloadAuditRules(r.Context(), eng)
			writeJSON(w, http.StatusOK, map[string]int{"restored": n})
			return
		}
		if id == "" || strings.Contains(id, "/") {
			writeAPIError(w, http.StatusNotFound, "rule not found")
			return
		}
		current, found, err := st.GetAuditRule(r.Context(), id)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "query failed")
			return
		}
		if !found {
			writeAPIError(w, http.StatusNotFound, "rule not found")
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, current)
		case http.MethodPut:
			rule, err := decodeAuditRule(r)
			if err != nil {
				writeAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			rule.ID, rule.Origin, rule.Group, rule.UpdatedBy = current.ID, current.Origin, current.Group, by
			rule.Normalize()
			if err := rule.Validate(); err != nil {
				writeAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			if _, err := st.UpdateAuditRule(r.Context(), rule); err != nil {
				writeAPIError(w, http.StatusInternalServerError, "write failed")
				return
			}
			reloadAuditRules(r.Context(), eng)
			writeJSON(w, http.StatusOK, rule)
		case http.MethodPatch:
			var flags struct {
				Enabled *bool `json:"enabled"`
				Alert   *bool `json:"alert"`
			}
			if json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&flags) != nil {
				writeAPIError(w, http.StatusBadRequest, "invalid json")
				return
			}
			if flags.Enabled != nil {
				current.Enabled = *flags.Enabled
			}
			if flags.Alert != nil {
				current.Alert = *flags.Alert
			}
			current.UpdatedBy = by
			if _, err := st.UpdateAuditRule(r.Context(), current); err != nil {
				writeAPIError(w, http.StatusInternalServerError, "write failed")
				return
			}
			reloadAuditRules(r.Context(), eng)
			writeJSON(w, http.StatusOK, current)
		case http.MethodDelete:
			if _, err := st.DeleteAuditRule(r.Context(), id); err != nil {
				writeAPIError(w, http.StatusInternalServerError, "write failed")
				return
			}
			reloadAuditRules(r.Context(), eng)
			w.WriteHeader(http.StatusNoContent)
		default:
			writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func auditQueryFromRequest(r *http.Request) store.AuditEventQuery {
	v := r.URL.Query()
	maxHours := int(store.AuditRetention().Hours())
	hours, _ := strconv.Atoi(v.Get("hours"))
	if hours <= 0 {
		hours = 24
	}
	if hours > maxHours {
		hours = maxHours
	}
	now := time.Now()
	q := store.AuditEventQuery{
		From:       now.Add(-time.Duration(hours) * time.Hour),
		To:         now,
		User:       strings.TrimSpace(v.Get("user")),
		Namespace:  strings.TrimSpace(v.Get("ns")),
		Kind:       strings.TrimSpace(v.Get("kind")),
		Resource:   strings.TrimSpace(v.Get("resource")),
		SourceIP:   strings.TrimSpace(v.Get("ip")),
		Result:     v.Get("result"),
		Search:     strings.TrimSpace(v.Get("q")),
		DangerOnly: v.Get("danger") == "1",
	}
	if v.Has("objResource") {
		q.Object = &store.AuditObject{
			Resource:  v.Get("objResource"),
			Namespace: v.Get("objNs"),
			Name:      v.Get("objName"),
		}
	}
	q.Limit, _ = strconv.Atoi(v.Get("limit"))
	if ms, err := strconv.ParseInt(v.Get("beforeTs"), 10, 64); err == nil && ms > 0 {
		q.BeforeTs = time.UnixMicro(ms)
		q.BeforeID, _ = strconv.ParseInt(v.Get("beforeId"), 10, 64)
	}
	return q
}

func auditQueryHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		q := auditQueryFromRequest(r)
		rows, err := st.Cluster(clusterctx.ForRead(r)).QueryAuditEvents(r.Context(), q)
		if err != nil {
			slog.Error("audit_query_failed", "component", "kvisior/audit-api", "error", err)
			writeAPIError(w, http.StatusInternalServerError, "query failed")
			return
		}
		out := map[string]interface{}{"events": rows}
		limit := q.Limit
		if limit <= 0 || limit > 500 {
			limit = 200
		}
		if len(rows) == limit {
			last := rows[len(rows)-1]
			out["next"] = map[string]int64{"beforeTs": last.Ts.UnixMicro(), "beforeId": last.ID}
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func auditSummaryHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		q := auditQueryFromRequest(r)
		buckets, _ := strconv.Atoi(r.URL.Query().Get("buckets"))
		rows, total, err := st.Cluster(clusterctx.ForRead(r)).AuditEventHistogram(r.Context(), q, buckets)
		if err != nil {
			slog.Error("audit_summary_failed", "component", "kvisior/audit-api", "error", err)
			writeAPIError(w, http.StatusInternalServerError, "query failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"buckets": rows, "total": total, "from": q.From, "to": q.To,
		})
	}
}

func auditGroupsHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		by := r.URL.Query().Get("by")
		if by != "object" {
			by = "user"
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		rows, err := st.Cluster(clusterctx.ForRead(r)).AuditEventGroups(r.Context(), auditQueryFromRequest(r), by, limit, offset)
		if err != nil {
			slog.Error("audit_groups_failed", "component", "kvisior/audit-api", "error", err)
			writeAPIError(w, http.StatusInternalServerError, "query failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"groups": rows, "by": by})
	}
}

func auditSourcesHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		src, err := st.Cluster(clusterctx.ForRead(r)).AuditSources(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "query failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"sources": src, "retentionHours": int(store.AuditRetention().Hours()),
		})
	}
}
