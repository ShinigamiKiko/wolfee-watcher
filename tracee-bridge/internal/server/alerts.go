package server

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
)

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	pool := s.hub.Pool()
	if pool == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]any{"error": "postgres not configured"})
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 200
	}

	const colList = `id, ts, source, det_type, COALESCE(rule_id, ''), COALESCE(rule_name, ''),
		       COALESCE(severity, ''), COALESCE(namespace, ''), COALESCE(target, ''),
		       COALESCE(syscall, ''), COALESCE(detail, ''), COALESCE(fingerprint, ''),
		       delivered_at`
	var (
		rows pgx.Rows
		err  error
	)
	if since == 0 {
		rows, err = pool.Query(r.Context(),
			`SELECT * FROM (
			    SELECT `+colList+`
			    FROM alerts
			    ORDER BY id DESC
			    LIMIT $1
			 ) recent
			 ORDER BY id`, limit)
	} else {
		rows, err = pool.Query(r.Context(),
			`SELECT `+colList+`
			 FROM alerts
			 WHERE id > $1
			 ORDER BY id
			 LIMIT $2`, since, limit)
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
		return
	}
	defer rows.Close()

	type alertOut struct {
		ID          int64   `json:"id"`
		Ts          string  `json:"ts"`
		Source      string  `json:"source"`
		DetType     string  `json:"detType"`
		RuleID      string  `json:"ruleId"`
		RuleName    string  `json:"ruleName"`
		Severity    string  `json:"severity,omitempty"`
		Namespace   string  `json:"namespace,omitempty"`
		Target      string  `json:"target,omitempty"`
		Syscall     string  `json:"syscall,omitempty"`
		Detail      string  `json:"detail,omitempty"`
		Fingerprint string  `json:"fingerprint,omitempty"`
		DeliveredAt *string `json:"deliveredAt,omitempty"`
	}

	out := []alertOut{}
	var lastID int64
	for rows.Next() {
		var a alertOut
		var ts string
		var deliveredAt *string
		if err := rows.Scan(&a.ID, &ts, &a.Source, &a.DetType, &a.RuleID, &a.RuleName,
			&a.Severity, &a.Namespace, &a.Target, &a.Syscall, &a.Detail, &a.Fingerprint, &deliveredAt); err != nil {
			continue
		}
		a.Ts = ts
		a.DeliveredAt = deliveredAt
		out = append(out, a)
		lastID = a.ID
	}
	if lastID == 0 {
		lastID = since
	}
	json.NewEncoder(w).Encode(map[string]any{"alerts": out, "lastId": strconv.FormatInt(lastID, 10)})
}
