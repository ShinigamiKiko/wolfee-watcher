package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

func (s *Server) handleAnomalies(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	sinceID, limit := parseAnomalyQuery(r)
	rows, err := s.pool.Query(r.Context(),
		`SELECT id, data FROM anomaly_events WHERE id > $1 AND silenced_at IS NULL ORDER BY id LIMIT $2`,
		sinceID, limit,
	)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	events, lastID := scanAnomalyEvents(rows)
	json.NewEncoder(w).Encode(map[string]any{
		"events":  events,
		"lastID":  lastID,
		"count":   len(events),
		"fetchAt": time.Now().UTC().Format(time.RFC3339),
	})
}

func parseAnomalyQuery(r *http.Request) (int64, int64) {
	sinceID, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	limit := int64(200)
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, _ := strconv.ParseInt(l, 10, 64); n > 0 && n <= 1000 {
			limit = n
		}
	}
	return sinceID, limit
}

func scanAnomalyEvents(rows interface {
	Next() bool
	Scan(dest ...any) error
}) ([]map[string]any, string) {
	events := []map[string]any{}
	var lastID string
	for rows.Next() {
		var id int64
		var data []byte
		if err := rows.Scan(&id, &data); err != nil {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal(data, &ev); err != nil {
			continue
		}
		idStr := strconv.FormatInt(id, 10)
		ev["id"] = idStr
		events = append(events, ev)
		lastID = idStr
	}
	return events, lastID
}

func (s *Server) handleAnomalyDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "POST or DELETE only", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSONError(w, http.StatusBadRequest, "id required")
		return
	}
	tag, err := s.pool.Exec(r.Context(), `DELETE FROM anomaly_events WHERE id = $1`, id)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"deleted": tag.RowsAffected()})
}

func (s *Server) handleAnomalyIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	var ev map[string]any
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	extID, _ := ev["id"].(string)
	if extID == "" {
		writeJSONError(w, http.StatusBadRequest, "id required")
		return
	}
	kind, _ := ev["kind"].(string)
	ts := time.Now()
	if raw, ok := ev["ts"].(string); ok {
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
			if t, err := time.Parse(layout, raw); err == nil {
				ts = t
				break
			}
		}
	}
	data, err := json.Marshal(ev)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "encode event")
		return
	}
	var id int64
	err = s.pool.QueryRow(r.Context(),
		`INSERT INTO anomaly_events (ts, kind, data, ext_id)
 VALUES ($1, $2, $3, $4)
 ON CONFLICT (ext_id) DO UPDATE SET data = EXCLUDED.data
 RETURNING id`,
		ts, kind, data, extID,
	).Scan(&id)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"id": strconv.FormatInt(id, 10)})
}

func (s *Server) handleAnomaliesSilent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, limit := parseAnomalyQuery(r)
	rows, err := s.pool.Query(r.Context(),
		`SELECT id, data FROM anomaly_events WHERE silenced_at IS NOT NULL ORDER BY silenced_at DESC LIMIT $1`,
		limit,
	)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	events, _ := scanAnomalyEvents(rows)
	json.NewEncoder(w).Encode(map[string]any{"events": events, "count": len(events)})
}

func (s *Server) handleAnomalySilence(w http.ResponseWriter, r *http.Request) {
	s.setEventSilenced(w, r, true)
}

func (s *Server) handleAnomalyUnsilence(w http.ResponseWriter, r *http.Request) {
	s.setEventSilenced(w, r, false)
}

func (s *Server) setEventSilenced(w http.ResponseWriter, r *http.Request, silence bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSONError(w, http.StatusBadRequest, "id required")
		return
	}
	query := `UPDATE anomaly_events SET silenced_at = NOW() WHERE id = $1 AND silenced_at IS NULL`
	if !silence {
		query = `UPDATE anomaly_events SET silenced_at = NULL WHERE id = $1`
	}
	tag, err := s.pool.Exec(r.Context(), query, id)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"updated": tag.RowsAffected()})
}

func (s *Server) handleSilents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		s.handleSilentsList(w, r)
	case http.MethodPost:
		if !s.requireAdmin(w, r) {
			return
		}
		s.handleSilentsUpsert(w, r)
	case http.MethodDelete:
		if !s.requireAdmin(w, r) {
			return
		}
		s.handleSilentsDelete(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSilentsList(w http.ResponseWriter, r *http.Request) {
	rows, err := s.pool.Query(r.Context(),
		`SELECT type, key, summary, created_at FROM anomaly_silents ORDER BY created_at DESC`)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var typ, key, summary string
		var createdAt time.Time
		if err := rows.Scan(&typ, &key, &summary, &createdAt); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"type":       typ,
			"key":        key,
			"summary":    summary,
			"created_at": createdAt.UTC().Format(time.RFC3339),
		})
	}
	json.NewEncoder(w).Encode(map[string]any{"items": out, "count": len(out)})
}

func (s *Server) handleSilentsUpsert(w http.ResponseWriter, r *http.Request) {
	var body struct{ Type, Key, Summary string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if body.Type != "ack" && body.Type != "fp" {
		writeJSONError(w, http.StatusBadRequest, "type must be ack|fp")
		return
	}
	if body.Key == "" {
		writeJSONError(w, http.StatusBadRequest, "key required")
		return
	}
	_, err := s.pool.Exec(r.Context(),
		`INSERT INTO anomaly_silents (type, key, summary)
 VALUES ($1, $2, $3)
 ON CONFLICT (type, key) DO UPDATE SET summary = EXCLUDED.summary`,
		body.Type, body.Key, body.Summary)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (s *Server) handleSilentsDelete(w http.ResponseWriter, r *http.Request) {
	typ := r.URL.Query().Get("type")
	key := r.URL.Query().Get("key")
	if typ == "" || key == "" {
		writeJSONError(w, http.StatusBadRequest, "type and key required")
		return
	}
	tag, err := s.pool.Exec(r.Context(), `DELETE FROM anomaly_silents WHERE type = $1 AND key = $2`, typ, key)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"deleted": tag.RowsAffected()})
}
