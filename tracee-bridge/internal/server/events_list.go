package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
)

func (s *Server) handleEventsList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limit := int64(1000)
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			limit = n
		}
	}

	events, lastID := s.hub.RecentEvents(limit)

	var buf bytes.Buffer
	buf.WriteString(`{"events":[`)
	for i, raw := range events {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(raw)
	}
	buf.WriteString(`],"lastId":`)
	idJSON, err := json.Marshal(lastID)
	if err != nil {
		http.Error(w, "encode failed", http.StatusInternalServerError)
		return
	}
	buf.Write(idJSON)
	buf.WriteString(`,"count":`)
	buf.WriteString(strconv.Itoa(len(events)))
	buf.WriteString(`}`)

	w.Write(buf.Bytes())
}
