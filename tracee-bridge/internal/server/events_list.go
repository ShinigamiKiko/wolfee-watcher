package server

import (
	"encoding/json"
	"net/http"
)

func (s *Server) handleEventsList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"events": []any{},
		"lastId": "0",
	})
}
