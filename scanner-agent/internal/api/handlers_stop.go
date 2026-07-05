package api

import (
	"encoding/json"
	"net/http"
)

func (s *Server) handleScanStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	stopped := s.stopScan()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"stopped": stopped})
}
