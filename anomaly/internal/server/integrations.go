package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/wolfee-watcher/anomaly-detector/internal/integrations"
	"github.com/wolfee-watcher/pkg/authz"
)

func (s *Server) handleIntegrations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	if !s.requirePerm(w, r, authz.PermIntegrationsRead) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	all := s.integ.All()
	out := make([]map[string]any, 0, len(all))
	for _, rec := range all {
		out = append(out, integrationResponse(rec))
	}
	json.NewEncoder(w).Encode(map[string]any{"items": out, "count": len(out)})
}

func integrationResponse(rec integrations.Record) map[string]any {
	return map[string]any{
		"kind":       rec.Kind,
		"enabled":    rec.Enabled,
		"config":     json.RawMessage(integrations.RedactedConfig(rec.Kind, rec.Config)),
		"updated_at": rec.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

func (s *Server) handleIntegrationItem(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/integrations/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "kind required", http.StatusBadRequest)
		return
	}
	kind := parts[0]
	if len(parts) == 2 && parts[1] == "test" {
		s.handleIntegrationTest(w, r, kind)
		return
	}
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		s.handleIntegrationUpsert(w, r, kind)
	case http.MethodDelete:
		s.handleIntegrationDelete(w, r, kind)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleIntegrationTest(w http.ResponseWriter, r *http.Request, kind string) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if !s.requirePerm(w, r, authz.PermIntegrationsWrite) {
		return
	}
	var payload struct {
		Config json.RawMessage `json:"config"`
	}
	if err := decodeJSONBody(r, &payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	merged, err := mergeSecrets(kind, payload.Config, s.integ)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.mgr.Test(ctx, kind, merged); err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (s *Server) handleIntegrationUpsert(w http.ResponseWriter, r *http.Request, kind string) {
	if !s.requirePerm(w, r, authz.PermIntegrationsWrite) {
		return
	}
	var payload struct {
		Enabled bool            `json:"enabled"`
		Config  json.RawMessage `json:"config"`
	}
	if err := decodeJSONBody(r, &payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	merged, err := mergeSecrets(kind, payload.Config, s.integ)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	rec, err := s.integ.Upsert(r.Context(), kind, payload.Enabled, merged)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	json.NewEncoder(w).Encode(integrationResponse(rec))
}

func (s *Server) handleIntegrationDelete(w http.ResponseWriter, r *http.Request, kind string) {
	if !s.requirePerm(w, r, authz.PermIntegrationsWrite) {
		return
	}
	if err := s.integ.Delete(r.Context(), kind); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func mergeSecrets(kind string, incoming json.RawMessage, store *integrations.Store) (json.RawMessage, error) {
	var in map[string]any
	if len(incoming) == 0 {
		in = map[string]any{}
	} else if err := json.Unmarshal(incoming, &in); err != nil {
		return nil, fmt.Errorf("invalid config json: %w", err)
	}
	prev, ok := store.Get(kind)
	if ok {
		var old map[string]any
		_ = json.Unmarshal(prev.Config, &old)
		for k, v := range in {
			if s, isStr := v.(string); isStr && s == "***" {
				if oldV, hadOld := old[k]; hadOld {
					in[k] = oldV
				} else {
					delete(in, k)
				}
			}
		}
	} else {
		for k, v := range in {
			if s, isStr := v.(string); isStr && s == "***" {
				delete(in, k)
			}
		}
	}
	out, _ := json.Marshal(in)
	return out, nil
}

func decodeJSONBody(r *http.Request, dst any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("invalid json")
	}
	return nil
}
