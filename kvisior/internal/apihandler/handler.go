package apihandler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/store"
)

type Handler struct {
	st *store.Store
}

func New(st *store.Store) *Handler {
	return &Handler{st: st}
}

func (h *Handler) Register(mux *http.ServeMux, wrap func(http.Handler) http.Handler) {
	reg := func(p string, fn http.HandlerFunc) { mux.Handle(p, wrap(fn)) }
	reg("/api/policies", h.handlePolicies)
	reg("/api/acks", h.handleAcks)
	reg("/api/alerts", h.handleAlerts)
}

func (h *Handler) handlePolicies(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		items, err := h.st.ListPolicies(r.Context())
		if err != nil {
			jsonErr(w, err, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"policies": items})

	case http.MethodPut:
		var body struct {
			Policies []json.RawMessage `json:"policies"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonErr(w, err, http.StatusBadRequest)
			return
		}
		ids := make([]string, 0, len(body.Policies))
		raws := make([][]byte, 0, len(body.Policies))
		for _, raw := range body.Policies {
			var id struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(raw, &id) == nil && id.ID != "" {
				ids = append(ids, id.ID)
				raws = append(raws, []byte(raw))
			}
		}
		if err := h.st.ReplacePolicies(r.Context(), ids, raws); err != nil {
			jsonErr(w, err, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "count": len(ids)})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleAcks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		items, err := h.st.ListAcks(r.Context())
		if err != nil {
			jsonErr(w, err, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"items": items})

	case http.MethodPost:
		var body struct {
			Key       string   `json:"key"`
			Type      string   `json:"type"`
			ExpiresAt *float64 `json:"expiresAt"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Key == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{"error": "key required"})
			return
		}
		if body.Type == "" {
			body.Type = "silent"
		}
		var exp *time.Time
		if body.ExpiresAt != nil {
			ms := int64(*body.ExpiresAt)
			t := time.Unix(ms/1000, (ms%1000)*int64(time.Millisecond))
			exp = &t
		}
		if err := h.st.UpsertAck(r.Context(), body.Key, body.Type, exp); err != nil {
			jsonErr(w, err, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true})

	case http.MethodDelete:
		key := r.URL.Query().Get("key")
		if key == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{"error": "key required"})
			return
		}
		if err := h.st.DeleteAck(r.Context(), key); err != nil {
			jsonErr(w, err, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleAlerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	out, lastID, err := h.st.QueryAlerts(r.Context(), since, limit)
	if err != nil {
		jsonErr(w, err, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"alerts": out,
		"lastId": strconv.FormatInt(lastID, 10),
	})
}

func jsonErr(w http.ResponseWriter, err error, code int) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
}
