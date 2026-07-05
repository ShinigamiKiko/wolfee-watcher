package auth

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/accounts"
	"github.com/wolfee-watcher/pkg/authz"
)

func (m *Manager) StartSessionPurge(ctx context.Context) {
	if m.store == nil {
		return
	}
	go func() {
		t := time.NewTicker(15 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := m.store.PurgeExpiredSessions(ctx); err != nil {
					log.Printf("[auth] purge sessions: %v", err)
				}
			}
		}
	}()
}

func callerUsername(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Acting-User"))
}

func callerRole(r *http.Request) string {
	if role := strings.TrimSpace(r.Header.Get("X-Acting-Role")); authz.ValidRole(role) {
		return role
	}
	return authz.RoleRO
}

func (m *Manager) requirePerm(w http.ResponseWriter, r *http.Request, perm string) bool {
	if authz.Permissions(callerRole(r))[perm] {
		return true
	}
	writeError(w, http.StatusForbidden, "permission denied: "+perm)
	return false
}

func (m *Manager) backendReady(w http.ResponseWriter) bool {
	if m.store == nil {
		writeError(w, http.StatusServiceUnavailable, errNoBackend.Error())
		return false
	}
	return true
}

func resourcePathID(path, prefix string) string {
	rest := strings.TrimPrefix(path, prefix)
	rest = strings.TrimSuffix(rest, "/")
	if i := strings.Index(rest, "/"); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

func (m *Manager) HandleChangePassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !m.backendReady(w) {
		return
	}
	var body struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}

	if err := accounts.ValidatePassword(body.New); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := m.store.ChangePassword(r.Context(), callerUsername(r), body.Current, body.New); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (m *Manager) HandleGroups(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !m.backendReady(w) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !m.requirePerm(w, r, authz.PermGroupsRead) {
			return
		}
		items, err := m.store.ListGroups(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"items": items, "count": len(items)})
	case http.MethodPost:
		if !m.requirePerm(w, r, authz.PermGroupsCreate) {
			return
		}
		var body struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Role        string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		g, err := m.store.CreateGroup(r.Context(), body.Name, body.Description, body.Role)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		json.NewEncoder(w).Encode(g)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (m *Manager) HandleGroupItem(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !m.backendReady(w) {
		return
	}
	id := resourcePathID(r.URL.Path, "/api/groups/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id required")
		return
	}
	switch r.Method {
	case http.MethodPut:
		if !m.requirePerm(w, r, authz.PermGroupsWrite) {
			return
		}
		var body struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Role        string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		g, err := m.store.UpdateGroup(r.Context(), id, body.Name, body.Description, body.Role)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		json.NewEncoder(w).Encode(g)
	case http.MethodDelete:
		if !m.requirePerm(w, r, authz.PermGroupsDelete) {
			return
		}
		if err := m.store.DeleteGroup(r.Context(), id); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (m *Manager) HandleUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !m.backendReady(w) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !m.requirePerm(w, r, authz.PermUsersRead) {
			return
		}
		items, err := m.store.ListUsers(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"items": items, "count": len(items)})
	case http.MethodPost:
		if !m.requirePerm(w, r, authz.PermUsersCreate) {
			return
		}
		var body struct {
			Username string `json:"username"`
			Email    string `json:"email"`
			FullName string `json:"full_name"`
			GroupID  string `json:"group_id"`
			Role     string `json:"role"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		u, err := m.store.CreateUser(r.Context(), body.Username, body.Email,
			body.FullName, body.GroupID, body.Role, body.Password)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		json.NewEncoder(w).Encode(u)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (m *Manager) HandleUsersSub(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(strings.TrimSuffix(r.URL.Path, "/"), "/password") {
		m.handleUserPasswordReset(w, r)
		return
	}
	m.handleUserItem(w, r)
}

func (m *Manager) handleUserItem(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !m.backendReady(w) {
		return
	}
	id := resourcePathID(r.URL.Path, "/api/users/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id required")
		return
	}
	switch r.Method {
	case http.MethodPut:
		if !m.requirePerm(w, r, authz.PermUsersWrite) {
			return
		}
		var body struct {
			Email    string `json:"email"`
			FullName string `json:"full_name"`
			GroupID  string `json:"group_id"`
			Role     string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		u, err := m.store.UpdateUser(r.Context(), id, body.Email, body.FullName,
			body.GroupID, body.Role)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		json.NewEncoder(w).Encode(u)
	case http.MethodDelete:
		if !m.requirePerm(w, r, authz.PermUsersDelete) {
			return
		}
		if err := m.store.DeleteUser(r.Context(), id); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (m *Manager) handleUserPasswordReset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !m.backendReady(w) {
		return
	}
	path := strings.TrimSuffix(r.URL.Path, "/")
	rest := strings.TrimPrefix(path, "/api/users/")
	id := strings.TrimSuffix(rest, "/password")
	if id == "" || id == rest {
		writeError(w, http.StatusBadRequest, "id required")
		return
	}
	if !m.requirePerm(w, r, authz.PermUsersWrite) {
		return
	}
	var body struct {
		New string `json:"new"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := m.store.SetPassword(r.Context(), id, body.New); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (m *Manager) HandleTokens(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !m.backendReady(w) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !m.requirePerm(w, r, authz.PermTokensRead) {
			return
		}
		items, err := m.store.ListTokens(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"items": items, "count": len(items)})
	case http.MethodPost:
		if !m.requirePerm(w, r, authz.PermTokensCreate) {
			return
		}
		var body struct {
			Name      string `json:"name"`
			Role      string `json:"role"`
			UserID    string `json:"user_id"`
			ExpiresIn string `json:"expires_in"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		var ttl time.Duration
		if body.ExpiresIn != "" {
			d, err := time.ParseDuration(body.ExpiresIn)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid expires_in")
				return
			}
			ttl = d
		}
		ct, err := m.store.CreateToken(r.Context(), body.Name, body.Role, body.UserID, ttl)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		json.NewEncoder(w).Encode(ct)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (m *Manager) HandleTokenItem(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !m.backendReady(w) {
		return
	}
	id := resourcePathID(r.URL.Path, "/api/tokens/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id required")
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !m.requirePerm(w, r, authz.PermTokensDelete) {
		return
	}
	if err := m.store.DeleteToken(r.Context(), id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}
