package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/accounts"
	"github.com/wolfee-watcher/pkg/authz"
)

type Store interface {
	VerifyPassword(ctx context.Context, username, password string) (accounts.User, error)
	CreateSession(ctx context.Context, userID string, ttl time.Duration) (accounts.Session, error)
	LookupSession(ctx context.Context, id string) (accounts.User, error)
	DeleteSession(ctx context.Context, id string) error
	ValidateToken(ctx context.Context, plaintext string) (accounts.User, error)
	PurgeExpiredSessions(ctx context.Context) error

	GetUserByUsername(ctx context.Context, username string) (accounts.User, error)
	ListUsers(ctx context.Context) ([]accounts.User, error)
	CreateUser(ctx context.Context, username, email, fullName, groupID, role, password string) (accounts.User, error)
	UpdateUser(ctx context.Context, id, email, fullName, groupID, role string) (accounts.User, error)
	DeleteUser(ctx context.Context, id string) error
	SetPassword(ctx context.Context, userID, newPassword string) error
	ChangePassword(ctx context.Context, username, current, newPassword string) error

	ListGroups(ctx context.Context) ([]accounts.Group, error)
	CreateGroup(ctx context.Context, name, description, role string) (accounts.Group, error)
	UpdateGroup(ctx context.Context, id, name, description, role string) (accounts.Group, error)
	DeleteGroup(ctx context.Context, id string) error

	ListTokens(ctx context.Context) ([]accounts.Token, error)
	CreateToken(ctx context.Context, name, role, userID string, ttl time.Duration) (accounts.CreatedToken, error)
	DeleteToken(ctx context.Context, id string) error
}

const (
	CookieName = "kv8_session"

	SessionTTL = 12 * time.Hour

	rlWindow     = time.Minute
	rlMaxTries   = 5
	rlEntriesMax = 1000

	cacheMax = 5000
)

type UserInfo struct {
	ID            string          `json:"id"`
	Username      string          `json:"username"`
	Email         string          `json:"email"`
	FullName      string          `json:"full_name"`
	Role          string          `json:"role"`
	GroupRole     string          `json:"group_role,omitempty"`
	EffectiveRole string          `json:"effective_role"`
	GroupID       string          `json:"group_id,omitempty"`
	GroupName     string          `json:"group_name,omitempty"`
	Permissions   map[string]bool `json:"permissions"`
}

type Manager struct {
	store        Store
	secureCookie bool

	mu    sync.Mutex
	cache map[string]cacheEntry

	rlMu      sync.Mutex
	rlEntries map[string]*rlEntry
}

func userInfo(u accounts.User) UserInfo {
	return UserInfo{
		ID:            u.ID,
		Username:      u.Username,
		Email:         u.Email,
		FullName:      u.FullName,
		Role:          u.Role,
		GroupRole:     u.GroupRole,
		EffectiveRole: u.EffectiveRole,
		GroupID:       u.GroupID,
		GroupName:     u.GroupName,
		Permissions:   authz.Permissions(u.EffectiveRole),
	}
}

type cacheEntry struct {
	user      UserInfo
	expiresAt time.Time
}

type rlEntry struct {
	failures int
	resetAt  time.Time
}

const cacheTTL = 5 * time.Second

func New(store Store, secureCookie bool) *Manager {
	return &Manager{
		store:        store,
		secureCookie: secureCookie,
		cache:        map[string]cacheEntry{},
		rlEntries:    map[string]*rlEntry{},
	}
}

var errNoBackend = errors.New("auth backend unavailable")

func (m *Manager) HandleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}

	if m.store == nil {
		writeError(w, http.StatusServiceUnavailable, errNoBackend.Error())
		return
	}

	rlKey := strings.ToLower(strings.TrimSpace(body.Username))
	if wait := m.rlCheck(rlKey); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "too many login attempts — try again later")
		return
	}

	u, err := m.store.VerifyPassword(r.Context(), body.Username, body.Password)
	if err != nil {
		m.rlRecord(rlKey)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	m.rlReset(rlKey)

	sess, err := m.store.CreateSession(r.Context(), u.ID, SessionTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session create failed")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    sess.ID,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		HttpOnly: true,
		Secure:   m.secureCookie,
		SameSite: http.SameSiteStrictMode,
	})
	json.NewEncoder(w).Encode(userInfo(u))
}

func (m *Manager) HandleLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cookie, err := r.Cookie(CookieName)
	if err == nil && cookie.Value != "" {
		m.invalidate(cookie.Value)
		if m.store != nil {
			_ = m.store.DeleteSession(r.Context(), cookie.Value)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   m.secureCookie,
		SameSite: http.SameSiteStrictMode,
	})
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (m *Manager) HandleMe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	u, err := m.Resolve(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	json.NewEncoder(w).Encode(u)
}

func (m *Manager) Resolve(r *http.Request) (UserInfo, error) {
	cookie, err := r.Cookie(CookieName)
	if err == nil && cookie.Value != "" {
		return m.resolveSession(r, cookie.Value)
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return m.resolveToken(r, strings.TrimPrefix(auth, "Bearer "))
	}
	return UserInfo{}, errors.New("no session")
}

func (m *Manager) resolveSession(r *http.Request, sessionID string) (UserInfo, error) {
	now := time.Now()
	m.mu.Lock()
	if e, ok := m.cache[sessionID]; ok && now.Before(e.expiresAt) {
		m.mu.Unlock()
		return e.user, nil
	}
	m.mu.Unlock()

	if m.store == nil {
		return UserInfo{}, errNoBackend
	}
	u, err := m.store.LookupSession(r.Context(), sessionID)
	if err != nil {
		m.invalidate(sessionID)
		return UserInfo{}, err
	}
	ui := userInfo(u)
	m.cacheSet(sessionID, ui, now)
	return ui, nil
}

func (m *Manager) resolveToken(r *http.Request, token string) (UserInfo, error) {
	cacheKey := "tok:" + token
	now := time.Now()
	m.mu.Lock()
	if e, ok := m.cache[cacheKey]; ok && now.Before(e.expiresAt) {
		m.mu.Unlock()
		return e.user, nil
	}
	m.mu.Unlock()

	if m.store == nil {
		return UserInfo{}, errNoBackend
	}
	u, err := m.store.ValidateToken(r.Context(), token)
	if err != nil {
		return UserInfo{}, err
	}
	ui := userInfo(u)
	m.cacheSet(cacheKey, ui, now)
	return ui, nil
}

func (m *Manager) cacheSet(key string, u UserInfo, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.cache) >= cacheMax {
		for k, v := range m.cache {
			if now.After(v.expiresAt) {
				delete(m.cache, k)
			}
		}
	}
	if len(m.cache) < cacheMax {
		m.cache[key] = cacheEntry{user: u, expiresAt: now.Add(cacheTTL)}
	}
}

func (m *Manager) invalidate(sessionID string) {
	m.mu.Lock()
	delete(m.cache, sessionID)
	m.mu.Unlock()
}

func (m *Manager) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := m.Resolve(r)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		r.Header.Set("X-Acting-User", u.Username)
		r.Header.Set("X-Acting-Role", u.EffectiveRole)
		next.ServeHTTP(w, r)
	})
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg})
}

func (m *Manager) rlCheck(key string) time.Duration {
	m.rlMu.Lock()
	defer m.rlMu.Unlock()
	e, ok := m.rlEntries[key]
	if !ok {
		return 0
	}
	if time.Now().After(e.resetAt) {
		delete(m.rlEntries, key)
		return 0
	}
	if e.failures >= rlMaxTries {
		return time.Until(e.resetAt)
	}
	return 0
}

func (m *Manager) rlRecord(key string) {
	m.rlMu.Lock()
	defer m.rlMu.Unlock()
	if len(m.rlEntries) >= rlEntriesMax {
		now := time.Now()
		for k, e := range m.rlEntries {
			if now.After(e.resetAt) {
				delete(m.rlEntries, k)
			}
		}
	}
	e, ok := m.rlEntries[key]
	if !ok || time.Now().After(e.resetAt) {
		if len(m.rlEntries) >= rlEntriesMax {

			var evictKey string
			var earliest time.Time
			for k, v := range m.rlEntries {
				if evictKey == "" || v.resetAt.Before(earliest) {
					evictKey = k
					earliest = v.resetAt
				}
			}
			delete(m.rlEntries, evictKey)
		}
		m.rlEntries[key] = &rlEntry{failures: 1, resetAt: time.Now().Add(rlWindow)}
		return
	}
	e.failures++
	if e.failures == rlMaxTries {
		log.Printf("[auth] rate-limit: %q locked for %v after %d failed attempts",
			key, time.Until(e.resetAt).Round(time.Second), e.failures)
	}
}

func (m *Manager) rlReset(key string) {
	m.rlMu.Lock()
	delete(m.rlEntries, key)
	m.rlMu.Unlock()
}
