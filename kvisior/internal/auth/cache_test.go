package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/accounts"
)

func TestCache_HitWithinTTL(t *testing.T) {
	calls := 0
	m := newMgrStore(&fakeStore{
		lookupSession: func(context.Context, string) (accounts.User, error) {
			calls++
			return accounts.User{Username: "alice"}, nil
		},
	})

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.AddCookie(&http.Cookie{Name: CookieName, Value: "sess_abc"})
		m.HandleMe(httptest.NewRecorder(), req)
	}
	if calls != 1 {
		t.Errorf("cache miss: expected 1 backend call for 5 requests, got %d", calls)
	}
}

func TestCache_MissAfterExpiry(t *testing.T) {
	calls := 0
	m := newMgrStore(&fakeStore{
		lookupSession: func(context.Context, string) (accounts.User, error) {
			calls++
			return accounts.User{Username: "alice"}, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "sess_abc"})
	m.HandleMe(httptest.NewRecorder(), req)

	m.mu.Lock()
	e := m.cache["sess_abc"]
	e.expiresAt = time.Now().Add(-time.Second)
	m.cache["sess_abc"] = e
	m.mu.Unlock()

	req2 := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req2.AddCookie(&http.Cookie{Name: CookieName, Value: "sess_abc"})
	m.HandleMe(httptest.NewRecorder(), req2)

	if calls != 2 {
		t.Errorf("expected 2 backend calls after cache expiry, got %d", calls)
	}
}

func TestCache_InvalidatedOnLogout(t *testing.T) {
	m := newMgrStore(&fakeStore{})

	m.mu.Lock()
	m.cache["sess_abc"] = cacheEntry{
		user:      UserInfo{Username: "alice"},
		expiresAt: time.Now().Add(cacheTTL),
	}
	m.mu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "sess_abc"})
	m.HandleLogout(httptest.NewRecorder(), req)

	m.mu.Lock()
	_, still := m.cache["sess_abc"]
	m.mu.Unlock()
	if still {
		t.Error("cache entry must be removed on logout")
	}
}
