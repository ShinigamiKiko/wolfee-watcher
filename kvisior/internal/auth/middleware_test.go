package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wolfee-watcher/kvisior/internal/accounts"
)

func TestRequireAuth_Unauthenticated(t *testing.T) {
	m := newMgr()
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	req := httptest.NewRequest(http.MethodGet, "/api/secret", nil)
	rr := httptest.NewRecorder()
	m.RequireAuth(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
	if called {
		t.Error("next handler must not be called for unauthenticated request")
	}
}

func TestRequireAuth_InjectsActingHeaders(t *testing.T) {
	m := newMgrStore(&fakeStore{
		lookupSession: func(context.Context, string) (accounts.User, error) {
			return accounts.User{ID: "usr-1", Username: "alice", EffectiveRole: "admin"}, nil
		},
	})

	var gotUser, gotRole string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = r.Header.Get("X-Acting-User")
		gotRole = r.Header.Get("X-Acting-Role")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/something", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "sess_abc"})
	m.RequireAuth(next).ServeHTTP(httptest.NewRecorder(), req)

	if gotUser != "alice" {
		t.Errorf("X-Acting-User: want alice, got %q", gotUser)
	}
	if gotRole != "admin" {
		t.Errorf("X-Acting-Role: want admin, got %q", gotRole)
	}
}

func TestRequireAuth_ClientCannotForgeActingHeaders(t *testing.T) {
	m := newMgrStore(&fakeStore{
		lookupSession: func(context.Context, string) (accounts.User, error) {
			return accounts.User{ID: "usr-1", Username: "alice", EffectiveRole: "ro"}, nil
		},
	})

	var gotUser, gotRole string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = r.Header.Get("X-Acting-User")
		gotRole = r.Header.Get("X-Acting-Role")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/something", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "sess_abc"})
	req.Header.Set("X-Acting-User", "hacker")
	req.Header.Set("X-Acting-Role", "admin")
	m.RequireAuth(next).ServeHTTP(httptest.NewRecorder(), req)

	if gotUser != "alice" {
		t.Errorf("forged X-Acting-User must be overwritten: got %q", gotUser)
	}
	if gotRole != "ro" {
		t.Errorf("forged X-Acting-Role must be overwritten: got %q", gotRole)
	}
}

func TestRequireAuth_BearerToken(t *testing.T) {
	m := newMgrStore(&fakeStore{
		validateToken: func(_ context.Context, plaintext string) (accounts.User, error) {
			if plaintext != "ewt_testtoken" {
				return accounts.User{}, errors.New("invalid token")
			}
			return accounts.User{Username: "ci-bot", EffectiveRole: "ro"}, nil
		},
	})

	var gotUser string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = r.Header.Get("X-Acting-User")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/something", nil)
	req.Header.Set("Authorization", "Bearer ewt_testtoken")
	rr := httptest.NewRecorder()
	m.RequireAuth(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if gotUser != "ci-bot" {
		t.Errorf("want ci-bot, got %q", gotUser)
	}
}

func TestRequireAuth_InvalidToken(t *testing.T) {
	m := newMgrStore(&fakeStore{
		validateToken: func(context.Context, string) (accounts.User, error) {
			return accounts.User{}, errors.New("invalid token")
		},
	})

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	req := httptest.NewRequest(http.MethodGet, "/api/something", nil)
	req.Header.Set("Authorization", "Bearer ewt_badtoken")
	rr := httptest.NewRecorder()
	m.RequireAuth(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
	if called {
		t.Error("next handler must not be called for invalid token")
	}
}

func TestRequireAuth_SessionTakesPrecedenceOverBearer(t *testing.T) {
	m := newMgrStore(&fakeStore{
		lookupSession: func(context.Context, string) (accounts.User, error) {
			return accounts.User{Username: "session-user", EffectiveRole: "admin"}, nil
		},
		validateToken: func(context.Context, string) (accounts.User, error) {
			return accounts.User{Username: "token-user", EffectiveRole: "ro"}, nil
		},
	})

	var gotUser string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = r.Header.Get("X-Acting-User")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/something", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "sess_abc"})
	req.Header.Set("Authorization", "Bearer ewt_sometoken")
	m.RequireAuth(next).ServeHTTP(httptest.NewRecorder(), req)

	if gotUser != "session-user" {
		t.Errorf("cookie session must take precedence over Bearer token: got %q", gotUser)
	}
}
