package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/accounts"
)

func TestHandleLogin_Success(t *testing.T) {
	m := newMgrStore(&fakeStore{
		verifyPassword: func(context.Context, string, string) (accounts.User, error) {
			return accounts.User{ID: "usr-1", Username: "alice", Role: "admin", EffectiveRole: "admin"}, nil
		},
		createSession: func(context.Context, string, time.Duration) (accounts.Session, error) {
			return accounts.Session{ID: "sess_newtoken", ExpiresAt: time.Now().Add(12 * time.Hour)}, nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/auth/login", loginBody("alice", "correct"))
	rr := httptest.NewRecorder()
	m.HandleLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var gotCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == CookieName {
			gotCookie = c
		}
	}
	if gotCookie == nil {
		t.Fatal("session cookie not set on login")
	}
	if gotCookie.Value != "sess_newtoken" {
		t.Errorf("cookie value: want sess_newtoken, got %q", gotCookie.Value)
	}
	if !gotCookie.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
}

func TestHandleLogin_WrongPassword(t *testing.T) {
	m := newMgrStore(&fakeStore{
		verifyPassword: func(context.Context, string, string) (accounts.User, error) {
			return accounts.User{}, errors.New("invalid credentials")
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/auth/login", loginBody("alice", "wrong"))
	rr := httptest.NewRecorder()
	m.HandleLogin(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestHandleLogin_RateLimited(t *testing.T) {
	m := newMgrStore(&fakeStore{
		verifyPassword: func(context.Context, string, string) (accounts.User, error) {
			return accounts.User{}, errors.New("invalid credentials")
		},
	})

	for i := 0; i < rlMaxTries; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/login", loginBody("alice", "bad"))
		rr := httptest.NewRecorder()
		m.HandleLogin(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401, got %d", i+1, rr.Code)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/login", loginBody("alice", "stillbad"))
	rr := httptest.NewRecorder()
	m.HandleLogin(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("after %d failures: want 429, got %d", rlMaxTries, rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("429 response must include Retry-After header")
	}
}

func TestHandleLogin_RateLimitIsPerUsername(t *testing.T) {
	m := newMgrStore(&fakeStore{
		verifyPassword: func(context.Context, string, string) (accounts.User, error) {
			return accounts.User{}, errors.New("invalid credentials")
		},
	})

	for i := 0; i < rlMaxTries; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/login", loginBody("alice", "bad"))
		m.HandleLogin(httptest.NewRecorder(), req)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/login", loginBody("bob", "wrong"))
	rr := httptest.NewRecorder()
	m.HandleLogin(rr, req)

	if rr.Code == http.StatusTooManyRequests {
		t.Error("locking alice must not affect bob")
	}
}

func TestHandleLogin_RateLimitClearedOnSuccess(t *testing.T) {
	m := newMgr()

	for i := 0; i < rlMaxTries-1; i++ {
		m.rlRecord("alice")
	}

	m.rlReset("alice")

	if w := m.rlCheck("alice"); w != 0 {
		t.Fatalf("rate limit must be cleared after successful login: got wait %v", w)
	}
}

func TestHandleLogin_MethodNotAllowed(t *testing.T) {
	m := newMgr()
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	rr := httptest.NewRecorder()
	m.HandleLogin(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rr.Code)
	}
}

func TestHandleLogin_InvalidJSON(t *testing.T) {
	m := newMgr()
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader("not-json"))
	rr := httptest.NewRecorder()
	m.HandleLogin(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rr.Code)
	}
}

func TestHandleLogout_ClearsCookie(t *testing.T) {
	m := newMgrStore(&fakeStore{})

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "sess_abc"})
	rr := httptest.NewRecorder()
	m.HandleLogout(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == CookieName && c.MaxAge >= 0 {
			t.Errorf("session cookie must be cleared: MaxAge=%d Value=%q", c.MaxAge, c.Value)
		}
	}
}

func TestHandleLogout_MethodNotAllowed(t *testing.T) {
	m := newMgr()
	req := httptest.NewRequest(http.MethodGet, "/auth/logout", nil)
	rr := httptest.NewRecorder()
	m.HandleLogout(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rr.Code)
	}
}

func TestHandleMe_NoCredentials(t *testing.T) {
	m := newMgr()
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	rr := httptest.NewRecorder()
	m.HandleMe(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestHandleMe_ValidSession(t *testing.T) {
	m := newMgrStore(&fakeStore{
		lookupSession: func(context.Context, string) (accounts.User, error) {
			return accounts.User{ID: "usr-1", Username: "alice", EffectiveRole: "admin"}, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "sess_abc"})
	rr := httptest.NewRecorder()
	m.HandleMe(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var got UserInfo
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Username != "alice" {
		t.Errorf("want alice, got %q", got.Username)
	}
}
