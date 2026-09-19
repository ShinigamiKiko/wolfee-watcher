package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wolfee-watcher/kvisior/internal/accounts"
)

func loginRecorder(m *Manager, user, pass string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/auth/login", loginBody(user, pass))
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	m.HandleLogin(rr, req)
	return rr
}

func deviceCookie(t *testing.T, rr *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rr.Result().Cookies() {
		if c.Name == DeviceCookieName {
			return c
		}
	}
	t.Fatal("device cookie not set on successful login")
	return nil
}

func passwordStore(user, password string) *fakeStore {
	return &fakeStore{
		verifyPassword: func(_ context.Context, u, p string) (accounts.User, error) {
			if u != user || p != password {
				return accounts.User{}, errors.New("invalid credentials")
			}
			return accounts.User{ID: "usr-" + user, Username: user, Role: "admin", EffectiveRole: "admin"}, nil
		},
	}
}

func TestHandleLogin_TrustedDeviceSurvivesUsernameLock(t *testing.T) {
	m := newMgrStore(passwordStore("alice", "correct"))

	first := loginRecorder(m, "alice", "correct")
	if first.Code != http.StatusOK {
		t.Fatalf("first login: want 200, got %d", first.Code)
	}
	device := deviceCookie(t, first)

	for i := 0; i < rlMaxTries; i++ {
		loginRecorder(m, "alice", "bad")
	}
	if rr := loginRecorder(m, "alice", "correct"); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("without device cookie: want 429, got %d", rr.Code)
	}
	if rr := loginRecorder(m, "alice", "correct", device); rr.Code != http.StatusOK {
		t.Fatalf("with trusted device cookie: want 200, got %d", rr.Code)
	}
}

func TestHandleLogin_DeviceCookieBoundToUsername(t *testing.T) {
	m := newMgrStore(passwordStore("bob", "pw"))

	first := loginRecorder(m, "bob", "pw")
	if first.Code != http.StatusOK {
		t.Fatalf("bob login: want 200, got %d", first.Code)
	}
	device := deviceCookie(t, first)

	for i := 0; i < rlMaxTries; i++ {
		loginRecorder(m, "alice", "bad")
	}
	if rr := loginRecorder(m, "alice", "bad", device); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("bob's device cookie must not unlock alice: want 429, got %d", rr.Code)
	}
}

func TestHandleLogin_TamperedDeviceCookieIgnored(t *testing.T) {
	m := newMgrStore(passwordStore("alice", "correct"))

	device := deviceCookie(t, loginRecorder(m, "alice", "correct"))
	device.Value += "x"

	for i := 0; i < rlMaxTries; i++ {
		loginRecorder(m, "alice", "bad")
	}
	if rr := loginRecorder(m, "alice", "correct", device); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("tampered device cookie: want 429, got %d", rr.Code)
	}
}
