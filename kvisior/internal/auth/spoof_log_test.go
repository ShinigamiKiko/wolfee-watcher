package auth

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wolfee-watcher/kvisior/internal/accounts"
)

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestRequireAuth_LogsForgedActingHeaders(t *testing.T) {
	logs := captureLogs(t)
	m := newMgrStore(&fakeStore{
		lookupSession: func(context.Context, string) (accounts.User, error) {
			return accounts.User{ID: "usr-1", Username: "alice", EffectiveRole: "ro"}, nil
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/something", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "sess_abc"})
	req.Header.Set("X-Acting-User", "admin")
	req.Header.Set("X-Acting-Role", "admin")
	m.RequireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)

	out := logs.String()
	for _, want := range []string{`"msg":"acting_header_spoof_attempt"`, `"user":"alice"`, `"claimed_role":"admin"`, `"authenticated":true`} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %s:\n%s", want, out)
		}
	}
}

func TestRequireAuth_QuietWithoutActingHeaders(t *testing.T) {
	logs := captureLogs(t)
	m := newMgrStore(&fakeStore{
		lookupSession: func(context.Context, string) (accounts.User, error) {
			return accounts.User{ID: "usr-1", Username: "alice", EffectiveRole: "ro"}, nil
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/something", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "sess_abc"})
	m.RequireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)

	if strings.Contains(logs.String(), "acting_header_spoof_attempt") {
		t.Errorf("clean request was logged as a spoof attempt:\n%s", logs.String())
	}
}

func TestClipForLog(t *testing.T) {
	long := strings.Repeat("a", maxLoggedHeader+50)
	if got := ClipForLog(long); len(got) > maxLoggedHeader+len("…") {
		t.Errorf("clipped to %d bytes", len(got))
	}
	if got := ClipForLog("admin"); got != "admin" {
		t.Errorf("short value changed: %q", got)
	}
}
