package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wolfee-watcher/pkg/authz"
)

func reqWithRole(role string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/integrations/jira", nil)
	if role != "" {
		r.Header.Set("X-Acting-Role", role)
	}
	return r
}

func TestCallerRole_DefaultsToROAndValidatesHeader(t *testing.T) {
	cases := map[string]string{
		"":          authz.RoleRO,
		"admin":     authz.RoleAdmin,
		"ro":        authz.RoleRO,
		"ADMIN":     authz.RoleRO,
		"superuser": authz.RoleRO,
	}
	for header, want := range cases {
		if got := callerRole(reqWithRole(header)); got != want {
			t.Errorf("callerRole(X-Acting-Role=%q) = %q, want %q", header, got, want)
		}
	}
}

func TestRequireAdmin_OnlyAdminHeaderPasses(t *testing.T) {
	s := &Server{}
	for _, role := range []string{"", "ro", "bogus"} {
		rr := httptest.NewRecorder()
		if s.requireAdmin(rr, reqWithRole(role)) {
			t.Errorf("requireAdmin must reject role %q", role)
		}
		if rr.Code != http.StatusForbidden {
			t.Errorf("role %q: want 403, got %d", role, rr.Code)
		}
	}
	rr := httptest.NewRecorder()
	if !s.requireAdmin(rr, reqWithRole("admin")) {
		t.Error("requireAdmin must accept admin")
	}
}

func TestRequirePerm_RespectsRolePermissions(t *testing.T) {
	s := &Server{}

	rr := httptest.NewRecorder()
	if !s.requirePerm(rr, reqWithRole("ro"), authz.PermIntegrationsRead) {
		t.Error("ro must have integrations.read")
	}

	rr = httptest.NewRecorder()
	if s.requirePerm(rr, reqWithRole("ro"), authz.PermIntegrationsWrite) {
		t.Error("ro must NOT have integrations.write")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("ro write: want 403, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	if !s.requirePerm(rr, reqWithRole("admin"), authz.PermIntegrationsWrite) {
		t.Error("admin must have integrations.write")
	}
}
