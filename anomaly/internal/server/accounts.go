package server

import (
	"net/http"
	"strings"

	"github.com/wolfee-watcher/pkg/authz"
)

func callerRole(r *http.Request) string {
	if role := strings.TrimSpace(r.Header.Get("X-Acting-Role")); authz.ValidRole(role) {
		return role
	}
	return authz.RoleRO
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if callerRole(r) == authz.RoleAdmin {
		return true
	}
	writeJSONError(w, http.StatusForbidden, "admin role required")
	return false
}

func (s *Server) requirePerm(w http.ResponseWriter, r *http.Request, perm string) bool {
	if authz.Permissions(callerRole(r))[perm] {
		return true
	}
	writeJSONError(w, http.StatusForbidden, "permission denied: "+perm)
	return false
}
