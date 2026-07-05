package authz_test

import (
	"testing"

	"github.com/wolfee-watcher/pkg/authz"
)

func TestPermissions_AdminHasAll(t *testing.T) {
	perms := authz.Permissions(authz.RoleAdmin)
	required := []string{
		authz.PermPoliciesRead, authz.PermPoliciesWrite,
		authz.PermPoliciesCreate, authz.PermPoliciesDelete,
		authz.PermGroupsRead, authz.PermGroupsWrite,
		authz.PermGroupsCreate, authz.PermGroupsDelete,
		authz.PermUsersRead, authz.PermUsersWrite,
		authz.PermUsersCreate, authz.PermUsersDelete,
		authz.PermTokensRead, authz.PermTokensCreate, authz.PermTokensDelete,
		authz.PermIntegrationsRead, authz.PermIntegrationsWrite,
	}
	for _, p := range required {
		if !perms[p] {
			t.Errorf("admin role missing permission %q", p)
		}
	}
}

func TestPermissions_ROReadOnlyNoWrite(t *testing.T) {
	perms := authz.Permissions(authz.RoleRO)

	readPerms := []string{
		authz.PermPoliciesRead,
		authz.PermGroupsRead,
		authz.PermUsersRead,
		authz.PermTokensRead,
		authz.PermIntegrationsRead,
	}
	for _, p := range readPerms {
		if !perms[p] {
			t.Errorf("ro role must have read permission %q", p)
		}
	}

	writePerms := []string{
		authz.PermPoliciesWrite, authz.PermPoliciesCreate, authz.PermPoliciesDelete,
		authz.PermGroupsWrite, authz.PermGroupsCreate, authz.PermGroupsDelete,
		authz.PermUsersWrite, authz.PermUsersCreate, authz.PermUsersDelete,
		authz.PermTokensCreate, authz.PermTokensDelete,
		authz.PermIntegrationsWrite,
	}
	for _, p := range writePerms {
		if perms[p] {
			t.Errorf("ro role must not have write permission %q", p)
		}
	}
}

func TestPermissions_UnknownRoleFailsClosed(t *testing.T) {
	for _, role := range []string{"", "superuser", "ADMIN", "god"} {
		perms := authz.Permissions(role)
		if perms[authz.PermUsersDelete] {
			t.Errorf("unknown role %q must not have delete permission", role)
		}
		if !perms[authz.PermUsersRead] {
			t.Errorf("unknown role %q must still have read permission (fail closed to RO)", role)
		}
	}
}

func TestPermissions_NoFalsePositives(t *testing.T) {
	for _, role := range []string{authz.RoleAdmin, authz.RoleRO, ""} {
		perms := authz.Permissions(role)
		if perms["does.not.exist"] {
			t.Errorf("role %q: phantom permission must not be set", role)
		}
	}
}
