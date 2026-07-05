package authz_test

import (
	"testing"

	"github.com/wolfee-watcher/pkg/authz"
)

func TestValidRole(t *testing.T) {
	cases := []struct {
		role  string
		valid bool
	}{
		{authz.RoleAdmin, true},
		{authz.RoleRO, true},
		{"", false},
		{"superuser", false},
		{"ADMIN", false},
		{"Admin", false},
		{" admin", false},
	}
	for _, c := range cases {
		if got := authz.ValidRole(c.role); got != c.valid {
			t.Errorf("ValidRole(%q) = %v, want %v", c.role, got, c.valid)
		}
	}
}

func TestEffectiveRole(t *testing.T) {
	cases := []struct {
		userRole, groupRole string
		want                string
	}{

		{authz.RoleAdmin, "", authz.RoleAdmin},
		{authz.RoleAdmin, authz.RoleRO, authz.RoleAdmin},

		{authz.RoleRO, authz.RoleAdmin, authz.RoleAdmin},
		{"", authz.RoleAdmin, authz.RoleAdmin},

		{authz.RoleRO, authz.RoleRO, authz.RoleRO},
		{authz.RoleRO, "", authz.RoleRO},
		{"", "", authz.RoleRO},

		{"superuser", "", authz.RoleRO},
		{"", "superuser", authz.RoleRO},
	}
	for _, c := range cases {
		got := authz.EffectiveRole(c.userRole, c.groupRole)
		if got != c.want {
			t.Errorf("EffectiveRole(%q, %q) = %q, want %q",
				c.userRole, c.groupRole, got, c.want)
		}
	}
}
