package accounts

import (
	"context"
	"testing"

	"github.com/wolfee-watcher/pkg/authz"
)

func TestUpdateUser_CannotDemoteBuiltInAdmin(t *testing.T) {
	s := &Store{}
	if _, err := s.UpdateUser(context.Background(), "usr-admin", "", "", "", authz.RoleRO); err == nil {
		t.Fatal("demoting the built-in admin to ro must be rejected")
	}
}

func TestUpdateUser_RejectsInvalidRole(t *testing.T) {
	s := &Store{}
	if _, err := s.UpdateUser(context.Background(), "usr-x", "", "", "", "superuser"); err == nil {
		t.Fatal("invalid role must be rejected")
	}
}
