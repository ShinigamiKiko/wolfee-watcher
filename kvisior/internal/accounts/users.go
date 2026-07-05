package accounts

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/wolfee-watcher/pkg/authz"
)

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT u.id, u.username, u.email, u.full_name, u.role, u.created_at,
		       COALESCE(u.group_id, ''), COALESCE(g.name, ''), COALESCE(g.role, '')
		FROM admin_users u
		LEFT JOIN admin_groups g ON g.id = u.group_id
		ORDER BY u.username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.FullName, &u.Role,
			&u.CreatedAt, &u.GroupID, &u.GroupName, &u.GroupRole); err != nil {
			return nil, err
		}
		u.EffectiveRole = authz.EffectiveRole(u.Role, u.GroupRole)
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx, `
		SELECT u.id, u.username, u.email, u.full_name, u.role, u.created_at,
		       COALESCE(u.group_id, ''), COALESCE(g.name, ''), COALESCE(g.role, '')
		FROM admin_users u
		LEFT JOIN admin_groups g ON g.id = u.group_id
		WHERE u.username = $1`, username,
	).Scan(&u.ID, &u.Username, &u.Email, &u.FullName, &u.Role, &u.CreatedAt,
		&u.GroupID, &u.GroupName, &u.GroupRole)
	if err != nil {
		return User{}, err
	}
	u.EffectiveRole = authz.EffectiveRole(u.Role, u.GroupRole)
	return u, nil
}

func (s *Store) CreateUser(ctx context.Context, username, email, fullName, groupID, role, password string) (User, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return User{}, errors.New("username required")
	}
	if !authz.ValidRole(role) {
		return User{}, fmt.Errorf("invalid role %q", role)
	}

	var hash string
	if password != "" {
		if err := ValidatePassword(password); err != nil {
			return User{}, err
		}
		h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return User{}, err
		}
		hash = string(h)
	}
	id := "usr-" + randID(10)
	var gid any
	if groupID != "" {
		gid = groupID
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO admin_users (id, username, email, full_name, group_id, role, password_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, username, email, fullName, gid, role, hash); err != nil {
		return User{}, err
	}
	return s.GetUserByUsername(ctx, username)
}

func (s *Store) UpdateUser(ctx context.Context, id, email, fullName, groupID, role string) (User, error) {
	if !authz.ValidRole(role) {
		return User{}, fmt.Errorf("invalid role %q", role)
	}

	if id == "usr-admin" && role != authz.RoleAdmin {
		return User{}, errors.New("cannot demote the built-in admin user")
	}
	var gid any
	if groupID != "" {
		gid = groupID
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE admin_users
		   SET email = $2, full_name = $3, group_id = $4, role = $5
		 WHERE id = $1`, id, email, fullName, gid, role)
	if err != nil {
		return User{}, err
	}
	if tag.RowsAffected() == 0 {
		return User{}, errors.New("user not found")
	}
	var u User
	err = s.pool.QueryRow(ctx, `
		SELECT u.id, u.username, u.email, u.full_name, u.role, u.created_at,
		       COALESCE(u.group_id, ''), COALESCE(g.name, ''), COALESCE(g.role, '')
		FROM admin_users u
		LEFT JOIN admin_groups g ON g.id = u.group_id
		WHERE u.id = $1`, id,
	).Scan(&u.ID, &u.Username, &u.Email, &u.FullName, &u.Role, &u.CreatedAt,
		&u.GroupID, &u.GroupName, &u.GroupRole)
	if err != nil {
		return User{}, err
	}
	u.EffectiveRole = authz.EffectiveRole(u.Role, u.GroupRole)
	return u, nil
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {

	if id == "usr-admin" {
		return errors.New("cannot delete the built-in admin user")
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM admin_users WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("user not found")
	}
	return nil
}
