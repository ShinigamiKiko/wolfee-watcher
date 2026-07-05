package accounts

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/wolfee-watcher/pkg/authz"
)

func (s *Store) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT g.id, g.name, g.description, g.role, g.created_at, g.updated_at,
		       (SELECT COUNT(*) FROM admin_users u WHERE u.group_id = g.id)
		FROM admin_groups g
		ORDER BY g.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Group{}
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.Role,
			&g.CreatedAt, &g.UpdatedAt, &g.MemberCount); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) CreateGroup(ctx context.Context, name, description, role string) (Group, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Group{}, errors.New("name required")
	}
	if !authz.ValidRole(role) {
		return Group{}, fmt.Errorf("invalid role %q", role)
	}
	id := "grp-" + randID(10)
	var g Group
	err := s.pool.QueryRow(ctx, `
		INSERT INTO admin_groups (id, name, description, role)
		VALUES ($1, $2, $3, $4)
		RETURNING id, name, description, role, created_at, updated_at`,
		id, name, description, role,
	).Scan(&g.ID, &g.Name, &g.Description, &g.Role, &g.CreatedAt, &g.UpdatedAt)
	return g, err
}

func (s *Store) UpdateGroup(ctx context.Context, id, name, description, role string) (Group, error) {
	if !authz.ValidRole(role) {
		return Group{}, fmt.Errorf("invalid role %q", role)
	}
	var g Group
	err := s.pool.QueryRow(ctx, `
		UPDATE admin_groups
		   SET name = $2, description = $3, role = $4, updated_at = NOW()
		 WHERE id = $1
		RETURNING id, name, description, role, created_at, updated_at`,
		id, name, description, role,
	).Scan(&g.ID, &g.Name, &g.Description, &g.Role, &g.CreatedAt, &g.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Group{}, errors.New("group not found")
	}
	return g, err
}

func (s *Store) DeleteGroup(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM admin_groups WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("group not found")
	}
	return nil
}
