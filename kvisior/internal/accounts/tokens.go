package accounts

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wolfee-watcher/pkg/authz"
)

type CreatedToken struct {
	Token     Token  `json:"token"`
	Plaintext string `json:"plaintext"`
}

func (s *Store) ListTokens(ctx context.Context) ([]Token, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT t.id, t.name, t.role, t.created_at, t.expires_at, t.last_used_at,
		       COALESCE(t.user_id, ''), COALESCE(u.username, '')
		FROM admin_tokens t
		LEFT JOIN admin_users u ON u.id = t.user_id
		ORDER BY t.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Token{}
	for rows.Next() {
		var t Token
		if err := rows.Scan(&t.ID, &t.Name, &t.Role, &t.CreatedAt,
			&t.ExpiresAt, &t.LastUsedAt, &t.UserID, &t.Username); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) CreateToken(ctx context.Context, name, role, userID string, ttl time.Duration) (CreatedToken, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return CreatedToken{}, errors.New("name required")
	}
	if !authz.ValidRole(role) {
		return CreatedToken{}, fmt.Errorf("invalid role %q", role)
	}
	plaintext := "ewt_" + randID(40)
	hash := hashToken(plaintext)
	id := "tok-" + randID(10)
	var uid any
	if userID != "" {
		uid = userID
	}
	var expires *time.Time
	if ttl > 0 {
		t := time.Now().Add(ttl)
		expires = &t
	}
	var t Token
	err := s.pool.QueryRow(ctx, `
		INSERT INTO admin_tokens (id, name, token_hash, role, user_id, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, name, role, created_at, expires_at, last_used_at, COALESCE(user_id, '')`,
		id, name, hash, role, uid, expires,
	).Scan(&t.ID, &t.Name, &t.Role, &t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &t.UserID)
	if err != nil {
		return CreatedToken{}, err
	}
	if t.UserID != "" {
		_ = s.pool.QueryRow(ctx,
			`SELECT username FROM admin_users WHERE id = $1`, t.UserID).Scan(&t.Username)
	}
	return CreatedToken{Token: t, Plaintext: plaintext}, nil
}

func (s *Store) DeleteToken(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM admin_tokens WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("token not found")
	}
	return nil
}

func (s *Store) ValidateToken(ctx context.Context, plaintext string) (User, error) {
	if plaintext == "" {
		return User{}, errors.New("invalid token")
	}
	hash := hashToken(plaintext)
	var tokenID, tokenRole, userID string
	var expires *time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT id, role, COALESCE(user_id, ''), expires_at
		 FROM admin_tokens WHERE token_hash = $1`, hash,
	).Scan(&tokenID, &tokenRole, &userID, &expires)
	if err != nil {
		return User{}, errors.New("invalid token")
	}
	if expires != nil && time.Now().After(*expires) {
		return User{}, errors.New("token expired")
	}
	_, _ = s.pool.Exec(ctx, `UPDATE admin_tokens SET last_used_at = NOW() WHERE id = $1`, tokenID)

	if userID == "" {
		return User{Role: tokenRole, EffectiveRole: tokenRole}, nil
	}
	var u User
	err = s.pool.QueryRow(ctx, `
		SELECT u.id, u.username, u.email, u.full_name, u.role, u.created_at,
		       COALESCE(u.group_id, ''), COALESCE(g.name, ''), COALESCE(g.role, '')
		FROM admin_users u
		LEFT JOIN admin_groups g ON g.id = u.group_id
		WHERE u.id = $1`, userID,
	).Scan(&u.ID, &u.Username, &u.Email, &u.FullName, &u.Role, &u.CreatedAt,
		&u.GroupID, &u.GroupName, &u.GroupRole)
	if err != nil {
		return User{}, errors.New("token user not found")
	}
	u.EffectiveRole = authz.EffectiveRole(u.Role, u.GroupRole)
	if tokenRole == authz.RoleRO {
		u.EffectiveRole = authz.RoleRO
	}
	return u, nil
}
