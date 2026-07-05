package accounts

import (
	"context"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/wolfee-watcher/pkg/authz"
)

func (s *Store) VerifyPassword(ctx context.Context, username, password string) (User, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return User{}, errors.New("invalid credentials")
	}
	var hash string
	var u User
	err := s.pool.QueryRow(ctx, `
		SELECT u.id, u.username, u.email, u.full_name, u.role, u.created_at,
		       COALESCE(u.group_id, ''), COALESCE(g.name, ''), COALESCE(g.role, ''),
		       u.password_hash
		FROM admin_users u
		LEFT JOIN admin_groups g ON g.id = u.group_id
		WHERE u.username = $1`, username,
	).Scan(&u.ID, &u.Username, &u.Email, &u.FullName, &u.Role, &u.CreatedAt,
		&u.GroupID, &u.GroupName, &u.GroupRole, &hash)
	userFound := err == nil && hash != ""

	hashToCheck := hash
	if !userFound {
		hashToCheck = string(dummyHash)
	}
	bcryptErr := bcrypt.CompareHashAndPassword([]byte(hashToCheck), []byte(password))

	if !userFound || bcryptErr != nil {
		return User{}, errors.New("invalid credentials")
	}
	u.EffectiveRole = authz.EffectiveRole(u.Role, u.GroupRole)
	return u, nil
}

func ValidatePassword(pw string) error {
	if len(pw) < 8 {
		return errors.New("password too short")
	}
	if len(pw) > 72 {
		return errors.New("password too long (max 72 characters)")
	}
	return nil
}

func (s *Store) SetPassword(ctx context.Context, userID, newPassword string) error {
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE admin_users SET password_hash = $1 WHERE id = $2`, string(h), userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("user not found")
	}

	_, _ = s.pool.Exec(ctx, `DELETE FROM admin_sessions WHERE user_id = $1`, userID)
	return nil
}

func (s *Store) ChangePassword(ctx context.Context, username, current, newPassword string) error {
	u, err := s.VerifyPassword(ctx, username, current)
	if err != nil {
		return errors.New("current password incorrect")
	}
	return s.SetPassword(ctx, u.ID, newPassword)
}

type Session struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

const maxSessionTTL = 24 * time.Hour

func (s *Store) CreateSession(ctx context.Context, userID string, ttl time.Duration) (Session, error) {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	if ttl > maxSessionTTL {
		ttl = maxSessionTTL
	}
	id := "sess_" + randID(48)
	expires := time.Now().Add(ttl)
	var sess Session
	err := s.pool.QueryRow(ctx, `
		INSERT INTO admin_sessions (id, user_id, expires_at)
		VALUES ($1, $2, $3)
		RETURNING id, user_id, created_at, expires_at, last_seen_at`,
		id, userID, expires,
	).Scan(&sess.ID, &sess.UserID, &sess.CreatedAt, &sess.ExpiresAt, &sess.LastSeenAt)
	return sess, err
}

func (s *Store) LookupSession(ctx context.Context, id string) (User, error) {
	var userID string
	var expires time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT user_id, expires_at FROM admin_sessions WHERE id = $1`, id,
	).Scan(&userID, &expires)
	if err != nil {
		return User{}, errors.New("session not found")
	}
	if time.Now().After(expires) {
		_, _ = s.pool.Exec(ctx, `DELETE FROM admin_sessions WHERE id = $1`, id)
		return User{}, errors.New("session not found")
	}
	_, _ = s.pool.Exec(ctx,
		`UPDATE admin_sessions SET last_seen_at = NOW() WHERE id = $1`, id)
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
		return User{}, errors.New("session user missing")
	}
	u.EffectiveRole = authz.EffectiveRole(u.Role, u.GroupRole)
	return u, nil
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM admin_sessions WHERE id = $1`, id)
	return err
}

func (s *Store) PurgeExpiredSessions(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM admin_sessions WHERE expires_at < NOW()`)
	return err
}
