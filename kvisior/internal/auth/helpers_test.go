package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/accounts"
)

type fakeStore struct {
	verifyPassword func(ctx context.Context, username, password string) (accounts.User, error)
	createSession  func(ctx context.Context, userID string, ttl time.Duration) (accounts.Session, error)
	lookupSession  func(ctx context.Context, id string) (accounts.User, error)
	deleteSession  func(ctx context.Context, id string) error
	validateToken  func(ctx context.Context, plaintext string) (accounts.User, error)
}

func (f *fakeStore) VerifyPassword(ctx context.Context, u, p string) (accounts.User, error) {
	if f.verifyPassword != nil {
		return f.verifyPassword(ctx, u, p)
	}
	return accounts.User{}, fmt.Errorf("invalid credentials")
}

func (f *fakeStore) CreateSession(ctx context.Context, userID string, ttl time.Duration) (accounts.Session, error) {
	if f.createSession != nil {
		return f.createSession(ctx, userID, ttl)
	}
	return accounts.Session{ID: "sess_default", ExpiresAt: time.Now().Add(ttl)}, nil
}

func (f *fakeStore) LookupSession(ctx context.Context, id string) (accounts.User, error) {
	if f.lookupSession != nil {
		return f.lookupSession(ctx, id)
	}
	return accounts.User{}, fmt.Errorf("session not found")
}

func (f *fakeStore) DeleteSession(ctx context.Context, id string) error {
	if f.deleteSession != nil {
		return f.deleteSession(ctx, id)
	}
	return nil
}

func (f *fakeStore) ValidateToken(ctx context.Context, plaintext string) (accounts.User, error) {
	if f.validateToken != nil {
		return f.validateToken(ctx, plaintext)
	}
	return accounts.User{}, fmt.Errorf("invalid token")
}

func (f *fakeStore) PurgeExpiredSessions(context.Context) error { return nil }

func (f *fakeStore) GetUserByUsername(context.Context, string) (accounts.User, error) {
	return accounts.User{}, fmt.Errorf("not found")
}
func (f *fakeStore) ListUsers(context.Context) ([]accounts.User, error) { return nil, nil }
func (f *fakeStore) CreateUser(context.Context, string, string, string, string, string, string) (accounts.User, error) {
	return accounts.User{}, nil
}
func (f *fakeStore) UpdateUser(context.Context, string, string, string, string, string) (accounts.User, error) {
	return accounts.User{}, nil
}
func (f *fakeStore) DeleteUser(context.Context, string) error          { return nil }
func (f *fakeStore) SetPassword(context.Context, string, string) error { return nil }
func (f *fakeStore) ChangePassword(context.Context, string, string, string) error {
	return nil
}
func (f *fakeStore) ListGroups(context.Context) ([]accounts.Group, error) { return nil, nil }
func (f *fakeStore) CreateGroup(context.Context, string, string, string) (accounts.Group, error) {
	return accounts.Group{}, nil
}
func (f *fakeStore) UpdateGroup(context.Context, string, string, string, string) (accounts.Group, error) {
	return accounts.Group{}, nil
}
func (f *fakeStore) DeleteGroup(context.Context, string) error            { return nil }
func (f *fakeStore) ListTokens(context.Context) ([]accounts.Token, error) { return nil, nil }
func (f *fakeStore) CreateToken(context.Context, string, string, string, time.Duration) (accounts.CreatedToken, error) {
	return accounts.CreatedToken{}, nil
}
func (f *fakeStore) DeleteToken(context.Context, string) error { return nil }

func newMgr() *Manager { return New(nil, false) }

func newMgrStore(fs *fakeStore) *Manager { return New(fs, false) }

func loginBody(user, pass string) *strings.Reader {
	return strings.NewReader(fmt.Sprintf(`{"username":%q,"password":%q}`, user, pass))
}
