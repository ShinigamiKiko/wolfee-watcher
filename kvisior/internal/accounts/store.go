package accounts

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Role        string    `json:"role"`
	MemberCount int       `json:"member_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type User struct {
	ID            string    `json:"id"`
	Username      string    `json:"username"`
	Email         string    `json:"email"`
	FullName      string    `json:"full_name"`
	GroupID       string    `json:"group_id,omitempty"`
	GroupName     string    `json:"group_name,omitempty"`
	Role          string    `json:"role"`
	GroupRole     string    `json:"group_role,omitempty"`
	EffectiveRole string    `json:"effective_role"`
	CreatedAt     time.Time `json:"created_at"`
}

type Token struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Role       string     `json:"role"`
	UserID     string     `json:"user_id,omitempty"`
	Username   string     `json:"username,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-never-matches-00000000"), bcrypt.DefaultCost)

type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func hashToken(plaintext string) string {
	h := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(h[:])
}

func randID(n int) string {
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {

		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)[:n]
}
