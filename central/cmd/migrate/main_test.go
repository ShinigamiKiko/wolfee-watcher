package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/wolfee-watcher/central/internal/schema"
)

// Requires a disposable PostgreSQL database with password authentication and a
// superuser connection so the test can create and remove its temporary role.
func TestSyncRolesPasswordEscaping(t *testing.T) {
	dsn := os.Getenv("MIGRATE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set MIGRATE_TEST_POSTGRES_DSN to run PostgreSQL integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	// Also catches accidental pool operations while syncRoles holds a connection.
	cfg.MaxConns = 1
	cfg.ConnConfig.RuntimeParams["standard_conforming_strings"] = "on"
	cfg.ConnConfig.RuntimeParams["client_encoding"] = "UTF8"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	role := `ww_test_"` + randID(12)
	quotedRole := pgx.Identifier{role}.Sanitize()
	const passwordEnv = "MIGRATE_TEST_ROLE_PASSWORD"
	originalPasswordEnv := schema.PasswordEnv
	schema.PasswordEnv = map[string]string{role: passwordEnv}
	t.Cleanup(func() {
		schema.PasswordEnv = originalPasswordEnv
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if _, err := pool.Exec(cleanupCtx, "DROP ROLE IF EXISTS "+quotedRole); err != nil {
			t.Errorf("drop test role: %v", err)
		}
	})

	tests := []struct {
		name     string
		password string
	}{
		{"create_with_special_characters", `q'uote\; $1 $$ -- /* */`},
		{"alter_with_special_characters", `another'password\`},
		{"unicode_and_newline", "пароль'\\\n€"},
		{"sql_injection", fmt.Sprintf(`x'; ALTER ROLE %s SUPERUSER; --`, quotedRole)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(passwordEnv, tt.password)
			if err := syncRoles(ctx, pool); err != nil {
				t.Fatal(err)
			}
			loginCfg := cfg.ConnConfig.Copy()
			loginCfg.User = role
			loginCfg.Password = tt.password
			login, err := pgx.ConnectConfig(ctx, loginCfg)
			if err != nil {
				t.Fatalf("authenticate with exact password: %v", err)
			}
			defer login.Close(context.Background())

			var superuser bool
			if err := pool.QueryRow(ctx, `SELECT rolsuper FROM pg_roles WHERE rolname = $1`, role).Scan(&superuser); err != nil {
				t.Fatal(err)
			}
			if superuser {
				t.Fatal("password was executed as SQL: test role became a superuser")
			}

			loginCfg.Password = "incorrect-password"
			wrongLogin, err := pgx.ConnectConfig(ctx, loginCfg)
			if err == nil {
				wrongLogin.Close(context.Background())
				t.Fatal("incorrect password accepted; test database must require password authentication")
			}
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "28P01" {
				t.Fatalf("expected password authentication failure, got %v", err)
			}
		})
	}

	t.Run("reject_unsafe_session_settings", func(t *testing.T) {
		t.Setenv(passwordEnv, `secret'\value`)
		if _, err := pool.Exec(ctx, "SET standard_conforming_strings = off"); err != nil {
			t.Fatal(err)
		}
		err := syncRoles(ctx, pool)
		if err == nil || !strings.Contains(err.Error(), "standard_conforming_strings=on") {
			t.Fatalf("expected unsafe session settings to be rejected, got %v", err)
		}
	})
}
