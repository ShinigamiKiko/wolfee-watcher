package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/wolfee-watcher/central/internal/schema"
	"github.com/wolfee-watcher/pkg/logging"
)

const (
	connectTimeout = 5 * time.Minute
	connectRetry   = 2 * time.Second
)

func main() {
	logging.Setup("central-migrate")

	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		log.Fatal("POSTGRES_DSN is required (database owner credentials)")
	}

	if want := os.Getenv("EXPECTED_SCHEMA_VERSION"); want != "" && want != schema.Version {
		log.Fatalf("helm expects schema version %q but this image applies %q — "+
			"bump centralMigrate.schemaVersion in values.yaml and rebuild/redeploy together", want, schema.Version)
	}

	ctx := context.Background()
	pool, err := connect(ctx, dsn)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	if err := applyDDL(ctx, pool); err != nil {
		log.Fatalf("schema: %v", err)
	}
	if err := seedAccounts(ctx, pool); err != nil {
		log.Fatalf("seed accounts: %v", err)
	}
	if err := syncRoles(ctx, pool); err != nil {
		log.Fatalf("roles: %v", err)
	}
	if err := applyGrants(ctx, pool); err != nil {
		log.Fatalf("grants: %v", err)
	}
	if err := dropRemovedRoles(ctx, pool); err != nil {
		log.Fatalf("drop removed roles: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT (version) DO NOTHING`,
		schema.Version); err != nil {
		log.Fatalf("record migration: %v", err)
	}
	log.Printf("done — schema version %s applied", schema.Version)
}

func connect(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	deadline := time.Now().Add(connectTimeout)
	for {
		pool, err := pgxpool.New(ctx, dsn)
		if err == nil {
			pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err = pool.Ping(pingCtx)
			cancel()
			if err == nil {
				return pool, nil
			}
			pool.Close()
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("postgres not reachable after %s: %w", connectTimeout, err)
		}
		log.Printf("waiting for postgres: %v", err)
		time.Sleep(connectRetry)
	}
}

func applyDDL(ctx context.Context, pool *pgxpool.Pool) error {
	for _, stmt := range schema.DDL {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("%w\nstatement:\n%s", err, stmt)
		}
	}
	log.Printf("schema: %d statements applied", len(schema.DDL))
	return nil
}

func seedAccounts(ctx context.Context, pool *pgxpool.Pool) error {
	seeds := []string{
		`INSERT INTO admin_groups (id, name, description, role)
		 VALUES ('grp-platform-admins', 'platform-admins', 'Cluster administrators', 'admin')
		 ON CONFLICT (id) DO NOTHING`,
		`INSERT INTO admin_groups (id, name, description, role)
		 VALUES ('grp-devops-ro', 'devops-ro', 'Read-only operators', 'ro')
		 ON CONFLICT (id) DO NOTHING`,
		`INSERT INTO admin_users (id, username, email, full_name, group_id, role)
		 VALUES ('usr-admin', 'admin', 'admin@cluster.local', 'Admin User', 'grp-platform-admins', 'admin')
		 ON CONFLICT (id) DO NOTHING`,
	}
	for _, s := range seeds {
		if _, err := pool.Exec(ctx, s); err != nil {
			return err
		}
	}

	var hash string
	if err := pool.QueryRow(ctx,
		`SELECT password_hash FROM admin_users WHERE id = 'usr-admin'`).Scan(&hash); err != nil {
		return err
	}
	if hash != "" {
		return nil
	}
	plaintext := os.Getenv("ADMIN_BOOTSTRAP_PASSWORD")
	generated := false
	if plaintext == "" {
		plaintext = "ewp_" + randID(20)
		generated = true
	} else if len(plaintext) < 8 {
		return fmt.Errorf("ADMIN_BOOTSTRAP_PASSWORD must be at least 8 characters")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("bcrypt seed admin: %w", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE admin_users SET password_hash = $1 WHERE id = 'usr-admin'`, string(h)); err != nil {
		return err
	}
	if generated {
		log.Printf("WARNING: ADMIN_BOOTSTRAP_PASSWORD unset — generated one-shot admin password: %s", plaintext)
		log.Printf("Change it via the UI on first login. This line will not be printed again.")
	} else {
		log.Printf("seeded admin password from ADMIN_BOOTSTRAP_PASSWORD")
	}
	return nil
}

func syncRoles(ctx context.Context, pool *pgxpool.Pool) error {
	for role, envName := range schema.PasswordEnv {
		pw := os.Getenv(envName)
		if pw == "" {
			log.Printf("roles: %s skipped — %s not set", role, envName)
			continue
		}
		var exists bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, role).Scan(&exists); err != nil {
			return err
		}
		verb := "ALTER"
		if !exists {
			verb = "CREATE"
		}

		stmt := fmt.Sprintf(`%s ROLE %s LOGIN PASSWORD '%s'`,
			verb, role, strings.ReplaceAll(pw, "'", "''"))
		if _, err := pool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("%s role %s: %w", strings.ToLower(verb), role, err)
		}
		log.Printf("roles: %s %sd", role, strings.ToLower(verb))
	}
	return nil
}

func applyGrants(ctx context.Context, pool *pgxpool.Pool) error {

	managed := managedTables()
	for role, grants := range schema.Grants {
		var exists bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, role).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			continue
		}
		for _, table := range managed {
			if _, err := pool.Exec(ctx,
				fmt.Sprintf(`REVOKE ALL ON %s FROM %s`, table, role)); err != nil {
				return fmt.Errorf("revoke on %s from %s: %w", table, role, err)
			}
		}
		for _, g := range append(grants, schema.TableGrant{Table: "schema_migrations", Privs: "SELECT"}) {
			if _, err := pool.Exec(ctx,
				fmt.Sprintf(`GRANT %s ON %s TO %s`, g.Privs, g.Table, role)); err != nil {
				return fmt.Errorf("grant %s on %s to %s: %w", g.Privs, g.Table, role, err)
			}
			if strings.Contains(g.Privs, "INSERT") {
				if err := grantSerialSequence(ctx, pool, g.Table, role); err != nil {
					return err
				}
			}
		}
		log.Printf("grants: %s — %d table(s)", role, len(grants))
	}
	return nil
}

func managedTables() []string {
	seen := map[string]bool{"schema_migrations": true}
	for _, grants := range schema.Grants {
		for _, g := range grants {
			seen[g.Table] = true
		}
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func dropRemovedRoles(ctx context.Context, pool *pgxpool.Pool) error {
	for _, role := range schema.DroppedRoles {
		var exists bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, role).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			continue
		}
		if _, err := pool.Exec(ctx, fmt.Sprintf(`DROP OWNED BY %s`, role)); err != nil {
			return fmt.Errorf("drop owned by %s: %w", role, err)
		}
		if _, err := pool.Exec(ctx, fmt.Sprintf(`DROP ROLE %s`, role)); err != nil {
			return fmt.Errorf("drop role %s: %w", role, err)
		}
		log.Printf("roles: %s dropped (service no longer uses the database)", role)
	}
	return nil
}

func grantSerialSequence(ctx context.Context, pool *pgxpool.Pool, table, role string) error {
	var seq *string
	if err := pool.QueryRow(ctx,
		`SELECT pg_get_serial_sequence($1, 'id')`, table).Scan(&seq); err != nil {

		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42703" {
			return nil
		}
		return fmt.Errorf("serial sequence lookup for %s: %w", table, err)
	}
	if seq == nil {
		return nil
	}
	if _, err := pool.Exec(ctx,
		fmt.Sprintf(`GRANT USAGE, SELECT ON SEQUENCE %s TO %s`, *seq, role)); err != nil {
		return fmt.Errorf("grant sequence %s to %s: %w", *seq, role, err)
	}
	return nil
}

func randID(n int) string {
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)[:n]
}
