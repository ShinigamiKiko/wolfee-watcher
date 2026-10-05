package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wolfee-watcher/pkg/auditrules"
)

func TestLegacyRulesRejectPartialConversion(t *testing.T) {
	check := auditrules.BuiltinRules()[0].ID
	for _, p := range []legacyAuditPolicy{
		{ID: "unknown", AuditChecks: []string{check, "unsupported-check"}},
		{ID: "empty"},
		{ID: "severity", Sev: "urgent", AuditChecks: []string{check}},
		{AuditChecks: []string{check}},
	} {
		if _, err := legacyRules(p); err == nil {
			t.Fatalf("invalid policy %q was accepted", p.ID)
		}
	}
	rules, err := legacyRules(legacyAuditPolicy{ID: "valid", Name: "Legacy", AuditChecks: []string{check}})
	if err != nil || len(rules) != 1 {
		t.Fatalf("valid policy: rules=%v err=%v", rules, err)
	}
}

func TestLegacyRulesKeepDisabledPoliciesSilent(t *testing.T) {
	check := auditrules.BuiltinRules()[0].ID
	off := false
	rules, err := legacyRules(legacyAuditPolicy{ID: "off", Enabled: &off, AlertOnly: true, AuditChecks: []string{check}})
	if err != nil || len(rules) != 1 {
		t.Fatalf("rules=%v err=%v", rules, err)
	}
	if rules[0].Enabled || rules[0].Alert {
		t.Fatalf("a disabled legacy policy must not alert: %+v", rules[0])
	}
	long := strings.Repeat("я", 90)
	rules, err = legacyRules(legacyAuditPolicy{ID: "long", Name: long, AuditChecks: []string{check}})
	if err != nil || len(rules) != 1 || len(rules[0].Name) > legacyNameLimit || !utf8.ValidString(rules[0].Name) {
		t.Fatalf("long name: rules=%v err=%v", rules, err)
	}
}

func migrationDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AUDIT_TEST_DSN")
	if dsn == "" {
		t.Skip("set AUDIT_TEST_DSN to a disposable PostgreSQL database")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("audit_migration_%d", time.Now().UnixNano())
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{name}.Sanitize()+" CASCADE"); admin.Close() })
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err = applyDDL(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestUpgradedDatabaseGetsNewBuiltinRulesOnce(t *testing.T) {
	pool := migrationDatabase(t)
	ctx := context.Background()
	if err := migrateAuditRules(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM audit_rules WHERE id = 'forwarded-spoof'`); err != nil {
		t.Fatal(err)
	}
	present := func() bool {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_rules WHERE id = 'forwarded-spoof')`).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if err := migrateAuditRules(ctx, pool); err != nil || present() {
		t.Fatalf("the 0013 migration already ran and must not reseed: err=%v", err)
	}
	if err := addBuiltinRules(ctx, pool); err != nil || !present() {
		t.Fatalf("an installation from before the rule existed must receive it: err=%v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM audit_rules WHERE id = 'forwarded-spoof'`); err != nil {
		t.Fatal(err)
	}
	if err := addBuiltinRules(ctx, pool); err != nil || present() {
		t.Fatalf("a built-in rule an admin deleted must stay deleted: err=%v", err)
	}
}

func TestMigrationPreservesUnconvertiblePolicies(t *testing.T) {
	pool := migrationDatabase(t)
	ctx := context.Background()
	check := auditrules.BuiltinRules()[0].ID
	good := map[string]any{"id": "good", "name": "Good", "detType": "Audit", "auditChecks": []string{check}}
	bad := map[string]any{"id": "bad", "name": "Bad", "detType": "Audit", "auditChecks": []string{check, "unsupported-check"}}
	for _, p := range []map[string]any{good, bad} {
		raw, _ := json.Marshal(p)
		if _, err := pool.Exec(ctx, `INSERT INTO runtime_policies(id,data) VALUES ($1,$2)`, p["id"], raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := migrateAuditRules(ctx, pool); err != nil {
		t.Fatalf("an unconvertible policy must not stop the migration: %v", err)
	}
	var left string
	var policies, converted int
	var builtinEnabled bool
	if err := pool.QueryRow(ctx, `SELECT (SELECT COUNT(*) FROM runtime_policies),
	 (SELECT COALESCE(MIN(id), '') FROM runtime_policies),
	 (SELECT COUNT(*) FROM audit_rules WHERE id LIKE 'good:%' OR id LIKE 'bad:%'),
	 (SELECT enabled FROM audit_rules WHERE id=$1)`, check).Scan(&policies, &left, &converted, &builtinEnabled); err != nil {
		t.Fatal(err)
	}
	if policies != 1 || left != "bad" || converted != 1 {
		t.Fatalf("policies=%d left=%q converted=%d, want the bad policy kept and only the good one converted", policies, left, converted)
	}
	if builtinEnabled {
		t.Fatal("the built-in rule replaced by a converted policy stayed enabled")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM runtime_policies WHERE id='bad'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM audit_rules WHERE id=$1`, check); err != nil {
		t.Fatal(err)
	}
	if err := migrateAuditRules(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_rules WHERE id=$1)`, check).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("repeat migration restored a deliberately deleted builtin")
	}
}

func TestViolationSequenceUpgradeIsIdempotent(t *testing.T) {
	pool := migrationDatabase(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `ALTER TABLE audit_violations ALTER COLUMN id SET DEFAULT nextval('audit_violations_id_seq');
 INSERT INTO kvisior_violations(id,vtype,data) VALUES(100,'runtime','{}');
 INSERT INTO audit_violations(id,data) VALUES(100,'{}');`); err != nil {
		t.Fatal(err)
	}
	if err := applyDDL(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := pool.QueryRow(ctx, `SELECT id FROM audit_violations`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if id <= 100 {
		t.Fatalf("colliding audit ID not migrated: %d", id)
	}
	if err := applyDDL(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var repeated int64
	if err := pool.QueryRow(ctx, `SELECT id FROM audit_violations`).Scan(&repeated); err != nil {
		t.Fatal(err)
	}
	if repeated != id {
		t.Fatalf("repeated DDL renumbered %d to %d", id, repeated)
	}
	var auditID, runtimeID int64
	if err := pool.QueryRow(ctx, `INSERT INTO audit_violations(data) VALUES('{}') RETURNING id`).Scan(&auditID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO kvisior_violations(vtype,data) VALUES('runtime','{}') RETURNING id`).Scan(&runtimeID); err != nil {
		t.Fatal(err)
	}
	if auditID <= id || runtimeID <= auditID {
		t.Fatalf("not a global sequence: %d %d %d", id, auditID, runtimeID)
	}
}
