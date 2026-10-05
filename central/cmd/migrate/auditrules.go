package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/wolfee-watcher/central/internal/schema"
	"github.com/wolfee-watcher/pkg/auditrules"
)

type legacyAuditPolicy struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Enabled     *bool    `json:"enabled"`
	AlertOnly   bool     `json:"alertOnly"`
	Sev         string   `json:"sev"`
	Namespace   string   `json:"namespace"`
	AuditChecks []string `json:"auditChecks"`
}

const legacyNameLimit = 120

func fitName(s string, limit int) string {
	for len(s) > limit && len(s) > 0 {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return strings.TrimSpace(s)
}

func legacyRules(p legacyAuditPolicy) ([]auditrules.Rule, error) {
	if p.ID == "" || len(p.AuditChecks) == 0 {
		return nil, fmt.Errorf("policy %q has no ID or audit checks", p.ID)
	}
	enabled := p.Enabled == nil || *p.Enabled
	sev := strings.ToLower(strings.TrimSpace(p.Sev))
	if sev != "" {
		valid := false
		for _, known := range auditrules.Severities {
			if sev == known {
				valid = true
			}
		}
		if !valid {
			return nil, fmt.Errorf("policy %q has unsupported severity %q", p.ID, p.Sev)
		}
	}
	var out []auditrules.Rule
	for _, check := range p.AuditChecks {
		b, ok := auditrules.LookupBuiltin(check)
		if !ok {
			return nil, fmt.Errorf("policy %q has unsupported check %q; source policy preserved", p.ID, check)
		}
		r := b.Rule()
		r.ID = p.ID + ":" + check
		r.Origin = auditrules.OriginCustom
		r.Group = "Custom"
		r.Enabled = enabled
		r.Alert = p.AlertOnly && enabled
		r.Name = b.Name
		if name := strings.TrimSpace(p.Name); name != "" {
			r.Name = fitName(name, legacyNameLimit)
			if len(p.AuditChecks) > 1 {
				r.Name = fitName(name, legacyNameLimit-len(b.Name)-2) + ": " + b.Name
			}
		}
		for _, known := range auditrules.Severities {
			if sev == known {
				r.Severity = sev
			}
		}
		if b.Kind != auditrules.KindExec && b.Kind != auditrules.KindAttach && b.Kind != auditrules.KindPortForward {
			r.Spec.NS = strings.TrimSpace(p.Namespace)
		}
		r.Normalize()
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("policy %q check %q: %w", p.ID, check, err)
		}
		out = append(out, r)
	}
	return out, nil
}

func insertAuditRule(ctx context.Context, tx pgx.Tx, r auditrules.Rule, by string) (bool, error) {
	spec, err := json.Marshal(r.Spec)
	if err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO audit_rules (id, name, grp, origin, enabled, alert, severity, spec, updated_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (id) DO NOTHING`,
		r.ID, r.Name, r.Group, r.Origin, r.Enabled, r.Alert, r.Severity, spec, by)
	if err != nil {
		return false, fmt.Errorf("insert audit rule %q: %w", r.ID, err)
	}
	return tag.RowsAffected() > 0, nil
}

func addBuiltinRules(ctx context.Context, pool *pgxpool.Pool) error {
	builtins := map[string]auditrules.Rule{}
	for _, r := range auditrules.BuiltinRules() {
		builtins[r.ID] = r
	}
	for _, addition := range schema.BuiltinRuleAdditions {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES ($1) ON CONFLICT DO NOTHING`, addition.Version)
		if err != nil {
			tx.Rollback(ctx)
			return err
		}
		if tag.RowsAffected() == 0 {
			tx.Rollback(ctx)
			continue
		}
		added := 0
		for _, id := range addition.IDs {
			r, ok := builtins[id]
			if !ok {
				tx.Rollback(ctx)
				return fmt.Errorf("built-in rule %q of %s is not in the catalog", id, addition.Version)
			}
			inserted, err := insertAuditRule(ctx, tx, r, "migration")
			if err != nil {
				tx.Rollback(ctx)
				return err
			}
			if inserted {
				added++
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		log.Printf("audit rules: %s added %d built-in rule(s)", addition.Version, added)
	}
	return nil
}

func migrateAuditRules(ctx context.Context, pool *pgxpool.Pool) error {
	var done bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`,
		schema.AuditRulesVersion).Scan(&done); err != nil {
		return err
	}
	if done {
		return nil
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	builtins := 0
	for _, r := range auditrules.BuiltinRules() {
		added, err := insertAuditRule(ctx, tx, r, "migration")
		if err != nil {
			return err
		}
		if added {
			builtins++
		}
	}

	rows, err := tx.Query(ctx, `SELECT data FROM runtime_policies WHERE data->>'detType' = 'Audit' FOR UPDATE`)
	if err != nil {
		return fmt.Errorf("read audit policies: %w", err)
	}
	var policies []legacyAuditPolicy
	kept := 0
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		var p legacyAuditPolicy
		if err := json.Unmarshal(raw, &p); err != nil || p.ID == "" {
			kept++
			log.Printf("audit rules: a legacy audit policy is unreadable and stays in runtime_policies: %v", err)
			continue
		}
		policies = append(policies, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	converted := 0
	var convertedIDs, convertedChecks []string
	for _, p := range policies {
		rules, err := legacyRules(p)
		if err != nil {
			kept++
			log.Printf("audit rules: %v; it stays in runtime_policies and is not evaluated", err)
			continue
		}
		for _, r := range rules {
			added, err := insertAuditRule(ctx, tx, r, "migration")
			if err != nil {
				return err
			}
			if added {
				converted++
			}
		}
		convertedIDs = append(convertedIDs, p.ID)
		convertedChecks = append(convertedChecks, p.AuditChecks...)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM runtime_policies WHERE data->>'detType' = 'Audit' AND data->>'id'=ANY($1::text[])`, convertedIDs); err != nil {
		return fmt.Errorf("remove converted audit policies: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE audit_rules SET enabled = FALSE WHERE origin = $1 AND updated_by = 'migration' AND id = ANY($2::text[])`,
		auditrules.OriginBuiltin, convertedChecks); err != nil {
		return fmt.Errorf("disable built-in rules replaced by converted policies: %w", err)
	}

	moved, err := tx.Exec(ctx,
		`INSERT INTO audit_violations
		   (cluster_id, ts, last_seen, rule_id, rule_name, sev, kind, resource, namespace, name, actor,
		    fingerprint, state, state_expires_at, state_changed_at, data)
		 SELECT cluster_id, ts, last_seen, rule_id, rule_name, sev,
		        COALESCE(data->>'kind', ''), COALESCE(data->>'resource', ''), namespace, pod,
		        COALESCE(data->>'user', ''), fingerprint, state, state_expires_at, state_changed_at, data
		   FROM kvisior_violations
		  WHERE vtype = 'audit'
		 ON CONFLICT DO NOTHING`)
	if err != nil {
		return fmt.Errorf("move audit violations: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM kvisior_violations WHERE vtype = 'audit'`); err != nil {
		return fmt.Errorf("remove moved audit violations: %w", err)
	}

	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES ($1) ON CONFLICT DO NOTHING`, schema.AuditRulesVersion); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	log.Printf("audit rules: %d built-in rule(s) seeded, %d audit polic(ies) converted into %d rule(s), %d left unconverted, %d violation(s) moved",
		builtins, len(convertedIDs), converted, kept, moved.RowsAffected())
	return nil
}
