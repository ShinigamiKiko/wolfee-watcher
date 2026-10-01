package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

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

func legacyRules(p legacyAuditPolicy) []auditrules.Rule {
	enabled := p.Enabled == nil || *p.Enabled
	sev := strings.ToLower(strings.TrimSpace(p.Sev))
	var out []auditrules.Rule
	for _, check := range p.AuditChecks {
		b, ok := auditrules.LookupBuiltin(check)
		if !ok {
			continue
		}
		r := b.Rule()
		r.ID = p.ID + ":" + check
		r.Origin = auditrules.OriginCustom
		r.Group = "Custom"
		r.Enabled = enabled
		r.Alert = p.AlertOnly
		r.Name = b.Name
		if name := strings.TrimSpace(p.Name); name != "" {
			r.Name = name
			if len(p.AuditChecks) > 1 {
				r.Name = name + ": " + b.Name
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
			log.Printf("audit rules: policy %q check %q skipped: %v", p.ID, check, err)
			continue
		}
		out = append(out, r)
	}
	return out
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

	rows, err := tx.Query(ctx, `SELECT data FROM runtime_policies WHERE data->>'detType' = 'Audit'`)
	if err != nil {
		return fmt.Errorf("read audit policies: %w", err)
	}
	var policies []legacyAuditPolicy
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		var p legacyAuditPolicy
		if json.Unmarshal(raw, &p) == nil && p.ID != "" {
			policies = append(policies, p)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	converted := 0
	for _, p := range policies {
		for _, r := range legacyRules(p) {
			added, err := insertAuditRule(ctx, tx, r, "migration")
			if err != nil {
				return err
			}
			if added {
				converted++
			}
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM runtime_policies WHERE data->>'detType' = 'Audit'`); err != nil {
		return fmt.Errorf("remove converted audit policies: %w", err)
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

	if err := tx.Commit(ctx); err != nil {
		return err
	}
	log.Printf("audit rules: %d built-in rule(s) seeded, %d audit polic(ies) converted into %d rule(s), %d violation(s) moved",
		builtins, len(policies), converted, moved.RowsAffected())
	return nil
}
