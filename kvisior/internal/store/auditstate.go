package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/wolfee-watcher/pkg/auditrules"
)

type auditDB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error)
}

func (c *Scoped) db() auditDB {
	if c.tx != nil {
		return c.tx
	}
	return c.s.pool
}

type AuditState struct {
	Admitted bool
	Enriched bool
	Pending  *AuditEnrichment
}

func (c *Scoped) WithAuditEvent(ctx context.Context, key string, fn func(*Scoped, *AuditState) error) error {
	tx, err := c.s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	scoped := &Scoped{s: c.s, id: c.id, tx: tx}
	var state AuditState
	var pending []byte
	if err = tx.QueryRow(ctx,
		`INSERT INTO audit_ingest_state(cluster_id, event_key) VALUES ($1,$2)
		 ON CONFLICT (cluster_id, event_key) DO UPDATE SET event_key = EXCLUDED.event_key
		 RETURNING admitted, enriched, pending`, c.id, key).Scan(&state.Admitted, &state.Enriched, &pending); err != nil {
		return err
	}
	if len(pending) > 0 {
		state.Pending = &AuditEnrichment{}
		if err = json.Unmarshal(pending, state.Pending); err != nil {
			return fmt.Errorf("decode pending audit enrichment: %w", err)
		}
	}
	before := state
	if err = fn(scoped, &state); err != nil {
		return err
	}
	if state.Admitted != before.Admitted || state.Enriched != before.Enriched || state.Pending != before.Pending {
		var raw []byte
		if state.Pending != nil {
			raw, err = json.Marshal(state.Pending)
			if err != nil {
				return err
			}
		}
		if _, err = tx.Exec(ctx, `UPDATE audit_ingest_state SET admitted=$3, enriched=$4, pending=$5 WHERE cluster_id=$1 AND event_key=$2`, c.id, key, state.Admitted, state.Enriched, raw); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

type AuditProgress struct {
	Admitted bool
	Enriched bool
	Pending  bool
}

func (c *Scoped) AuditProgress(ctx context.Context, keys []string) (map[string]AuditProgress, error) {
	out := map[string]AuditProgress{}
	if len(keys) == 0 {
		return out, nil
	}
	rows, err := c.s.pool.Query(ctx,
		`SELECT event_key, admitted, enriched, pending IS NOT NULL
		   FROM audit_ingest_state WHERE cluster_id=$1 AND event_key = ANY($2)`, c.id, keys)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var p AuditProgress
		if err := rows.Scan(&key, &p.Admitted, &p.Enriched, &p.Pending); err != nil {
			return nil, err
		}
		out[key] = p
	}
	return out, rows.Err()
}

func IsDataError(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && strings.HasPrefix(pgErr.Code, "22")
}

func (c *Scoped) ClaimAuditRule(ctx context.Context, key, rule string) (bool, error) {
	tag, err := c.db().Exec(ctx, `INSERT INTO audit_rule_matches(cluster_id,event_key,rule_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, c.id, key, rule)
	return tag.RowsAffected() > 0, err
}

func (c *Scoped) AuditThreshold(ctx context.Context, r auditrules.Rule) (bool, error) {
	if r.Spec.AlertEvery != auditrules.AlertThreshold {
		return true, nil
	}
	spec, _ := json.Marshal(r.Spec)
	revision := string(spec) + "/" + r.UpdatedAt.UTC().Format(time.RFC3339Nano)
	if _, err := c.db().Exec(ctx, `INSERT INTO audit_thresholds(cluster_id,rule_id,revision) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, c.id, r.ID, revision); err != nil {
		return false, err
	}
	var oldRevision string
	var times []time.Time
	var now time.Time
	if err := c.db().QueryRow(ctx, `SELECT revision,hit_at,clock_timestamp() FROM audit_thresholds WHERE cluster_id=$1 AND rule_id=$2 FOR UPDATE`, c.id, r.ID).Scan(&oldRevision, &times, &now); err != nil {
		return false, err
	}
	kept := make([]time.Time, 0, len(times)+1)
	if oldRevision == revision {
		for _, at := range times {
			if now.Sub(at) < time.Duration(r.Spec.ThMin)*time.Minute {
				kept = append(kept, at)
			}
		}
	}
	kept = append(kept, now)
	fire := len(kept) >= r.Spec.ThN
	if fire {
		kept = []time.Time{}
	}
	_, err := c.db().Exec(ctx, `UPDATE audit_thresholds SET revision=$3, hit_at=$4, updated_at=clock_timestamp() WHERE cluster_id=$1 AND rule_id=$2`, c.id, r.ID, revision, kept)
	return fire, err
}

func (c *Scoped) ExistingAuditEvent(ctx context.Context, uid string, around time.Time) (bool, bool, error) {
	from, to := auditJoinWindow(around)
	var admitted, enriched bool
	err := c.db().QueryRow(ctx,
		`SELECT COUNT(*) > 0, COALESCE(BOOL_OR(origin = 'both'), FALSE)
		   FROM audit_events WHERE cluster_id=$1 AND event_uid=$2 AND ts >= $3 AND ts <= $4`,
		pgx.QueryExecModeExec, c.id, uid, from, to).Scan(&admitted, &enriched)
	return admitted, enriched, err
}

func auditJoinWindow(around time.Time) (time.Time, time.Time) {
	if around.IsZero() {
		around = time.Now()
	}
	return around.Add(-auditJoinSlack), around.Add(auditJoinSlack)
}
