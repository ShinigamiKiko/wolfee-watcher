package store

import (
	"context"
	"encoding/json"
	"time"
)

func (s *Store) ListPolicies(ctx context.Context) ([]json.RawMessage, error) {
	return s.listJSONBlobs(ctx, `SELECT data FROM runtime_policies ORDER BY data->>'name'`)
}

func (s *Store) ReplacePolicies(ctx context.Context, ids []string, raws [][]byte) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for i, raw := range raws {
		if _, err := tx.Exec(ctx,
			`INSERT INTO runtime_policies (id, data, updated_at) VALUES ($1, $2, NOW())
			 ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()`,
			ids[i], raw); err != nil {
			return err
		}
	}
	if len(ids) == 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM runtime_policies`); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(ctx,
			`DELETE FROM runtime_policies WHERE id <> ALL($1)`, ids); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

type AckItem struct {
	Key       string   `json:"key"`
	Type      string   `json:"type"`
	ExpiresAt *float64 `json:"expiresAt"`
}

func (s *Store) ListAcks(ctx context.Context) ([]AckItem, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT key, type,
		        CASE WHEN expires_at IS NULL THEN NULL
		             ELSE extract(epoch from expires_at)*1000
		        END
		   FROM violation_acks
		  WHERE expires_at IS NULL OR expires_at > NOW()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AckItem{}
	for rows.Next() {
		var it AckItem
		if rows.Scan(&it.Key, &it.Type, &it.ExpiresAt) == nil {
			items = append(items, it)
		}
	}
	return items, rows.Err()
}

func (s *Store) UpsertAck(ctx context.Context, key, typ string, expiresAt *time.Time) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO violation_acks(key, type, expires_at) VALUES($1,$2,$3)
		 ON CONFLICT(key) DO UPDATE SET type = EXCLUDED.type, expires_at = EXCLUDED.expires_at`,
		key, typ, expiresAt)
	return err
}

func (s *Store) DeleteAck(ctx context.Context, key string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM violation_acks WHERE key=$1`, key)
	return err
}

type AlertRow struct {
	ID          int64   `json:"id"`
	Ts          string  `json:"ts"`
	Source      string  `json:"source"`
	DetType     string  `json:"detType"`
	RuleID      string  `json:"ruleId"`
	RuleName    string  `json:"ruleName"`
	Severity    string  `json:"severity,omitempty"`
	Namespace   string  `json:"namespace,omitempty"`
	Target      string  `json:"target,omitempty"`
	Syscall     string  `json:"syscall,omitempty"`
	Detail      string  `json:"detail,omitempty"`
	Fingerprint string  `json:"fingerprint,omitempty"`
	DeliveredAt *string `json:"deliveredAt,omitempty"`
}

func (s *Store) QueryAlerts(ctx context.Context, since int64, limit int) ([]AlertRow, int64, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	const cols = `id, ts, source, det_type,
		COALESCE(rule_id,''), COALESCE(rule_name,''), COALESCE(severity,''),
		COALESCE(namespace,''), COALESCE(target,''), COALESCE(syscall,''),
		COALESCE(detail,''), COALESCE(fingerprint,''), delivered_at`

	var (
		q    string
		args []interface{}
	)
	if since == 0 {
		q = `SELECT * FROM (SELECT ` + cols + ` FROM alerts ORDER BY id DESC LIMIT $1) r ORDER BY id`
		args = []interface{}{limit}
	} else {
		q = `SELECT ` + cols + ` FROM alerts WHERE id > $1 ORDER BY id LIMIT $2`
		args = []interface{}{since, limit}
	}
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, since, err
	}
	defer rows.Close()

	out := []AlertRow{}
	lastID := since
	for rows.Next() {
		var a AlertRow
		if err := rows.Scan(&a.ID, &a.Ts, &a.Source, &a.DetType, &a.RuleID, &a.RuleName,
			&a.Severity, &a.Namespace, &a.Target, &a.Syscall, &a.Detail, &a.Fingerprint, &a.DeliveredAt); err != nil {
			continue
		}
		out = append(out, a)
		lastID = a.ID
	}
	return out, lastID, rows.Err()
}
