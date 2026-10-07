package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

const PostureFindingsMax = 5000

var ErrPostureUnavailable = errors.New("store: posture findings need schema 0018")

type PostureState struct {
	Findings    json.RawMessage `json:"findings"`
	Count       int             `json:"count"`
	EvaluatedAt *time.Time      `json:"evaluatedAt"`
}

func (s *Store) postureReady(ctx context.Context) (bool, error) {
	return s.tableReady(ctx, s.pool, "posture_findings")
}

func (c *Scoped) SavePosture(ctx context.Context, vtype string, evaluatedAt time.Time, count int, findings json.RawMessage) error {
	if ready, err := c.s.postureReady(ctx); err != nil || !ready {
		return err
	}
	_, err := c.s.pool.Exec(ctx,
		`INSERT INTO posture_findings (cluster_id, vtype, evaluated_at, count, findings)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (cluster_id, vtype) DO UPDATE
		   SET evaluated_at = EXCLUDED.evaluated_at, count = EXCLUDED.count,
		       findings = CASE WHEN posture_findings.findings IS DISTINCT FROM EXCLUDED.findings
		                       THEN EXCLUDED.findings ELSE posture_findings.findings END
		 WHERE posture_findings.evaluated_at <= EXCLUDED.evaluated_at`,
		c.id, vtype, evaluatedAt, count, findings)
	return err
}

func (c *Scoped) Posture(ctx context.Context, vtype string) (PostureState, error) {
	out := PostureState{Findings: json.RawMessage(`[]`)}
	if ready, err := c.s.postureReady(ctx); err != nil {
		return out, err
	} else if !ready {
		return out, ErrPostureUnavailable
	}
	var at time.Time
	err := c.s.pool.QueryRow(ctx,
		`SELECT findings, count, evaluated_at FROM posture_findings WHERE cluster_id = $1 AND vtype = $2`,
		c.id, vtype).Scan(&out.Findings, &out.Count, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.EvaluatedAt = &at
	return out, nil
}

func (c *Scoped) ViolationFirstSeen(ctx context.Context, fingerprints []string) (map[string]time.Time, error) {
	out := make(map[string]time.Time, len(fingerprints))
	if len(fingerprints) == 0 {
		return out, nil
	}
	rows, err := c.s.pool.Query(ctx,
		`SELECT fingerprint, ts FROM kvisior_violations WHERE cluster_id = $1 AND fingerprint = ANY($2)`,
		c.id, fingerprints)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var fp string
		var ts time.Time
		if err := rows.Scan(&fp, &ts); err != nil {
			return nil, err
		}
		out[fp] = ts
	}
	return out, rows.Err()
}
