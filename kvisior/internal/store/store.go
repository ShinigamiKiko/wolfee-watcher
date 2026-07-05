package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	StateActive    = "ACTIVE"
	StateFP        = "FP"
	StateACK       = "ACK"
	StateDismissed = "DISMISSED"

	StateFPDuration  = 7 * 24 * time.Hour
	StateACKDuration = 60 * 24 * time.Hour

	StateDismissedDuration = 25 * time.Hour

	ActiveTTL = 30 * 24 * time.Hour

	AuditRunsTTL = 14 * 24 * time.Hour

	HoneypotEventsTTL = 30 * 24 * time.Hour
)

type Store struct {
	pool *pgxpool.Pool
}

func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	st, err := NewFromPool(ctx, pool)
	if err != nil {
		pool.Close()
		return nil, err
	}
	return st, nil
}

func NewFromPool(ctx context.Context, pool *pgxpool.Pool) (*Store, error) {
	var n int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil || n == 0 {
		if err == nil {
			err = fmt.Errorf("no migrations recorded")
		}
		return nil, fmt.Errorf("store: schema not ready (run central-migrate): %w", err)
	}
	log.Printf("[store] PostgreSQL schema ready")
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

func Fingerprint(ruleID, ns, pod string, ts time.Time) string {
	bucket := ts.Truncate(time.Hour).Unix()
	h := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d", ruleID, ns, pod, bucket)))
	return fmt.Sprintf("%x", h[:12])
}

func (s *Store) WriteViolation(ctx context.Context, vtype, ruleID, ruleName, sev, ns, pod, fingerprint string, data json.RawMessage) {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO kvisior_violations(vtype,rule_id,rule_name,sev,namespace,pod,fingerprint,data,last_seen)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
		 ON CONFLICT (fingerprint) WHERE fingerprint != '' DO UPDATE SET
		    data      = EXCLUDED.data,
		    last_seen = NOW(),
		    state = CASE
		              WHEN kvisior_violations.state IN ('FP','ACK','DISMISSED')
		                   AND kvisior_violations.state_expires_at IS NOT NULL
		                   AND kvisior_violations.state_expires_at < NOW()
		              THEN 'ACTIVE'
		              ELSE kvisior_violations.state
		            END,
		    state_expires_at = CASE
		              WHEN kvisior_violations.state IN ('FP','ACK','DISMISSED')
		                   AND kvisior_violations.state_expires_at IS NOT NULL
		                   AND kvisior_violations.state_expires_at < NOW()
		              THEN NULL
		              ELSE kvisior_violations.state_expires_at
		            END`,
		vtype, ruleID, ruleName, sev, ns, pod, fingerprint, data,
	)
	if err != nil {
		log.Printf("[store] write violation: %v", err)
	}
}

func (s *Store) SetViolationState(ctx context.Context, fingerprint, state string, ttl time.Duration) error {
	if fingerprint == "" {
		return nil
	}
	if state != StateFP && state != StateACK && state != StateActive && state != StateDismissed {
		return fmt.Errorf("store: invalid state %q", state)
	}
	var expires *time.Time
	if ttl > 0 {
		t := time.Now().Add(ttl)
		expires = &t
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE kvisior_violations
		    SET state            = $2,
		        state_expires_at = $3,
		        state_changed_at = NOW()
		  WHERE fingerprint = $1`,
		fingerprint, state, expires)
	return err
}

type ViolationRow struct {
	ID             int64           `json:"id"`
	Ts             time.Time       `json:"ts"`
	VType          string          `json:"type"`
	RuleID         string          `json:"ruleId"`
	RuleName       string          `json:"ruleName"`
	Sev            string          `json:"sev"`
	NS             string          `json:"ns"`
	Pod            string          `json:"pod"`
	Fingerprint    string          `json:"fingerprint"`
	State          string          `json:"state"`
	StateExpiresAt *time.Time      `json:"stateExpiresAt,omitempty"`
	Data           json.RawMessage `json:"data"`
}

func (s *Store) QueryViolations(ctx context.Context, vtype, stateFilter string, sinceID int64, limit int) ([]ViolationRow, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var stateClause string
	switch stateFilter {
	case "suppressed":
		stateClause = ` AND state IN ('FP','ACK','DISMISSED')
		                AND state_expires_at IS NOT NULL
		                AND state_expires_at > NOW()`
	case "all":
		stateClause = ""
	default:
		stateClause = ` AND (state = 'ACTIVE'
		                    OR (state IN ('FP','ACK','DISMISSED')
		                        AND state_expires_at IS NOT NULL
		                        AND state_expires_at < NOW()))`
	}
	q := `SELECT id, ts, vtype, rule_id, rule_name, sev, namespace, pod, fingerprint, state, state_expires_at, data
	      FROM kvisior_violations
	      WHERE id > $1` + stateClause
	args := []interface{}{sinceID}
	if vtype != "" {
		args = append(args, vtype)
		q += fmt.Sprintf(" AND vtype=$%d", len(args))
	}
	args = append(args, limit)
	q += fmt.Sprintf(" ORDER BY id ASC LIMIT $%d", len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ViolationRow
	for rows.Next() {
		var r ViolationRow
		if err := rows.Scan(&r.ID, &r.Ts, &r.VType, &r.RuleID, &r.RuleName, &r.Sev, &r.NS, &r.Pod, &r.Fingerprint, &r.State, &r.StateExpiresAt, &r.Data); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) DeleteViolation(ctx context.Context, fingerprint string) error {
	if fingerprint == "" {
		return nil
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM kvisior_violations WHERE fingerprint = $1`, fingerprint)
	return err
}

func (s *Store) SweepExpiredStates(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM kvisior_violations
		  WHERE (state IN ('FP','ACK','DISMISSED')
		         AND state_expires_at IS NOT NULL
		         AND state_expires_at < NOW())
		     OR (state = 'ACTIVE'
		         AND last_seen < NOW() - $1::interval)`,
		fmt.Sprintf("%d seconds", int64(ActiveTTL.Seconds())))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *Store) RunRetention(ctx context.Context) {
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()

	s.sweepOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.sweepOnce(ctx)
		}
	}
}

const retentionLockKey int64 = 0x77770001

func (s *Store) tryAdvisoryLock(ctx context.Context, key int64) (func(), bool) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, false
	}
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&got); err != nil || !got {
		conn.Release()
		return nil, false
	}
	return func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, key)
		conn.Release()
	}, true
}

func (s *Store) sweepOnce(ctx context.Context) {
	release, ok := s.tryAdvisoryLock(ctx, retentionLockKey)
	if !ok {
		return
	}
	defer release()
	if n, err := s.SweepExpiredStates(ctx); err != nil {
		log.Printf("[store] retention sweep: %v", err)
	} else if n > 0 {
		log.Printf("[store] retention sweep: %d expired rows dropped", n)
	}
	if n, err := s.SweepOldAuditRuns(ctx); err != nil {
		log.Printf("[store] audit-run retention sweep: %v", err)
	} else if n > 0 {
		log.Printf("[store] audit-run retention sweep: %d expired rows dropped", n)
	}
	if n, err := s.SweepOldHoneypotEvents(ctx); err != nil {
		log.Printf("[store] honeypot-event retention sweep: %v", err)
	} else if n > 0 {
		log.Printf("[store] honeypot-event retention sweep: %d expired rows dropped", n)
	}
	s.sweepIngested(ctx)
}

func (s *Store) UpsertImageScan(ctx context.Context, image string, scannedAt time.Time, data json.RawMessage) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO image_scans(image, scanned_at, data, updated_at)
		 VALUES ($1, $2, $3, NOW())
		 ON CONFLICT (image) DO UPDATE SET
		    scanned_at = EXCLUDED.scanned_at,
		    data       = EXCLUDED.data,
		    updated_at = NOW()`,
		image, scannedAt, data)
	return err
}

func (s *Store) ListImageScans(ctx context.Context) ([]json.RawMessage, error) {
	return s.listJSONBlobs(ctx, `SELECT data FROM image_scans ORDER BY scanned_at DESC`)
}

func (s *Store) UpsertImageHistory(ctx context.Context, image string, data json.RawMessage) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO image_histories(image, data, updated_at)
		 VALUES ($1, $2, NOW())
		 ON CONFLICT (image) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()`,
		image, data)
	return err
}

func (s *Store) ListImageHistories(ctx context.Context) ([]json.RawMessage, error) {
	return s.listJSONBlobs(ctx, `SELECT data FROM image_histories ORDER BY updated_at DESC`)
}

func (s *Store) PutScannerState(ctx context.Context, key string, data json.RawMessage) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO scanner_state(key, data, updated_at)
		 VALUES ($1, $2, NOW())
		 ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()`,
		key, data)
	return err
}

func (s *Store) GetScannerState(ctx context.Context, key string) (json.RawMessage, bool, error) {
	var d json.RawMessage
	err := s.pool.QueryRow(ctx, `SELECT data FROM scanner_state WHERE key = $1`, key).Scan(&d)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, err
	}
	return d, true, nil
}

const auditRunsKeepPerTool = 50

func (s *Store) InsertAuditRun(ctx context.Context, tool, runID, status string, startedAt, doneAt time.Time, data json.RawMessage) error {
	var sa, da *time.Time
	if !startedAt.IsZero() {
		sa = &startedAt
	}
	if !doneAt.IsZero() {
		da = &doneAt
	}
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO audit_runs(tool, run_id, status, started_at, done_at, data)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		tool, runID, status, sa, da, data); err != nil {
		return err
	}
	_, err := s.SweepOldAuditRuns(ctx)
	return err
}

func (s *Store) SweepOldAuditRuns(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM audit_runs
		  WHERE created_at < NOW() - $1::interval
		     OR id NOT IN (
		         SELECT id FROM (
		             SELECT id, ROW_NUMBER() OVER (PARTITION BY tool ORDER BY created_at DESC) AS rn
		             FROM audit_runs
		         ) ranked WHERE rn <= $2
		     )`,
		fmt.Sprintf("%d seconds", int64(AuditRunsTTL.Seconds())), auditRunsKeepPerTool)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *Store) ListAuditRuns(ctx context.Context, tool string, limit int) ([]json.RawMessage, error) {
	q := `SELECT data FROM audit_runs`
	args := []interface{}{}
	if tool != "" {
		q += ` WHERE tool = $1`
		args = append(args, tool)
	}
	q += ` ORDER BY created_at DESC`
	if limit > 0 {
		args = append(args, limit)
		q += fmt.Sprintf(` LIMIT $%d`, len(args))
	}
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]json.RawMessage, 0)
	for rows.Next() {
		var d json.RawMessage
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) listJSONBlobs(ctx context.Context, query string, args ...interface{}) ([]json.RawMessage, error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]json.RawMessage, 0)
	for rows.Next() {
		var d json.RawMessage
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

type RuleRow struct {
	ID   string          `json:"id"`
	Data json.RawMessage `json:"data"`
}

func (s *Store) SetPodWatch(ctx context.Context, ns, pod string, syscalls []string) error {
	key := ns + "/" + pod
	data, _ := json.Marshal(syscalls)
	_, err := s.pool.Exec(ctx,
		`INSERT INTO pod_syscall_watches(pod_key,namespace,pod,syscalls,updated_at)
		 VALUES($1,$2,$3,$4,NOW())
		 ON CONFLICT(pod_key) DO UPDATE SET syscalls=$4, updated_at=NOW()`,
		key, ns, pod, string(data))
	return err
}

func (s *Store) DeletePodWatch(ctx context.Context, ns, pod string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM pod_syscall_watches WHERE pod_key=$1`, ns+"/"+pod)
	return err
}

func (s *Store) GetPodWatch(ctx context.Context, ns, pod string) ([]string, error) {
	var raw string
	err := s.pool.QueryRow(ctx,
		`SELECT syscalls FROM pod_syscall_watches WHERE pod_key=$1`, ns+"/"+pod).Scan(&raw)
	if err != nil {
		return nil, err
	}
	var syscalls []string
	if err := json.Unmarshal([]byte(raw), &syscalls); err != nil {
		return nil, fmt.Errorf("store: unmarshal syscalls for %s/%s: %w", ns, pod, err)
	}
	return syscalls, nil
}

type PodWatchEntry struct {
	Syscalls  []string
	UpdatedAt time.Time
}

func (s *Store) ListPodWatches(ctx context.Context) (map[string]PodWatchEntry, error) {
	rows, err := s.pool.Query(ctx, `SELECT pod_key, syscalls, updated_at FROM pod_syscall_watches`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := make(map[string]PodWatchEntry)
	for rows.Next() {
		var key, raw string
		var updatedAt time.Time
		if err := rows.Scan(&key, &raw, &updatedAt); err == nil {
			var sc []string
			if err := json.Unmarshal([]byte(raw), &sc); err != nil {
				log.Printf("[store] unmarshal syscalls for %s: %v", key, err)
			}
			m[key] = PodWatchEntry{Syscalls: sc, UpdatedAt: updatedAt}
		}
	}
	return m, nil
}

func (s *Store) HideHoneypotEvent(ctx context.Context, ns, honeypot, eventID string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO honeypot_hidden_events(namespace,honeypot,event_id)
		 VALUES($1,$2,$3) ON CONFLICT DO NOTHING`,
		ns, honeypot, eventID)
	return err
}

func (s *Store) WriteHoneypotEvent(ctx context.Context, ns, honeypot, eventID, ts string, data json.RawMessage) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO honeypot_events(namespace,honeypot,event_id,ts,data)
		 VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`,
		ns, honeypot, eventID, ts, data)
	return err
}

func (s *Store) ListHoneypotEvents(ctx context.Context, ns, honeypot string) ([]json.RawMessage, error) {
	return s.listJSONBlobs(ctx,
		`SELECT data FROM honeypot_events
		  WHERE namespace=$1 AND honeypot=$2
		  ORDER BY ts ASC, created_at ASC`,
		ns, honeypot)
}

func (s *Store) SweepOldHoneypotEvents(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM honeypot_events WHERE created_at < NOW() - $1::interval`,
		fmt.Sprintf("%d seconds", int64(HoneypotEventsTTL.Seconds())))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *Store) HiddenHoneypotEvents(ctx context.Context, ns, honeypot string) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT event_id FROM honeypot_hidden_events WHERE namespace=$1 AND honeypot=$2`,
		ns, honeypot)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	return ids, rows.Err()
}

func (s *Store) LoadRules(ctx context.Context) ([]RuleRow, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, data FROM runtime_policies WHERE enabled = TRUE ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RuleRow
	for rows.Next() {
		var r RuleRow
		if err := rows.Scan(&r.ID, &r.Data); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
