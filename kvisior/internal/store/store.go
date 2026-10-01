package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
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

func Fingerprint(cluster, ruleID, ns, pod string) string {
	if cluster == "" {
		cluster = DefaultCluster
	}
	h := sha256.Sum256([]byte(cluster + "\x00" + ruleID + "\x00" + ns + "\x00" + pod))
	return fmt.Sprintf("%x", h[:12])
}

func (c *Scoped) WriteViolation(ctx context.Context, vtype, ruleID, ruleName, sev, ns, pod, fingerprint string, data json.RawMessage) {
	_, err := c.s.pool.Exec(ctx,
		`INSERT INTO kvisior_violations(cluster_id,vtype,rule_id,rule_name,sev,namespace,pod,fingerprint,data,last_seen)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
		 ON CONFLICT (cluster_id,fingerprint) WHERE fingerprint != '' DO UPDATE SET
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
		c.id, vtype, ruleID, ruleName, sev, ns, pod, fingerprint, data,
	)
	if err != nil {
		log.Printf("[store] write violation (cluster=%s): %v", c.id, err)
	}
}

func (c *Scoped) SetViolationState(ctx context.Context, fingerprint, state string, ttl time.Duration) error {
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
	for _, table := range violationTables {
		if _, err := c.s.pool.Exec(ctx,
			`UPDATE `+table+`
			    SET state            = $3,
			        state_expires_at = $4,
			        state_changed_at = NOW()
			  WHERE cluster_id = $1 AND fingerprint = $2`,
			c.id, fingerprint, state, expires); err != nil {
			return err
		}
	}
	return nil
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
	Hits           int64           `json:"hits,omitempty"`
	LastSeen       *time.Time      `json:"lastSeen,omitempty"`
	Data           json.RawMessage `json:"data"`
}

const (
	violationTypeAudit   = "audit"
	tableViolations      = "kvisior_violations"
	tableAuditViolations = "audit_violations"
)

var violationTables = []string{tableViolations, tableAuditViolations}

func violationStateClause(stateFilter string) string {
	switch stateFilter {
	case "suppressed":
		return ` AND state IN ('FP','ACK','DISMISSED')
		         AND state_expires_at IS NOT NULL
		         AND state_expires_at > NOW()`
	case "all":
		return ""
	default:
		return ` AND (state = 'ACTIVE'
		              OR (state IN ('FP','ACK','DISMISSED')
		                  AND state_expires_at IS NOT NULL
		                  AND state_expires_at < NOW()))`
	}
}

func (c *Scoped) queryViolationTable(ctx context.Context, table, vtype, stateFilter string, sinceID int64, limit int) ([]ViolationRow, error) {
	cols := `id, ts, vtype, rule_id, rule_name, sev, namespace, pod, fingerprint, state, state_expires_at, 0::bigint, NULL::timestamptz, data`
	if table == tableAuditViolations {
		cols = `id, ts, 'audit', rule_id, rule_name, sev, namespace, name, fingerprint, state, state_expires_at, hits, last_seen, data`
	}
	q := `SELECT ` + cols + ` FROM ` + table + ` WHERE cluster_id = $1 AND id > $2` + violationStateClause(stateFilter)
	args := []interface{}{c.id, sinceID}
	if vtype != "" && table == tableViolations {
		args = append(args, vtype)
		q += fmt.Sprintf(" AND vtype=$%d", len(args))
	}
	args = append(args, limit)
	q += fmt.Sprintf(" ORDER BY id ASC LIMIT $%d", len(args))

	rows, err := c.s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ViolationRow
	for rows.Next() {
		var r ViolationRow
		if err := rows.Scan(&r.ID, &r.Ts, &r.VType, &r.RuleID, &r.RuleName, &r.Sev, &r.NS, &r.Pod, &r.Fingerprint,
			&r.State, &r.StateExpiresAt, &r.Hits, &r.LastSeen, &r.Data); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (c *Scoped) QueryViolations(ctx context.Context, vtype, stateFilter string, sinceID int64, limit int) ([]ViolationRow, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	if vtype == violationTypeAudit {
		return c.queryViolationTable(ctx, tableAuditViolations, vtype, stateFilter, sinceID, limit)
	}
	out, err := c.queryViolationTable(ctx, tableViolations, vtype, stateFilter, sinceID, limit)
	if err != nil || vtype != "" {
		return out, err
	}
	audit, err := c.queryViolationTable(ctx, tableAuditViolations, vtype, stateFilter, 0, limit)
	if err != nil {
		return nil, err
	}
	return append(out, audit...), nil
}

func (c *Scoped) DeleteViolation(ctx context.Context, fingerprint string) error {
	if fingerprint == "" {
		return nil
	}
	for _, table := range violationTables {
		if _, err := c.s.pool.Exec(ctx,
			`DELETE FROM `+table+` WHERE cluster_id = $1 AND fingerprint = $2`, c.id, fingerprint); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) SweepExpiredStates(ctx context.Context) (int64, error) {
	return sweepExpiredStates(ctx, s.pool)
}

func sweepExpiredStates(ctx context.Context, db execer) (int64, error) {
	var total int64
	for _, table := range violationTables {
		tag, err := db.Exec(ctx,
			`DELETE FROM `+table+`
			  WHERE (state IN ('FP','ACK','DISMISSED')
			         AND state_expires_at IS NOT NULL
			         AND state_expires_at < NOW())
			     OR (state = 'ACTIVE'
			         AND last_seen < NOW() - $1::interval)`,
			fmt.Sprintf("%d seconds", int64(ActiveTTL.Seconds())))
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
	}
	return total, nil
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

func (s *Store) withRetentionLock(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var got bool
	if err := tx.QueryRow(ctx,
		`SELECT pg_try_advisory_xact_lock($1)`, retentionLockKey).Scan(&got); err != nil {
		return err
	}
	if !got {
		return nil
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) sweepOnce(ctx context.Context) {
	err := s.withRetentionLock(ctx, func(tx pgx.Tx) error {
		if n, err := sweepExpiredStates(ctx, tx); err != nil {
			return fmt.Errorf("violation states: %w", err)
		} else if n > 0 {
			log.Printf("[store] retention sweep: %d expired rows dropped", n)
		}
		if n, err := sweepOldAuditRuns(ctx, tx); err != nil {
			return fmt.Errorf("audit runs: %w", err)
		} else if n > 0 {
			log.Printf("[store] audit-run retention sweep: %d expired rows dropped", n)
		}
		if n, err := sweepOldHoneypotEvents(ctx, tx); err != nil {
			return fmt.Errorf("honeypot events: %w", err)
		} else if n > 0 {
			log.Printf("[store] honeypot-event retention sweep: %d expired rows dropped", n)
		}
		return sweepIngested(ctx, tx)
	})
	if err != nil {
		log.Printf("[store] retention sweep: %v", err)
	}
	s.sweepUnpartitioned(ctx)
}

func (c *Scoped) UpsertImageScan(ctx context.Context, image string, scannedAt time.Time, data json.RawMessage) error {
	_, err := c.s.pool.Exec(ctx,
		`INSERT INTO image_scans(cluster_id, image, scanned_at, data, updated_at)
		 VALUES ($1, $2, $3, $4, NOW())
		 ON CONFLICT (cluster_id, image) DO UPDATE SET
		    scanned_at = EXCLUDED.scanned_at,
		    data       = EXCLUDED.data,
		    updated_at = NOW()`,
		c.id, image, scannedAt, data)
	return err
}

func (c *Scoped) ListImageScans(ctx context.Context) ([]json.RawMessage, error) {
	return c.listJSONBlobs(ctx,
		`SELECT data FROM image_scans WHERE cluster_id = $1 ORDER BY scanned_at DESC`, c.id)
}

func (c *Scoped) InsertImageScanWorkloads(ctx context.Context, image string, scannedAt time.Time, data json.RawMessage) error {
	var payload struct {
		Workloads []struct {
			Image      string    `json:"image"`
			Pod        string    `json:"pod"`
			Namespace  string    `json:"namespace"`
			PodUID     string    `json:"podUID"`
			PodIP      string    `json:"podIP"`
			Node       string    `json:"node"`
			ObservedAt time.Time `json:"observedAt"`
		} `json:"workloads"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("decode image workloads: %w", err)
	}
	for _, workload := range payload.Workloads {
		observedAt := workload.ObservedAt
		if observedAt.IsZero() {
			observedAt = scannedAt
		}
		workloadImage := workload.Image
		if workloadImage == "" {
			workloadImage = image
		}
		workloadData, err := json.Marshal(workload)
		if err != nil {
			return fmt.Errorf("encode image workload: %w", err)
		}
		if _, err := c.s.pool.Exec(ctx, `
			INSERT INTO image_scan_workloads
			  (cluster_id, image, namespace, pod, pod_uid, pod_ip, node, observed_at, data)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (cluster_id, image, namespace, pod_uid, observed_at) DO UPDATE SET
			  pod = EXCLUDED.pod, pod_ip = EXCLUDED.pod_ip,
			  node = EXCLUDED.node, data = EXCLUDED.data`,
			c.id, workloadImage, workload.Namespace, workload.Pod, workload.PodUID,
			workload.PodIP, workload.Node, observedAt, workloadData); err != nil {
			return err
		}
	}
	return nil
}

func (c *Scoped) ListImageScanWorkloads(ctx context.Context, image string) ([]json.RawMessage, error) {
	rows, err := c.s.pool.Query(ctx, `
		SELECT data FROM image_scan_workloads
		WHERE cluster_id = $1 AND ($2 = '' OR image = $2)
		ORDER BY observed_at DESC LIMIT 5000`, c.id, image)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []json.RawMessage
	for rows.Next() {
		var data json.RawMessage
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		out = append(out, data)
	}
	return out, rows.Err()
}

func (c *Scoped) UpsertImageHistory(ctx context.Context, image string, data json.RawMessage) error {
	_, err := c.s.pool.Exec(ctx,
		`INSERT INTO image_histories(cluster_id, image, data, updated_at)
		 VALUES ($1, $2, $3, NOW())
		 ON CONFLICT (cluster_id, image) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()`,
		c.id, image, data)
	return err
}

func (c *Scoped) ListImageHistories(ctx context.Context) ([]json.RawMessage, error) {
	return c.listJSONBlobs(ctx,
		`SELECT data FROM image_histories WHERE cluster_id = $1 ORDER BY updated_at DESC`, c.id)
}

func (c *Scoped) PutScannerState(ctx context.Context, key string, data json.RawMessage) error {
	_, err := c.s.pool.Exec(ctx,
		`INSERT INTO scanner_state(cluster_id, key, data, updated_at)
		 VALUES ($1, $2, $3, NOW())
		 ON CONFLICT (cluster_id, key) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()`,
		c.id, key, data)
	return err
}

func (c *Scoped) GetScannerState(ctx context.Context, key string) (json.RawMessage, bool, error) {
	var d json.RawMessage
	err := c.s.pool.QueryRow(ctx,
		`SELECT data FROM scanner_state WHERE cluster_id = $1 AND key = $2`, c.id, key).Scan(&d)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, err
	}
	return d, true, nil
}

const auditRunsKeepPerTool = 50

func (c *Scoped) InsertAuditRun(ctx context.Context, tool, runID, status string, startedAt, doneAt time.Time, data json.RawMessage) error {
	var sa, da *time.Time
	if !startedAt.IsZero() {
		sa = &startedAt
	}
	if !doneAt.IsZero() {
		da = &doneAt
	}
	if _, err := c.s.pool.Exec(ctx,
		`INSERT INTO audit_runs(cluster_id, tool, run_id, status, started_at, done_at, data)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		c.id, tool, runID, status, sa, da, data); err != nil {
		return err
	}
	_, err := c.s.SweepOldAuditRuns(ctx)
	return err
}

func (s *Store) SweepOldAuditRuns(ctx context.Context) (int64, error) {
	return sweepOldAuditRuns(ctx, s.pool)
}

func sweepOldAuditRuns(ctx context.Context, db execer) (int64, error) {
	tag, err := db.Exec(ctx,
		`DELETE FROM audit_runs
		  WHERE created_at < NOW() - $1::interval
		     OR id NOT IN (
		         SELECT id FROM (
		             SELECT id, ROW_NUMBER() OVER (PARTITION BY cluster_id, tool ORDER BY created_at DESC) AS rn
		             FROM audit_runs
		         ) ranked WHERE rn <= $2
		     )`,
		fmt.Sprintf("%d seconds", int64(AuditRunsTTL.Seconds())), auditRunsKeepPerTool)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

const MaxAuditRunsLimit = 500

func (c *Scoped) ListAuditRuns(ctx context.Context, tool string, limit int) ([]json.RawMessage, error) {
	if limit <= 0 || limit > MaxAuditRunsLimit {
		limit = MaxAuditRunsLimit
	}
	q := `SELECT data FROM audit_runs WHERE cluster_id = $1`
	args := []interface{}{c.id}
	if tool != "" {
		args = append(args, tool)
		q += fmt.Sprintf(` AND tool = $%d`, len(args))
	}
	q += ` ORDER BY created_at DESC`
	args = append(args, limit)
	q += fmt.Sprintf(` LIMIT $%d`, len(args))
	rows, err := c.s.pool.Query(ctx, q, args...)
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

type PodWatchSelection struct {
	Syscalls    []string `json:"syscalls"`
	LSMHooks    []string `json:"lsm_hooks"`
	Tracepoints []string `json:"tracepoints"`
}

func (c *Scoped) SetPodWatch(ctx context.Context, ns, pod string, selection PodWatchSelection) error {
	key := ns + "/" + pod
	data, _ := json.Marshal(selection)
	_, err := c.s.pool.Exec(ctx,
		`INSERT INTO pod_syscall_watches(cluster_id,pod_key,namespace,pod,syscalls,updated_at)
		 VALUES($1,$2,$3,$4,$5,NOW())
		 ON CONFLICT(cluster_id,pod_key) DO UPDATE SET syscalls=$5, updated_at=NOW()`,
		c.id, key, ns, pod, string(data))
	return err
}

func (c *Scoped) DeletePodWatch(ctx context.Context, ns, pod string) error {
	_, err := c.s.pool.Exec(ctx,
		`DELETE FROM pod_syscall_watches WHERE cluster_id=$1 AND pod_key=$2`, c.id, ns+"/"+pod)
	return err
}

func (c *Scoped) GetPodWatch(ctx context.Context, ns, pod string) (PodWatchSelection, error) {
	var raw string
	err := c.s.pool.QueryRow(ctx,
		`SELECT syscalls FROM pod_syscall_watches WHERE cluster_id=$1 AND pod_key=$2`,
		c.id, ns+"/"+pod).Scan(&raw)
	if err != nil {
		return podWatchError(err)
	}
	var selection PodWatchSelection
	if len(raw) > 0 && raw[0] == '{' {
		if err := json.Unmarshal([]byte(raw), &selection); err == nil {
			return selection, nil
		}
	}
	if len(raw) > 0 && raw[0] == '[' {
		var legacy []string
		if err := json.Unmarshal([]byte(raw), &legacy); err == nil {
			return PodWatchSelection{Syscalls: legacy}, nil
		}
	}
	return PodWatchSelection{}, fmt.Errorf("store: unmarshal watch for %s/%s", ns, pod)
}

func podWatchError(err error) (PodWatchSelection, error) {
	if errors.Is(err, pgx.ErrNoRows) {
		return PodWatchSelection{}, nil
	}
	return PodWatchSelection{}, err
}

type PodWatchEntry struct {
	PodWatchSelection
	UpdatedAt time.Time
}

func (c *Scoped) ListPodWatches(ctx context.Context) (map[string]PodWatchEntry, error) {
	rows, err := c.s.pool.Query(ctx,
		`SELECT pod_key, syscalls, updated_at FROM pod_syscall_watches WHERE cluster_id=$1`, c.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := make(map[string]PodWatchEntry)
	for rows.Next() {
		var key, raw string
		var updatedAt time.Time
		if err := rows.Scan(&key, &raw, &updatedAt); err == nil {
			var selection PodWatchSelection
			if len(raw) > 0 && raw[0] == '{' {
				if err := json.Unmarshal([]byte(raw), &selection); err != nil {
					log.Printf("[store] unmarshal watch for %s: %v", key, err)
					continue
				}
			} else {
				var legacy []string
				if err := json.Unmarshal([]byte(raw), &legacy); err != nil {
					log.Printf("[store] unmarshal watch for %s: %v", key, err)
					continue
				}
				selection.Syscalls = legacy
			}
			m[key] = PodWatchEntry{PodWatchSelection: selection, UpdatedAt: updatedAt}
		}
	}
	return m, nil
}

func (c *Scoped) HideHoneypotEvent(ctx context.Context, ns, honeypot, eventID string) error {
	_, err := c.s.pool.Exec(ctx,
		`INSERT INTO honeypot_hidden_events(cluster_id,namespace,honeypot,event_id)
		 VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
		c.id, ns, honeypot, eventID)
	return err
}

func (c *Scoped) WriteHoneypotEvent(ctx context.Context, ns, honeypot, eventID, ts string, data json.RawMessage) error {
	_, err := c.s.pool.Exec(ctx,
		`INSERT INTO honeypot_events(cluster_id,namespace,honeypot,event_id,ts,data)
		 VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
		c.id, ns, honeypot, eventID, ts, data)
	return err
}

func (c *Scoped) ListHoneypotEvents(ctx context.Context, ns, honeypot string) ([]json.RawMessage, error) {
	return c.listJSONBlobs(ctx,
		`SELECT data FROM honeypot_events
		  WHERE cluster_id=$1 AND namespace=$2 AND honeypot=$3
		  ORDER BY ts ASC, created_at ASC`,
		c.id, ns, honeypot)
}

func (s *Store) SweepOldHoneypotEvents(ctx context.Context) (int64, error) {
	return sweepOldHoneypotEvents(ctx, s.pool)
}

func sweepOldHoneypotEvents(ctx context.Context, db execer) (int64, error) {
	tag, err := db.Exec(ctx,
		`DELETE FROM honeypot_events WHERE created_at < NOW() - $1::interval`,
		fmt.Sprintf("%d seconds", int64(HoneypotEventsTTL.Seconds())))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (c *Scoped) HiddenHoneypotEvents(ctx context.Context, ns, honeypot string) ([]string, error) {
	rows, err := c.s.pool.Query(ctx,
		`SELECT event_id FROM honeypot_hidden_events WHERE cluster_id=$1 AND namespace=$2 AND honeypot=$3`,
		c.id, ns, honeypot)
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
