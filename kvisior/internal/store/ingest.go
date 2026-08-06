package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	AuditEventTTL    = 24 * time.Hour
	ForensicEventTTL = 24 * time.Hour
	BinaryEventTTL   = 24 * time.Hour
	ContainerLogTTL  = 24 * time.Hour
)

type IncomingAlert struct {
	Timestamp   time.Time
	Source      string
	DetType     string
	RuleID      string
	RuleName    string
	Severity    string
	Namespace   string
	Target      string
	Syscall     string
	Detail      string
	Fingerprint string
	Data        json.RawMessage
}

func (s *Store) InsertAlerts(ctx context.Context, alerts []IncomingAlert) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, a := range alerts {
		data := a.Data
		if len(data) == 0 {
			data = json.RawMessage(`{}`)
		}
		ts := a.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO alerts
			  (ts, source, det_type, rule_id, rule_name, severity, namespace, target, syscall, detail, fingerprint, data)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			ts, a.Source, a.DetType, a.RuleID, a.RuleName, a.Severity,
			a.Namespace, a.Target, a.Syscall, a.Detail, a.Fingerprint, data); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) LoadAlertRules(ctx context.Context, detType string) ([]json.RawMessage, error) {
	q := `SELECT data FROM runtime_policies WHERE alert_only = TRUE AND enabled = TRUE`
	args := []interface{}{}
	if detType != "" {
		args = append(args, detType)
		q += ` AND det_type = $1`
	}
	return s.listJSONBlobs(ctx, q, args...)
}

func (s *Store) GetEnabledIntegration(ctx context.Context, kind string) (json.RawMessage, bool, error) {
	var cfg json.RawMessage
	err := s.pool.QueryRow(ctx,
		`SELECT config FROM integrations WHERE kind = $1 AND enabled = TRUE`, kind).Scan(&cfg)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {

		return nil, false, err
	}
	return cfg, true, nil
}

func (s *Store) InsertAuditEvent(ctx context.Context, raw json.RawMessage) error {
	var meta struct {
		Timestamp time.Time `json:"timestamp"`
		User      string    `json:"user"`
		Kind      string    `json:"kind"`
		Namespace string    `json:"namespace"`
		Resource  string    `json:"resource"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return fmt.Errorf("audit event meta: %w", err)
	}
	ts := meta.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO audit_events (ts, "user", kind, ns, resource, data)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		ts, meta.User, meta.Kind, meta.Namespace, meta.Resource, raw)
	return err
}

func (s *Store) QueryAuditEventsSince(ctx context.Context, since string, limit int) ([]json.RawMessage, string, error) {
	sinceID, _ := strconv.ParseInt(since, 10, 64)
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, data FROM audit_events WHERE id > $1 ORDER BY id LIMIT $2`,
		sinceID, limit)
	if err != nil {
		return nil, since, err
	}
	defer rows.Close()
	events := make([]json.RawMessage, 0, limit)
	lastID := since
	if lastID == "" {
		lastID = "0"
	}
	for rows.Next() {
		var id int64
		var data json.RawMessage
		if err := rows.Scan(&id, &data); err != nil {
			continue
		}
		events = append(events, data)
		lastID = strconv.FormatInt(id, 10)
	}
	return events, lastID, rows.Err()
}

type ForensicEntry struct {
	Path      string `json:"path"`
	Op        string `json:"op"`
	Size      int64  `json:"size"`
	Mtime     string `json:"mtime"`
	SHA256    string `json:"sha256,omitempty"`
	SnappedAt string `json:"snapped_at"`
}

type BinaryExecQuery struct {
	Namespace string
	Pod       string
	PodUID    string
	Limit     int
}

func (s *Store) InsertBinaryExecEvent(ctx context.Context, raw json.RawMessage) error {
	var ev map[string]json.RawMessage
	if err := json.Unmarshal(raw, &ev); err != nil {
		return fmt.Errorf("binary event JSON: %w", err)
	}
	get := func(names ...string) string {
		for _, name := range names {
			var value string
			if data, ok := ev[name]; ok && json.Unmarshal(data, &value) == nil && value != "" {
				return value
			}
		}
		return ""
	}
	parseTime := func(data json.RawMessage) time.Time {
		var text string
		if json.Unmarshal(data, &text) == nil {
			if ts, err := time.Parse(time.RFC3339Nano, text); err == nil {
				return ts
			}
			if ts, err := time.Parse(time.RFC3339, text); err == nil {
				return ts
			}
		}
		var seconds float64
		if json.Unmarshal(data, &seconds) == nil && seconds > 0 {
			return time.Unix(int64(seconds), 0)
		}
		return time.Now()
	}

	ns := get("namespace", "ns")
	pod := get("pod")
	if ns == "" || pod == "" {
		return nil
	}
	ts := time.Now()
	if data, ok := ev["ts"]; ok {
		ts = parseTime(data)
	} else if data, ok := ev["timestamp"]; ok {
		ts = parseTime(data)
	}
	hash := sha256.Sum256(raw)
	eventID := get("id", "event_id", "eventId")
	_, err := s.pool.Exec(ctx, `
		INSERT INTO binary_exec_events
		  (event_id, event_hash, ts, ns, pod, pod_uid, pod_ip, container, node, "binary", process, cmdline, data)
		VALUES (NULLIF($1, ''),$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT (event_hash) DO NOTHING`,
		eventID, hex.EncodeToString(hash[:]), ts, ns, pod,
		get("pod_uid", "podUID", "uid"), get("pod_ip", "podIP"),
		get("container"), get("node"), get("execpath", "binary"),
		get("process"), get("cmdline"), raw)
	return err
}

func (s *Store) QueryBinaryExecEvents(ctx context.Context, q BinaryExecQuery) ([]json.RawMessage, error) {
	if q.Limit <= 0 || q.Limit > 10000 {
		q.Limit = 10000
	}
	query := `SELECT data FROM binary_exec_events WHERE ts > NOW() - INTERVAL '24 hours'`
	args := make([]interface{}, 0, 4)
	if q.Namespace != "" {
		args = append(args, q.Namespace)
		query += fmt.Sprintf(" AND ns = $%d", len(args))
	}
	if q.Pod != "" {
		args = append(args, q.Pod)
		query += fmt.Sprintf(" AND pod = $%d", len(args))
	}
	if q.PodUID != "" {
		args = append(args, q.PodUID)
		query += fmt.Sprintf(" AND pod_uid = $%d", len(args))
	}
	args = append(args, q.Limit)
	query += fmt.Sprintf(" ORDER BY ts DESC, id DESC LIMIT $%d", len(args))
	return s.listJSONBlobs(ctx, query, args...)
}

func (s *Store) InsertForensicEvents(ctx context.Context, ns, pod string, entries []ForensicEntry) error {
	if len(entries) == 0 {
		return nil
	}
	paths := make([]string, len(entries))
	ops := make([]string, len(entries))
	sizes := make([]int64, len(entries))
	mtimes := make([]string, len(entries))
	shas := make([]string, len(entries))
	snaps := make([]string, len(entries))
	for i, e := range entries {
		paths[i], ops[i], sizes[i] = e.Path, e.Op, e.Size
		mtimes[i], shas[i], snaps[i] = e.Mtime, e.SHA256, e.SnappedAt
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO forensic_events (ns, pod, path, op, size, mtime, sha256, snapped_at)
		 SELECT $1, $2, * FROM unnest($3::text[], $4::text[], $5::bigint[], $6::text[], $7::text[], $8::text[])
		 ON CONFLICT (ns, pod, path, op, snapped_at) DO NOTHING`,
		ns, pod, paths, ops, sizes, mtimes, shas, snaps)
	return err
}

func (s *Store) QueryForensicEvents(ctx context.Context, ns, pod string) ([]ForensicEntry, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT path, op, size, mtime, sha256, snapped_at
		 FROM forensic_events
		 WHERE ns=$1 AND pod=$2 AND ts > NOW() - INTERVAL '24 hours'
		 ORDER BY ts`,
		ns, pod)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := make([]ForensicEntry, 0)
	for rows.Next() {
		var e ForensicEntry
		var sha *string
		if err := rows.Scan(&e.Path, &e.Op, &e.Size, &e.Mtime, &sha, &e.SnappedAt); err != nil {
			continue
		}
		if sha != nil {
			e.SHA256 = *sha
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (s *Store) UpsertForensicWatch(ctx context.Context, ns, pod, source string) error {
	if source != "anomaly" {
		source = "manual"
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO forensic_watches (key, ns, pod, started_at, active, source)
		VALUES ($1,$2,$3,NOW(),TRUE,$4)
		ON CONFLICT (key) DO UPDATE SET active=TRUE, started_at=NOW(), source=$4`,
		ns+"/"+pod, ns, pod, source)
	return err
}

func (s *Store) DeleteForensicWatch(ctx context.Context, ns, pod string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM forensic_watches WHERE key=$1`, ns+"/"+pod)
	return err
}

type ForensicWatch struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Source    string `json:"source"`
}

func (s *Store) ListActiveForensicWatches(ctx context.Context) ([]ForensicWatch, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ns, pod, source
		FROM forensic_watches
		WHERE active = TRUE
		ORDER BY ns, pod`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var watches []ForensicWatch
	for rows.Next() {
		var watch ForensicWatch
		if err := rows.Scan(&watch.Namespace, &watch.Pod, &watch.Source); err != nil {
			return nil, err
		}
		watches = append(watches, watch)
	}
	return watches, rows.Err()
}

type ContainerLogLine struct {
	Timestamp string `json:"timestamp"`
	Log       string `json:"log"`
}

func (s *Store) QueryContainerLogs(ctx context.Context, ns, pod, container string, sinceSeconds int64) ([]ContainerLogLine, error) {
	fromTS := time.Now().Add(-time.Duration(sinceSeconds) * time.Second)
	rows, err := s.pool.Query(ctx,
		`SELECT ts, log FROM container_logs
		 WHERE ns=$1 AND pod=$2 AND container=$3 AND ts > $4
		 ORDER BY ts LIMIT 10000`,
		ns, pod, container, fromTS)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	lines := make([]ContainerLogLine, 0)
	for rows.Next() {
		var ts time.Time
		var l string
		if err := rows.Scan(&ts, &l); err != nil {
			continue
		}
		lines = append(lines, ContainerLogLine{Timestamp: ts.UTC().Format(time.RFC3339Nano), Log: l})
	}
	return lines, rows.Err()
}

type ContainerLogEntry struct {
	Ts  time.Time `json:"ts"`
	Log string    `json:"log"`
}

func (s *Store) InsertContainerLogEntries(ctx context.Context, node, ns, pod, container string, entries []ContainerLogEntry) error {
	var maxTs time.Time
	rows := make([][]interface{}, 0, len(entries))
	for _, e := range entries {
		if e.Log == "" {
			continue
		}
		rows = append(rows, []interface{}{e.Ts, ns, pod, container, e.Log})
		if e.Ts.After(maxTs) {
			maxTs = e.Ts
		}
	}
	if len(rows) == 0 {
		return nil
	}
	key := ns + "/" + pod + "/" + container
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var cur time.Time
	err = tx.QueryRow(ctx,
		`SELECT cursor_ts FROM log_cursors WHERE key = $1 FOR UPDATE`, key).Scan(&cur)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err == nil && !cur.Before(maxTs) {
		return nil
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"container_logs"},
		[]string{"ts", "ns", "pod", "container", "log"}, pgx.CopyFromRows(rows)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO log_cursors (key, cursor_ts, node, updated_at) VALUES ($1,$2,NULLIF($3,''),NOW())
		 ON CONFLICT (key) DO UPDATE SET cursor_ts=$2, node=NULLIF($3,''), updated_at=NOW()`,
		key, maxTs, node); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) LoadLogCursors(ctx context.Context, node string) (map[string]time.Time, error) {
	q, args := `SELECT key, cursor_ts FROM log_cursors`, []interface{}{}
	if node != "" {
		q += ` WHERE node = $1 OR node IS NULL`
		args = append(args, node)
	}
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]time.Time)
	for rows.Next() {
		var key string
		var ts time.Time
		if err := rows.Scan(&key, &ts); err == nil {
			out[key] = ts
		}
	}
	return out, rows.Err()
}

func (s *Store) PutSnapshotCache(ctx context.Context, key string, data []byte, etag string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO snapshot_cache (key, data, etag, updated_at) VALUES ($1,$2,$3,NOW())
		 ON CONFLICT (key) DO UPDATE SET data=$2, etag=$3, updated_at=NOW()`,
		key, data, etag)
	return err
}

func (s *Store) GetSnapshotCache(ctx context.Context, key string) ([]byte, string, error) {
	var data []byte
	var etag string
	err := s.pool.QueryRow(ctx,
		`SELECT data, etag FROM snapshot_cache WHERE key=$1`, key).Scan(&data, &etag)
	if err != nil {
		return nil, "", err
	}
	return data, etag, nil
}

func (s *Store) sweepIngested(ctx context.Context) {
	for _, t := range []struct {
		table string
		ttl   time.Duration
	}{
		{"audit_events", AuditEventTTL},
		{"forensic_events", ForensicEventTTL},
		{"binary_exec_events", BinaryEventTTL},
		{"container_logs", ContainerLogTTL},
	} {
		tag, err := s.pool.Exec(ctx,
			fmt.Sprintf(`DELETE FROM %s WHERE ts < NOW() - $1::interval`, t.table),
			fmt.Sprintf("%d seconds", int64(t.ttl.Seconds())))
		if err != nil {
			log.Printf("[store] %s retention sweep: %v", t.table, err)
			continue
		}
		if n := tag.RowsAffected(); n > 0 {
			log.Printf("[store] %s retention sweep: %d expired rows dropped", t.table, n)
		}
	}

	if tag, err := s.pool.Exec(ctx,
		`DELETE FROM log_cursors WHERE updated_at < NOW() - INTERVAL '48 hours'`); err != nil {
		log.Printf("[store] log_cursors retention sweep: %v", err)
	} else if n := tag.RowsAffected(); n > 0 {
		log.Printf("[store] log_cursors retention sweep: %d stale cursor(s) dropped", n)
	}
}
