package store

import (
	"bytes"
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
	ForensicEventTTL = 24 * time.Hour
	BinaryEventTTL   = 24 * time.Hour
	ContainerLogTTL  = 24 * time.Hour

	partitionsAheadHours    = 48
	schemaPartitionedTables = "container_logs, audit_events"
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

func (c *Scoped) InsertAlerts(ctx context.Context, alerts []IncomingAlert) error {
	if len(alerts) == 0 {
		return nil
	}
	rows := make([][]interface{}, 0, len(alerts))
	for _, a := range alerts {
		data := a.Data
		if len(data) == 0 {
			data = json.RawMessage(`{}`)
		}
		ts := a.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		rows = append(rows, []interface{}{
			c.id, ts, a.Source, a.DetType, a.RuleID, a.RuleName, a.Severity,
			a.Namespace, a.Target, a.Syscall, a.Detail, a.Fingerprint, data,
		})
	}
	_, err := c.s.pool.CopyFrom(ctx, pgx.Identifier{"alerts"},
		[]string{"cluster_id", "ts", "source", "det_type", "rule_id", "rule_name", "severity",
			"namespace", "target", "syscall", "detail", "fingerprint", "data"},
		pgx.CopyFromRows(rows))
	return err
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

func (c *Scoped) QueryAuditEventsSince(ctx context.Context, since string, limit int) ([]json.RawMessage, string, error) {
	sinceID, _ := strconv.ParseInt(since, 10, 64)
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := c.s.pool.Query(ctx,
		`SELECT id, data FROM audit_events WHERE cluster_id = $1 AND id > $2 ORDER BY id LIMIT $3`,
		c.id, sinceID, limit)
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

func (c *Scoped) InsertBinaryExecEvent(ctx context.Context, raw json.RawMessage) error {
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
	_, err := c.s.pool.Exec(ctx, `
		INSERT INTO binary_exec_events
		  (cluster_id, event_id, event_hash, ts, ns, pod, pod_uid, pod_ip, container, node, "binary", process, cmdline, data)
		VALUES ($1,NULLIF($2, ''),$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (cluster_id, event_hash) DO NOTHING`,
		c.id, eventID, hex.EncodeToString(hash[:]), ts, ns, pod,
		get("pod_uid", "podUID", "uid"), get("pod_ip", "podIP"),
		get("container", "containerId"), get("node"), get("execpath", "binary"),
		get("process"), get("cmdline"), raw)
	return err
}

func (c *Scoped) QueryBinaryExecEvents(ctx context.Context, q BinaryExecQuery) ([]json.RawMessage, error) {
	if q.Limit <= 0 || q.Limit > 10000 {
		q.Limit = 10000
	}
	query := `SELECT data FROM binary_exec_events WHERE cluster_id = $1 AND ts > NOW() - INTERVAL '24 hours'`
	args := make([]interface{}, 0, 5)
	args = append(args, c.id)
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
	return c.listJSONBlobs(ctx, query, args...)
}

type BinaryEventSummary struct {
	Namespace   string    `json:"namespace"`
	Pod         string    `json:"pod"`
	PodUID      string    `json:"pod_uid,omitempty"`
	PodIP       string    `json:"pod_ip,omitempty"`
	ContainerID string    `json:"container_id,omitempty"`
	Syscall     string    `json:"syscall"`
	Binary      string    `json:"binary"`
	Count       int       `json:"count"`
	LastTS      time.Time `json:"last_ts"`
}

const cursorOverlap = 128

type ForensicEventQuery struct {
	Namespace   string
	Pod         string
	PodUID      string
	ContainerID string
	Syscalls    []string
	SinceID     int64
	Limit       int
}

func withRowID(data json.RawMessage, id int64) json.RawMessage {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return data
	}
	out := make([]byte, 0, len(trimmed)+24)
	out = append(out, '{')
	out = append(out, fmt.Sprintf(`"_rid":%d`, id)...)
	if len(trimmed) > 1 && trimmed[1] != '}' {
		out = append(out, ',')
	}
	return append(out, trimmed[1:]...)
}

type ForensicEventPage struct {
	Events  []json.RawMessage
	NextID  int64
	HasMore bool
}

const (
	initialPageLimit    = 5000
	incrementalPageSize = 500
	maxPageLimit        = 5000
)

func (c *Scoped) QueryFilteredBinaryEvents(ctx context.Context, q ForensicEventQuery) (ForensicEventPage, error) {
	initial := q.SinceID == 0
	if q.Limit <= 0 {
		if initial {
			q.Limit = initialPageLimit
		} else {
			q.Limit = incrementalPageSize
		}
	}
	if q.Limit > maxPageLimit {
		q.Limit = maxPageLimit
	}
	if q.Syscalls == nil {
		q.Syscalls = []string{}
	}
	watermark := q.SinceID
	if initial {
		watermarkQuery := `SELECT COALESCE(MAX(id), 0) FROM binary_exec_events WHERE cluster_id=$1 AND ns=$2 AND pod=$3`
		watermarkArgs := []interface{}{c.id, q.Namespace, q.Pod}
		if q.PodUID != "" {
			watermarkArgs = append(watermarkArgs, q.PodUID)
			watermarkQuery += fmt.Sprintf(" AND (pod_uid=$%d", len(watermarkArgs))
			if q.ContainerID != "" {
				watermarkArgs = append(watermarkArgs, q.ContainerID)
				watermarkQuery += fmt.Sprintf(" OR (pod_uid='' AND COALESCE(NULLIF(container,''), data->>'containerId')=$%d)", len(watermarkArgs))
			}
			watermarkQuery += ")"
		} else if q.ContainerID != "" {
			watermarkArgs = append(watermarkArgs, q.ContainerID)
			watermarkQuery += fmt.Sprintf(" AND COALESCE(NULLIF(container,''), data->>'containerId')=$%d", len(watermarkArgs))
		}
		if err := c.s.pool.QueryRow(ctx, watermarkQuery, watermarkArgs...).Scan(&watermark); err != nil {
			return ForensicEventPage{}, err
		}
		if watermark == 0 {
			return ForensicEventPage{Events: []json.RawMessage{}}, nil
		}
	}

	query := `
		SELECT id, data
		FROM binary_exec_events
		WHERE cluster_id = $1
		  AND ns = $2
		  AND pod = $3`
	args := []interface{}{c.id, q.Namespace, q.Pod}
	if len(q.Syscalls) > 0 {
		args = append(args, q.Syscalls)
		query += fmt.Sprintf(" AND syscall = ANY($%d::text[])", len(args))
	}
	if q.PodUID != "" {
		args = append(args, q.PodUID)
		query += fmt.Sprintf(" AND (pod_uid = $%d", len(args))
		if q.ContainerID != "" {
			args = append(args, q.ContainerID)
			query += fmt.Sprintf(" OR (pod_uid = '' AND COALESCE(NULLIF(container,''), data->>'containerId') = $%d)", len(args))
		}
		query += ")"
	} else if q.ContainerID != "" {
		args = append(args, q.ContainerID)
		query += fmt.Sprintf(" AND COALESCE(NULLIF(container,''), data->>'containerId') = $%d", len(args))
	}
	comparison, order := ">", "ASC"
	bound := watermark
	if initial {
		comparison, order = "<=", "DESC"
	} else {
		bound -= cursorOverlap
		if bound < 0 {
			bound = 0
		}
	}
	args = append(args, bound, q.Limit+1)
	query += fmt.Sprintf(" AND id %s $%d ORDER BY id %s LIMIT $%d", comparison, len(args)-1, order, len(args))
	rows, err := c.s.pool.Query(ctx, query, args...)
	if err != nil {
		return ForensicEventPage{}, err
	}
	defer rows.Close()

	page := ForensicEventPage{Events: make([]json.RawMessage, 0, q.Limit)}
	for rows.Next() {
		var id int64
		var data json.RawMessage
		if err := rows.Scan(&id, &data); err != nil {
			return ForensicEventPage{}, err
		}
		if len(page.Events) == q.Limit {
			page.HasMore = true
			break
		}
		page.Events = append(page.Events, withRowID(data, id))
		if id > page.NextID {
			page.NextID = id
		}
	}
	if err := rows.Err(); err != nil {
		return ForensicEventPage{}, err
	}
	if initial {
		for i, j := 0, len(page.Events)-1; i < j; i, j = i+1, j-1 {
			page.Events[i], page.Events[j] = page.Events[j], page.Events[i]
		}
		page.NextID = watermark
		page.HasMore = false
	} else if page.NextID < q.SinceID {
		page.NextID = q.SinceID
	}
	return page, nil
}

var AlwaysWatchedSyscalls = []string{"execve", "execveat"}

func isAlwaysWatched(syscall string) bool {
	for _, sc := range AlwaysWatchedSyscalls {
		if sc == syscall {
			return true
		}
	}
	return false
}

func WatchedSyscalls(selected PodWatchSelection) []string {
	out := make([]string, 0, len(selected.Syscalls)+len(selected.LSMHooks)+len(selected.Tracepoints)+len(AlwaysWatchedSyscalls))
	out = append(out, AlwaysWatchedSyscalls...)
	out = append(out, selected.Syscalls...)
	out = append(out, selected.LSMHooks...)
	return append(out, selected.Tracepoints...)
}

type PodEventDeleteResult struct {
	Runtime int64
	Anomaly int64
}

func (c *Scoped) DeletePodEvents(ctx context.Context, ns, pod string) (PodEventDeleteResult, error) {
	tx, err := c.s.pool.Begin(ctx)
	if err != nil {
		return PodEventDeleteResult{}, err
	}
	defer tx.Rollback(ctx)

	result := PodEventDeleteResult{}
	tag, err := tx.Exec(ctx,
		`DELETE FROM binary_exec_events WHERE cluster_id = $1 AND ns = $2 AND pod = $3`, c.id, ns, pod)
	if err != nil {
		return PodEventDeleteResult{}, err
	}
	result.Runtime = tag.RowsAffected()

	tag, err = tx.Exec(ctx, `
		DELETE FROM anomaly_events
		WHERE cluster_id = $1
		  AND data->>'src_namespace' = $2 AND data->>'src_pod' = $3`, c.id, ns, pod)
	if err != nil {
		return PodEventDeleteResult{}, err
	}
	result.Anomaly = tag.RowsAffected()

	if err := tx.Commit(ctx); err != nil {
		return PodEventDeleteResult{}, err
	}
	return result, nil
}

func (c *Scoped) QueryBinaryEventSummary(ctx context.Context) ([]BinaryEventSummary, error) {
	rows, err := c.s.pool.Query(ctx, `
		SELECT
			ns,
			pod,
			COALESCE(NULLIF(pod_uid, ''), '') AS pod_uid,
			COALESCE(MAX(NULLIF(pod_ip, '')), '') AS pod_ip,
			COALESCE(NULLIF(container, ''), NULLIF(data->>'containerId', '')) AS container_id,
			COALESCE(syscall, '') AS sc,
			COALESCE(NULLIF("binary", ''), NULLIF(process, ''), COALESCE(syscall, '')) AS bin,
			COUNT(*),
			MAX(ts)
		FROM binary_exec_events
		WHERE ts > NOW() - INTERVAL '24 hours'
		GROUP BY ns, pod, pod_uid, container_id, sc, bin
		ORDER BY ns, pod, MAX(ts) DESC
		LIMIT 10000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []BinaryEventSummary
	for rows.Next() {
		var item BinaryEventSummary
		if err := rows.Scan(&item.Namespace, &item.Pod, &item.PodUID, &item.PodIP, &item.ContainerID, &item.Syscall, &item.Binary, &item.Count, &item.LastTS); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (c *Scoped) InsertForensicEvents(ctx context.Context, ns, pod string, entries []ForensicEntry) error {
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
	_, err := c.s.pool.Exec(ctx,
		`INSERT INTO forensic_events (cluster_id, ns, pod, path, op, size, mtime, sha256, snapped_at)
		 SELECT $1, $2, $3, * FROM unnest($4::text[], $5::text[], $6::bigint[], $7::text[], $8::text[], $9::text[])
		 ON CONFLICT (cluster_id, ns, pod, path, op, snapped_at) DO NOTHING`,
		c.id, ns, pod, paths, ops, sizes, mtimes, shas, snaps)
	return err
}

const maxForensicEntries = 5000

func (c *Scoped) QueryForensicEvents(ctx context.Context, ns, pod string) ([]ForensicEntry, error) {
	rows, err := c.s.pool.Query(ctx,
		`SELECT path, op, size, mtime, sha256, snapped_at FROM (
			SELECT path, op, size, mtime, sha256, snapped_at, ts
			FROM forensic_events
			WHERE cluster_id=$1 AND ns=$2 AND pod=$3 AND ts > NOW() - INTERVAL '24 hours'
			ORDER BY ts DESC
			LIMIT $4
		 ) recent
		 ORDER BY ts`,
		c.id, ns, pod, maxForensicEntries)
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

func (c *Scoped) UpsertForensicWatch(ctx context.Context, ns, pod, source string) error {
	if source != "anomaly" {
		source = "manual"
	}
	_, err := c.s.pool.Exec(ctx, `
		INSERT INTO forensic_watches (cluster_id, key, ns, pod, started_at, active, source)
		VALUES ($1,$2,$3,$4,NOW(),TRUE,$5)
		ON CONFLICT (cluster_id, key) DO UPDATE SET active=TRUE, started_at=NOW(), source=$5`,
		c.id, ns+"/"+pod, ns, pod, source)
	return err
}

func (c *Scoped) DeleteForensicWatch(ctx context.Context, ns, pod string) error {
	_, err := c.s.pool.Exec(ctx,
		`DELETE FROM forensic_watches WHERE cluster_id=$1 AND key=$2`, c.id, ns+"/"+pod)
	return err
}

type ForensicWatch struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Source    string `json:"source"`
}

func (c *Scoped) ListActiveForensicWatches(ctx context.Context) ([]ForensicWatch, error) {
	rows, err := c.s.pool.Query(ctx, `
		SELECT ns, pod, source
		FROM forensic_watches
		WHERE cluster_id = $1 AND active = TRUE
		ORDER BY ns, pod`, c.id)
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

func (c *Scoped) QueryContainerLogs(ctx context.Context, ns, pod, container string, sinceSeconds int64) ([]ContainerLogLine, error) {
	fromTS := time.Now().Add(-time.Duration(sinceSeconds) * time.Second)
	rows, err := c.s.pool.Query(ctx,
		`SELECT ts, log FROM container_logs
		 WHERE cluster_id=$1 AND ns=$2 AND pod=$3 AND container=$4 AND ts > $5
		 ORDER BY ts LIMIT 10000`,
		c.id, ns, pod, container, fromTS)
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

func (c *Scoped) InsertContainerLogEntries(ctx context.Context, node, ns, pod, container string, entries []ContainerLogEntry) error {
	var maxTs time.Time
	rows := make([][]interface{}, 0, len(entries))
	for _, e := range entries {
		if e.Log == "" {
			continue
		}
		if e.Ts.After(maxTs) {
			maxTs = e.Ts
		}
		ts, keep := partitionedTS(e.Ts, ContainerLogTTL)
		if !keep {
			continue
		}
		rows = append(rows, []interface{}{c.id, ts, ns, pod, container, e.Log})
	}
	if maxTs.IsZero() {
		return nil
	}
	key := ns + "/" + pod + "/" + container
	tx, err := c.s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var cur time.Time
	err = tx.QueryRow(ctx,
		`SELECT cursor_ts FROM log_cursors WHERE cluster_id = $1 AND key = $2 FOR UPDATE`,
		c.id, key).Scan(&cur)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err == nil && !cur.Before(maxTs) {
		return nil
	}
	if len(rows) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"container_logs"},
			[]string{"cluster_id", "ts", "ns", "pod", "container", "log"}, pgx.CopyFromRows(rows)); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO log_cursors (cluster_id, key, cursor_ts, node, updated_at)
		 VALUES ($1,$2,$3,NULLIF($4,''),NOW())
		 ON CONFLICT (cluster_id, key) DO UPDATE SET cursor_ts=$3, node=NULLIF($4,''), updated_at=NOW()`,
		c.id, key, maxTs, node); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (c *Scoped) LoadLogCursors(ctx context.Context, node string) (map[string]time.Time, error) {
	q := `SELECT key, cursor_ts FROM log_cursors WHERE cluster_id = $1`
	args := []interface{}{c.id}
	if node != "" {
		args = append(args, node)
		q += fmt.Sprintf(` AND (node = $%d OR node IS NULL)`, len(args))
	}
	rows, err := c.s.pool.Query(ctx, q, args...)
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

func (c *Scoped) PutSnapshotCache(ctx context.Context, key string, data []byte, etag string) error {
	_, err := c.s.pool.Exec(ctx,
		`INSERT INTO snapshot_cache (cluster_id, key, data, etag, updated_at) VALUES ($1,$2,$3,$4,NOW())
		 ON CONFLICT (cluster_id, key) DO UPDATE SET data=$3, etag=$4, updated_at=NOW()`,
		c.id, key, data, etag)
	return err
}

func (c *Scoped) GetSnapshotCache(ctx context.Context, key string) ([]byte, string, error) {
	var data []byte
	var etag string
	err := c.s.pool.QueryRow(ctx,
		`SELECT data, etag FROM snapshot_cache WHERE cluster_id=$1 AND key=$2`,
		c.id, key).Scan(&data, &etag)
	if err != nil {
		return nil, "", err
	}
	return data, etag, nil
}

const (
	sweepBatchSize  = 10000
	sweepMaxBatches = 500
)

func (s *Store) sweepExpiredRows(ctx context.Context, table string, ttl time.Duration) (int64, error) {
	interval := fmt.Sprintf("%d seconds", int64(ttl.Seconds()))
	query := fmt.Sprintf(`
		DELETE FROM %s
		WHERE ctid IN (
			SELECT ctid FROM %s WHERE ts < NOW() - $1::interval LIMIT %d
		)`, table, table, sweepBatchSize)

	var total int64
	for batch := 0; batch < sweepMaxBatches; batch++ {
		tag, err := s.pool.Exec(ctx, query, interval)
		if err != nil {
			return total, err
		}
		n := tag.RowsAffected()
		total += n
		if n < sweepBatchSize {
			break
		}
		if ctx.Err() != nil {
			break
		}
	}
	return total, nil
}

func (s *Store) MaintainPartitions(ctx context.Context) error {
	return maintainPartitions(ctx, s.pool)
}

func maintainPartitions(ctx context.Context, db execer) error {
	retentionHours := int(ContainerLogTTL.Hours()) + 2
	auditHours := int(AuditRetention.Hours()) + 2
	var created, dropped int
	if err := db.QueryRow(ctx,
		`SELECT created, dropped FROM ww_maintain_partitions($1, $2, $3)`,
		retentionHours, partitionsAheadHours, auditHours).Scan(&created, &dropped); err != nil {
		return err
	}
	if created > 0 || dropped > 0 {
		log.Printf("[store] partition maintenance: %d created, %d dropped (logs=%dh audit=%dh)",
			created, dropped, retentionHours, auditHours)
	}
	return nil
}

func sweepIngested(ctx context.Context, db execer) error {
	if err := maintainPartitions(ctx, db); err != nil {
		return fmt.Errorf("partition maintenance (%s ingestion stalls once pre-created "+
			"partitions run out): %w", schemaPartitionedTables, err)
	}

	if tag, err := db.Exec(ctx,
		`DELETE FROM log_cursors WHERE updated_at < NOW() - INTERVAL '48 hours'`); err != nil {
		return fmt.Errorf("log_cursors: %w", err)
	} else if n := tag.RowsAffected(); n > 0 {
		log.Printf("[store] log_cursors retention sweep: %d stale cursor(s) dropped", n)
	}
	return nil
}

func (s *Store) sweepUnpartitioned(ctx context.Context) {
	for _, t := range []struct {
		table string
		ttl   time.Duration
	}{
		{"forensic_events", ForensicEventTTL},
		{"binary_exec_events", BinaryEventTTL},
	} {
		dropped, err := s.sweepExpiredRows(ctx, t.table, t.ttl)
		if err != nil {
			log.Printf("[store] %s retention sweep: %v (dropped %d before failing)", t.table, err, dropped)
			continue
		}
		if dropped > 0 {
			log.Printf("[store] %s retention sweep: %d expired rows dropped", t.table, dropped)
		}
	}
}

func partitionedTS(ts time.Time, ttl time.Duration) (time.Time, bool) {
	now := time.Now()
	if ts.Before(now.Add(-ttl)) {
		return ts, false
	}
	if ts.After(now.Add(time.Hour)) {
		return now, true
	}
	return ts, true
}
