package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	rollupRefreshLock int64 = 0x77770002
	rollupSettle            = 5 * time.Minute
	rollupClockSkew         = time.Minute
	rollupBatch             = 500
	rollupBudget            = 20 * time.Second
	rollupMinHours          = 6
)

func hourOf(t time.Time) time.Time { return t.UTC().Truncate(time.Hour) }

func hourKey(h time.Time) int32 { return int32(h.Unix() / 3600) }

func rollupBuildable(h, now time.Time) bool {
	return !h.Add(time.Hour + rollupSettle - rollupClockSkew).After(now)
}

func (c *Scoped) invalidateRollupHours(ctx context.Context, stamps ...time.Time) error {
	now := time.Now()
	var hours []time.Time
	var keys []int32
	seen := map[int32]bool{}
	for _, ts := range stamps {
		h := hourOf(ts)
		if k := hourKey(h); rollupBuildable(h, now) && !seen[k] {
			seen[k] = true
			hours = append(hours, h)
			keys = append(keys, k)
		}
	}
	if len(hours) == 0 {
		return nil
	}
	if ready, err := c.s.auditRollupsReady(ctx, c.db()); err != nil || !ready {
		return err
	}
	if c.tx != nil {
		return c.dropRollupMarks(ctx, c.tx, hours, keys)
	}
	tx, err := c.s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err := c.dropRollupMarks(ctx, tx, hours, keys); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (c *Scoped) dropRollupMarks(ctx context.Context, tx pgx.Tx, hours []time.Time, keys []int32) error {
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock_shared(hashtext($1), k) FROM unnest($2::int[]) k ORDER BY k`, c.id, keys); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `DELETE FROM audit_rollup_marks WHERE cluster_id = $1 AND hour = ANY($2)`, c.id, hours)
	return err
}

func rebuildRollupHour(ctx context.Context, tx pgx.Tx, cluster string, h time.Time) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1), $2)`, cluster, hourKey(h)); err != nil {
		return err
	}
	steps := []struct {
		sql  string
		args []any
	}{
		{`DELETE FROM audit_user_hourly WHERE cluster_id = $1 AND hour = $2`, []any{cluster, h}},
		{`INSERT INTO audit_user_hourly (cluster_id, hour, "user", allowed, danger, events, last_seen, ips)
		  SELECT $1::text, $2::timestamptz, COALESCE("user", ''), COALESCE(allowed, TRUE), ` + auditDangerExpr + `,
		         COUNT(*), MAX(ts),
		         COALESCE((ARRAY_AGG(DISTINCT source_ip) FILTER (WHERE source_ip IS NOT NULL AND source_ip != ''))[1:6], '{}')
		    FROM audit_events WHERE cluster_id = $1 AND ts >= $2 AND ts < $3 AND NOT silenced
		   GROUP BY 3, 4, 5`, []any{pgx.QueryExecModeExec, cluster, h, h.Add(time.Hour)}},
		{`INSERT INTO audit_rollup_marks (cluster_id, hour, built_at) VALUES ($1, $2, clock_timestamp())
		  ON CONFLICT (cluster_id, hour) DO UPDATE SET built_at = EXCLUDED.built_at`, []any{cluster, h}},
	}
	for _, st := range steps {
		if _, err := tx.Exec(ctx, st.sql, st.args...); err != nil {
			return fmt.Errorf("rollup %s %s: %w", cluster, h.Format(time.RFC3339), err)
		}
	}
	return nil
}

type rollupTask struct {
	cluster string
	hour    time.Time
}

func (s *Store) RefreshAuditRollups(ctx context.Context) (int, error) {
	ready, err := s.auditRollupsReady(ctx, s.pool)
	if err != nil || !ready {
		return 0, err
	}
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Release()
	var locked bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, rollupRefreshLock).Scan(&locked); err != nil || !locked {
		return 0, err
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, rollupRefreshLock)

	var now time.Time
	if err := conn.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return 0, err
	}
	oldest := hourOf(now.Add(-AuditRetention())).Add(time.Hour)
	newest := hourOf(now.Add(-rollupSettle)).Add(-time.Hour)
	if newest.Before(oldest) {
		return 0, nil
	}
	rows, err := conn.Query(ctx,
		`SELECT c.id, h FROM clusters c CROSS JOIN generate_series($1::timestamptz, $2::timestamptz, interval '1 hour') h
		  WHERE NOT EXISTS (SELECT 1 FROM audit_rollup_marks r WHERE r.cluster_id = c.id AND r.hour = h)
		  ORDER BY h DESC, c.id LIMIT $3`, oldest, newest, rollupBatch)
	if err != nil {
		return 0, err
	}
	tasks, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (rollupTask, error) {
		var t rollupTask
		err := row.Scan(&t.cluster, &t.hour)
		t.hour = t.hour.UTC()
		return t, err
	})
	if err != nil {
		return 0, err
	}
	built := 0
	started := time.Now()
	for _, t := range tasks {
		if err := ctx.Err(); err != nil {
			return built, err
		}
		if time.Since(started) > rollupBudget {
			break
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return built, err
		}
		if err := rebuildRollupHour(ctx, tx, t.cluster, t.hour); err != nil {
			tx.Rollback(context.WithoutCancel(ctx))
			return built, err
		}
		if err := tx.Commit(ctx); err != nil {
			return built, err
		}
		built++
	}
	return built, nil
}

func (s *Store) sweepAuditRollups(ctx context.Context, tx pgx.Tx) error {
	if ready, err := s.tableReady(ctx, tx, "audit_rollup_marks"); err != nil || !ready {
		return err
	}
	retention, known := auditRetentionInterval()
	if !known {
		return nil
	}
	for _, table := range []string{"audit_user_hourly", "audit_rollup_marks"} {
		if _, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE hour < NOW() - $1::interval`, retention); err != nil {
			return err
		}
	}
	return nil
}

func (c *Scoped) missingRollupHours(ctx context.Context, from, to time.Time, limit int) ([]time.Time, error) {
	rows, err := c.db().Query(ctx,
		`SELECT h FROM generate_series($2::timestamptz, $3::timestamptz, interval '1 hour') h
		  WHERE NOT EXISTS (SELECT 1 FROM audit_rollup_marks r WHERE r.cluster_id = $1 AND r.hour = h)
		  ORDER BY h LIMIT $4`, c.id, from, to, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (time.Time, error) {
		var h time.Time
		err := row.Scan(&h)
		return h.UTC(), err
	})
}

type rollupSpan struct {
	start, end time.Time
}

func (c *Scoped) rollupSpanFor(ctx context.Context, q AuditEventQuery) (rollupSpan, bool) {
	if q.Object != nil || q.SourceIP != "" || q.Search != "" || q.Namespace != "" || q.Kind != "" || q.Resource != "" ||
		q.From.IsZero() || q.To.IsZero() {
		return rollupSpan{}, false
	}
	if ready, err := c.s.auditRollupsReady(ctx, c.db()); err != nil || !ready {
		return rollupSpan{}, false
	}
	start := hourOf(q.From)
	if start.Before(q.From) {
		start = start.Add(time.Hour)
	}
	end := hourOf(q.To)
	if current := hourOf(time.Now()); end.After(current) {
		end = current
	}
	if int(end.Sub(start)/time.Hour) < rollupMinHours {
		return rollupSpan{}, false
	}
	gap, err := c.missingRollupHours(ctx, start, end.Add(-time.Hour), 1)
	if err != nil {
		return rollupSpan{}, false
	}
	if len(gap) > 0 {
		end = gap[0]
	}
	if int(end.Sub(start)/time.Hour) < rollupMinHours {
		return rollupSpan{}, false
	}
	return rollupSpan{start: start, end: end}, true
}

func rollupWhere(q AuditEventQuery, span rollupSpan, args []interface{}) (string, []interface{}) {
	where := []string{"cluster_id = $1"}
	args = append(args, span.start, span.end)
	where = append(where, fmt.Sprintf("hour >= $%d", len(args)-1), fmt.Sprintf("hour < $%d", len(args)))
	where, args = userResultFilters(q, "danger", where, args)
	return strings.Join(where, " AND "), args
}

func (c *Scoped) rollupEdges(ctx context.Context, q AuditEventQuery, span rollupSpan, args []interface{}) ([]string, []interface{}) {
	head := q
	head.To = span.start.Add(-time.Microsecond)
	tail := q
	tail.From = span.end
	var edges []string
	for _, part := range []AuditEventQuery{head, tail} {
		if part.To.Before(part.From) {
			continue
		}
		var where string
		where, args = c.auditWhereWith(ctx, part, args)
		edges = append(edges, where)
	}
	return edges, args
}

func rawBucketPart(where string) func(bucket func(string) string) string {
	return func(bucket func(string) string) string {
		return fmt.Sprintf(`SELECT %s AS b, 1 AS t, CASE WHEN %s THEN 1 ELSE 0 END AS d FROM audit_events WHERE %s`,
			bucket("ts"), auditDangerExpr, where)
	}
}

func (c *Scoped) histogram(ctx context.Context, args []interface{}, from time.Time, step time.Duration, buckets int,
	parts []func(bucket func(string) string) string) (map[int][2]int64, error) {
	args = append(args, from, step.Seconds(), buckets)
	n := len(args)
	bucket := func(col string) string {
		return fmt.Sprintf(`LEAST($%d::int - 1, FLOOR(EXTRACT(EPOCH FROM (%s - $%d::timestamptz))::float8 / $%d::float8)::int)`, n, col, n-2, n-1)
	}
	sqls := make([]string, 0, len(parts))
	for _, p := range parts {
		sqls = append(sqls, p(bucket))
	}
	rows, err := c.db().Query(ctx, `SELECT b, SUM(t)::bigint, SUM(d)::bigint FROM (`+strings.Join(sqls, " UNION ALL ")+`) x GROUP BY b`,
		append([]interface{}{pgx.QueryExecModeExec}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int][2]int64{}
	for rows.Next() {
		var b int
		var all, danger int64
		if err := rows.Scan(&b, &all, &danger); err != nil {
			return nil, err
		}
		out[b] = [2]int64{all, danger}
	}
	return out, rows.Err()
}

func (c *Scoped) rollupHistogram(ctx context.Context, q AuditEventQuery, span rollupSpan, buckets int, step time.Duration) (map[int][2]int64, error) {
	args := []interface{}{c.id}
	rollWhere, args := rollupWhere(q, span, args)
	edges, args := c.rollupEdges(ctx, q, span, args)
	parts := []func(func(string) string) string{func(bucket func(string) string) string {
		return fmt.Sprintf(`SELECT %s AS b, events AS t, CASE WHEN danger THEN events ELSE 0 END AS d FROM audit_user_hourly WHERE %s`,
			bucket("(hour + interval '30 minutes')"), rollWhere)
	}}
	for _, edge := range edges {
		parts = append(parts, rawBucketPart(edge))
	}
	return c.histogram(ctx, args, q.From, step, buckets, parts)
}

func (c *Scoped) rollupUserGroups(ctx context.Context, q AuditEventQuery, span rollupSpan, limit, offset int) ([]AuditGroup, error) {
	args := []interface{}{c.id}
	rollWhere, args := rollupWhere(q, span, args)
	edges, args := c.rollupEdges(ctx, q, span, args)
	parts := []string{`SELECT "user" AS k, events AS n, CASE WHEN danger THEN events ELSE 0 END AS d,
	                          CASE WHEN NOT allowed THEN events ELSE 0 END AS den, last_seen AS last, ips
	                     FROM audit_user_hourly WHERE ` + rollWhere}
	for _, edge := range edges {
		parts = append(parts, `SELECT COALESCE("user", ''), 1, CASE WHEN `+auditDangerExpr+` THEN 1 ELSE 0 END,
		                              CASE WHEN COALESCE(allowed, TRUE) = FALSE THEN 1 ELSE 0 END, ts,
		                              CASE WHEN COALESCE(source_ip, '') <> '' THEN ARRAY[source_ip] ELSE '{}'::text[] END
		                         FROM audit_events WHERE `+edge)
	}
	args = append(args, limit, offset)
	rows, err := c.db().Query(ctx, fmt.Sprintf(`WITH x AS MATERIALIZED (%s),
	     g AS (SELECT k, SUM(n)::bigint AS n, SUM(d)::bigint AS d, SUM(den)::bigint AS den, MAX(last) AS last
	             FROM x GROUP BY k ORDER BY 2 DESC, k LIMIT $%d OFFSET $%d),
	     a AS (SELECT x.k, (ARRAY_AGG(DISTINCT ip))[1:6] AS ips FROM x JOIN g ON g.k = x.k, unnest(x.ips) ip GROUP BY x.k)
	   SELECT g.k, g.n, g.d, g.den, g.last, COALESCE(a.ips, '{}') FROM g LEFT JOIN a ON a.k = g.k ORDER BY g.n DESC, g.k`,
		strings.Join(parts, " UNION ALL "), len(args)-1, len(args)),
		append([]interface{}{pgx.QueryExecModeExec}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditGroup{}
	for rows.Next() {
		var g AuditGroup
		if err := rows.Scan(&g.Key, &g.Events, &g.Dangerous, &g.Denied, &g.LastSeen, &g.Others); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
