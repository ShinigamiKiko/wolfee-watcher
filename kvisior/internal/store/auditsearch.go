package store

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	auditWindowFirst     = 6 * time.Hour
	auditWindowGrowth    = 3
	auditWindowMinSpan   = 24 * time.Hour
	auditUserCandidates  = 1000
	auditUserRawHoursMax = 6
	auditUserCacheTTL    = time.Minute
)

func auditWindows(q AuditEventQuery) [][2]time.Time {
	upper := q.To
	if !q.BeforeTs.IsZero() && (upper.IsZero() || q.BeforeTs.Before(upper)) {
		upper = q.BeforeTs
	}
	if q.From.IsZero() || upper.IsZero() || upper.Sub(q.From) <= auditWindowMinSpan {
		return [][2]time.Time{{q.From, q.To}}
	}
	var out [][2]time.Time
	size := auditWindowFirst
	for cur := upper; !cur.Before(q.From); size *= auditWindowGrowth {
		from := cur.Add(-size)
		if from.Before(q.From) {
			from = q.From
		}
		out = append(out, [2]time.Time{from, cur})
		cur = from.Add(-time.Microsecond)
	}
	return out
}

type rolledUsers struct {
	users []string
	at    time.Time
}

func (c *Scoped) resolveAuditUsers(ctx context.Context, q AuditEventQuery) ([]string, bool, error) {
	if q.From.IsZero() {
		return nil, false, nil
	}
	if ready, err := c.s.auditRollupsReady(ctx, c.db()); err != nil || !ready {
		return nil, false, err
	}
	to := q.To
	if now := time.Now(); to.IsZero() || to.After(now) {
		to = now
	}
	first, last := hourOf(q.From), hourOf(to)
	if last.Before(first) {
		return []string{}, true, nil
	}
	raw, err := c.missingRollupHours(ctx, first, last, auditUserRawHoursMax+1)
	if err != nil || len(raw) > auditUserRawHoursMax {
		return nil, false, err
	}
	pattern := "%" + likeEscape(q.User) + "%"
	rolled, err := c.rolledUsers(ctx, pattern, first, last, raw)
	if err != nil {
		return nil, false, err
	}
	seen := make(map[string]bool, len(rolled))
	for _, u := range rolled {
		seen[u] = true
	}
	for _, h := range raw {
		rows, err := c.db().Query(ctx, `SELECT DISTINCT "user" FROM audit_events
		                    WHERE cluster_id = $1 AND ts >= $2 AND ts < $3 AND "user" ILIKE $4`+c.silencedFilter(ctx),
			pgx.QueryExecModeExec, c.id, h, h.Add(time.Hour), pattern)
		if err != nil {
			return nil, false, err
		}
		users, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return nil, false, err
		}
		for _, u := range users {
			seen[u] = true
		}
		if len(seen) > auditUserCandidates {
			return nil, false, nil
		}
	}
	if len(seen) > auditUserCandidates {
		return nil, false, nil
	}
	users := make([]string, 0, len(seen))
	for u := range seen {
		users = append(users, u)
	}
	return users, true, nil
}

func (c *Scoped) rolledUsers(ctx context.Context, pattern string, first, last time.Time, raw []time.Time) ([]string, error) {
	parts := []string{c.id, strings.ToLower(pattern), first.Format(time.RFC3339), last.Format(time.RFC3339)}
	for _, h := range raw {
		parts = append(parts, h.Format(time.RFC3339))
	}
	key := strings.Join(parts, "\x00")
	if v, ok := c.s.userCache.Load(key); ok {
		if e := v.(rolledUsers); time.Since(e.at) < auditUserCacheTTL {
			return e.users, nil
		}
	}
	rows, err := c.db().Query(ctx, `SELECT DISTINCT "user" FROM audit_user_hourly
	                    WHERE cluster_id = $1 AND hour >= $2 AND hour <= $3 AND "user" ILIKE $4`,
		c.id, first, last, pattern)
	if err != nil {
		return nil, err
	}
	users, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	c.s.userCache.Range(func(k, v any) bool {
		if time.Since(v.(rolledUsers).at) >= auditUserCacheTTL {
			c.s.userCache.Delete(k)
		}
		return true
	})
	c.s.userCache.Store(key, rolledUsers{users: users, at: time.Now()})
	return users, nil
}
