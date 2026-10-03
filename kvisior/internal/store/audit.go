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

const (
	AuditOriginAdmission = "admission"
	AuditOriginAPILog    = "apilog"
	AuditOriginBoth      = "both"

	auditEnrichWindow = 30 * time.Minute
)

var (
	AuditRetention = 14 * 24 * time.Hour

	ErrAuditRuleExists = errors.New("store: audit rule already exists")
)

func SetAuditRetention(d time.Duration) {
	if d >= time.Hour {
		AuditRetention = d
	}
}

func scanAuditRule(row pgx.Row) (auditrules.Rule, error) {
	var r auditrules.Rule
	var spec []byte
	if err := row.Scan(&r.ID, &r.Name, &r.Group, &r.Origin, &r.Enabled, &r.Alert, &r.Severity, &spec, &r.UpdatedBy, &r.UpdatedAt); err != nil {
		return r, err
	}
	if len(spec) > 0 {
		if err := json.Unmarshal(spec, &r.Spec); err != nil {
			return r, fmt.Errorf("audit rule %q spec: %w", r.ID, err)
		}
	}
	r.Normalize()
	return r, nil
}

const auditRuleColumns = `id, name, grp, origin, enabled, alert, severity, spec, updated_by, updated_at`

func (s *Store) ListAuditRules(ctx context.Context) ([]auditrules.Rule, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+auditRuleColumns+` FROM audit_rules ORDER BY (origin = 'builtin'), created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []auditrules.Rule{}
	for rows.Next() {
		r, err := scanAuditRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetAuditRule(ctx context.Context, id string) (auditrules.Rule, bool, error) {
	r, err := scanAuditRule(s.pool.QueryRow(ctx,
		`SELECT `+auditRuleColumns+` FROM audit_rules WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return r, false, nil
	}
	return r, err == nil, err
}

func (s *Store) AuditRulesStamp(ctx context.Context) (string, error) {
	var n int
	var latest *time.Time
	if err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*), MAX(updated_at) FROM audit_rules`).Scan(&n, &latest); err != nil {
		return "", err
	}
	if latest == nil {
		return fmt.Sprintf("%d", n), nil
	}
	return fmt.Sprintf("%d/%d", n, latest.UnixNano()), nil
}

func (s *Store) CreateAuditRule(ctx context.Context, r auditrules.Rule) error {
	spec, err := json.Marshal(r.Spec)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO audit_rules (id, name, grp, origin, enabled, alert, severity, spec, updated_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		r.ID, r.Name, r.Group, r.Origin, r.Enabled, r.Alert, r.Severity, spec, r.UpdatedBy)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrAuditRuleExists
	}
	return err
}

func (s *Store) UpdateAuditRule(ctx context.Context, r auditrules.Rule) (bool, error) {
	spec, err := json.Marshal(r.Spec)
	if err != nil {
		return false, err
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE audit_rules
		    SET name = $2, enabled = $3, alert = $4, severity = $5, spec = $6, updated_by = $7, updated_at = NOW()
		  WHERE id = $1`,
		r.ID, r.Name, r.Enabled, r.Alert, r.Severity, spec, r.UpdatedBy)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) DeleteAuditRule(ctx context.Context, id string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM audit_rules WHERE id = $1`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) RestoreBuiltinAuditRules(ctx context.Context, by string) (int, error) {
	restored := 0
	for _, r := range auditrules.BuiltinRules() {
		r.UpdatedBy = by
		err := s.CreateAuditRule(ctx, r)
		if errors.Is(err, ErrAuditRuleExists) {
			continue
		}
		if err != nil {
			return restored, err
		}
		restored++
	}
	return restored, nil
}

type AuditRuleStat struct {
	Violations int        `json:"violations"`
	Hits       int64      `json:"hits"`
	LastSeen   *time.Time `json:"lastSeen,omitempty"`
}

func (c *Scoped) AuditRuleStats(ctx context.Context) (map[string]AuditRuleStat, error) {
	rows, err := c.s.pool.Query(ctx,
		`SELECT rule_id, COUNT(*), COALESCE(SUM(hits), 0), MAX(last_seen)
		   FROM audit_violations WHERE cluster_id = $1 GROUP BY rule_id`, c.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]AuditRuleStat{}
	for rows.Next() {
		var id string
		var st AuditRuleStat
		if err := rows.Scan(&id, &st.Violations, &st.Hits, &st.LastSeen); err != nil {
			return nil, err
		}
		out[id] = st
	}
	return out, rows.Err()
}

type AuditViolationWrite struct {
	RuleID      string
	RuleName    string
	Sev         string
	Kind        string
	Resource    string
	Namespace   string
	Name        string
	Actor       string
	SourceIP    string
	Fingerprint string
	Data        json.RawMessage
}

func (c *Scoped) WriteAuditViolation(ctx context.Context, v AuditViolationWrite) error {
	_, err := c.s.pool.Exec(ctx,
		`INSERT INTO audit_violations
		   (cluster_id, rule_id, rule_name, sev, kind, resource, namespace, name, actor, source_ip, fingerprint, data, last_seen)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW())
		 ON CONFLICT (cluster_id, fingerprint) WHERE fingerprint != '' DO UPDATE SET
		    data      = EXCLUDED.data,
		    rule_name = EXCLUDED.rule_name,
		    sev       = EXCLUDED.sev,
		    source_ip = CASE WHEN EXCLUDED.source_ip != '' THEN EXCLUDED.source_ip ELSE audit_violations.source_ip END,
		    hits      = audit_violations.hits + 1,
		    last_seen = NOW(),
		    state = CASE
		              WHEN audit_violations.state IN ('FP','ACK','DISMISSED')
		                   AND audit_violations.state_expires_at IS NOT NULL
		                   AND audit_violations.state_expires_at < NOW()
		              THEN 'ACTIVE'
		              ELSE audit_violations.state
		            END,
		    state_expires_at = CASE
		              WHEN audit_violations.state IN ('FP','ACK','DISMISSED')
		                   AND audit_violations.state_expires_at IS NOT NULL
		                   AND audit_violations.state_expires_at < NOW()
		              THEN NULL
		              ELSE audit_violations.state_expires_at
		            END`,
		c.id, v.RuleID, v.RuleName, v.Sev, v.Kind, v.Resource, v.Namespace, v.Name, v.Actor, v.SourceIP, v.Fingerprint, v.Data)
	return err
}

type AuditEventInsert struct {
	Raw    json.RawMessage
	Event  *auditrules.Event
	Origin string
	RuleID string
	Sev    string
}

func nullable(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func (c *Scoped) InsertAuditEvents(ctx context.Context, items []AuditEventInsert) error {
	rows := make([][]interface{}, 0, len(items))
	for _, it := range items {
		ev := it.Event
		ts := ev.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		ts, keep := partitionedTS(ts, AuditRetention)
		if !keep {
			continue
		}
		rows = append(rows, []interface{}{
			c.id, ts, ev.User, ev.Kind, ev.Namespace, ev.Resource, it.Raw,
			nullable(ev.ID), ev.Name, nullable(ev.SourceIP()), ev.IsAllowed(), it.Origin,
			nullable(it.RuleID), nullable(it.Sev),
		})
	}
	if len(rows) == 0 {
		return nil
	}
	_, err := c.s.pool.CopyFrom(ctx, pgx.Identifier{"audit_events"},
		[]string{"cluster_id", "ts", "user", "kind", "ns", "resource", "data",
			"event_uid", "name", "source_ip", "allowed", "origin", "rule_id", "sev"},
		pgx.CopyFromRows(rows))
	return err
}

type AuditEnrichment struct {
	EventUID   string
	SourceIPs  []string
	UserAgent  string
	AuditID    string
	StatusCode int32
	Allowed    bool
}

type AuditEventRow struct {
	ID     int64           `json:"id"`
	Ts     time.Time       `json:"ts"`
	RuleID string          `json:"ruleId,omitempty"`
	Sev    string          `json:"sev,omitempty"`
	Origin string          `json:"origin,omitempty"`
	Data   json.RawMessage `json:"data"`
}

func (c *Scoped) EnrichAuditEvent(ctx context.Context, en AuditEnrichment) (AuditEventRow, bool, error) {
	patch, err := json.Marshal(map[string]interface{}{
		"sourceIPs":  en.SourceIPs,
		"userAgent":  en.UserAgent,
		"auditID":    en.AuditID,
		"statusCode": en.StatusCode,
		"allowed":    en.Allowed,
	})
	if err != nil {
		return AuditEventRow{}, false, err
	}
	ip := ""
	if len(en.SourceIPs) > 0 {
		ip = en.SourceIPs[0]
	}
	var row AuditEventRow
	var ruleID, sev *string
	err = c.s.pool.QueryRow(ctx,
		`UPDATE audit_events
		    SET source_ip = $3, allowed = $4, origin = $5, data = data || $6::jsonb
		  WHERE cluster_id = $1 AND event_uid = $2 AND ts > $7 AND origin = $8
		 RETURNING id, ts, rule_id, sev, data`,
		c.id, en.EventUID, nullable(ip), en.Allowed, AuditOriginBoth, patch,
		time.Now().Add(-auditEnrichWindow), AuditOriginAdmission,
	).Scan(&row.ID, &row.Ts, &ruleID, &sev, &row.Data)
	if errors.Is(err, pgx.ErrNoRows) {
		return row, false, nil
	}
	if err != nil {
		return row, false, err
	}
	row.Origin = AuditOriginBoth
	if ruleID != nil {
		row.RuleID = *ruleID
	}
	if sev != nil {
		row.Sev = *sev
	}
	return row, true, nil
}

func (c *Scoped) MarkAuditEventRule(ctx context.Context, id int64, ts time.Time, ruleID, sev string) error {
	_, err := c.s.pool.Exec(ctx,
		`UPDATE audit_events SET rule_id = $4, sev = $5 WHERE cluster_id = $1 AND id = $2 AND ts = $3`,
		c.id, id, ts, ruleID, sev)
	return err
}

type AuditEventQuery struct {
	From       time.Time
	To         time.Time
	User       string
	Namespace  string
	Kind       string
	Resource   string
	SourceIP   string
	Result     string
	Search     string
	DangerOnly bool
	BeforeTs   time.Time
	BeforeID   int64
	Limit      int
}

const auditDangerExpr = `(rule_id IS NOT NULL OR COALESCE(allowed, TRUE) = FALSE)`

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func (c *Scoped) auditWhere(q AuditEventQuery) (string, []interface{}) {
	args := []interface{}{c.id}
	where := []string{"cluster_id = $1"}
	add := func(cond string, v interface{}) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if !q.From.IsZero() {
		add("ts >= $%d", q.From)
	}
	if !q.To.IsZero() {
		add("ts <= $%d", q.To)
	}
	if q.User != "" {
		add(`"user" ILIKE $%d`, "%"+likeEscape(q.User)+"%")
	}
	if q.Namespace != "" {
		add("ns = $%d", q.Namespace)
	}
	if q.Kind != "" {
		add("kind = $%d", q.Kind)
	}
	if q.Resource != "" {
		add("resource ILIKE $%d", "%"+likeEscape(q.Resource)+"%")
	}
	if q.SourceIP != "" {
		add("source_ip LIKE $%d", likeEscape(q.SourceIP)+"%")
	}
	if q.Search != "" {
		args = append(args, "%"+likeEscape(q.Search)+"%")
		n := len(args)
		where = append(where, fmt.Sprintf(
			`("user" ILIKE $%d OR name ILIKE $%d OR ns ILIKE $%d OR resource ILIKE $%d OR source_ip ILIKE $%d OR kind ILIKE $%d)`,
			n, n, n, n, n, n))
	}
	switch q.Result {
	case auditrules.ResultAllowed:
		where = append(where, "COALESCE(allowed, TRUE) = TRUE")
	case auditrules.ResultDenied:
		where = append(where, "COALESCE(allowed, TRUE) = FALSE")
	}
	if q.DangerOnly {
		where = append(where, auditDangerExpr)
	}
	return strings.Join(where, " AND "), args
}

func (c *Scoped) QueryAuditEvents(ctx context.Context, q AuditEventQuery) ([]AuditEventRow, error) {
	limit := q.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	where, args := c.auditWhere(q)
	if !q.BeforeTs.IsZero() {
		args = append(args, q.BeforeTs, q.BeforeID)
		where += fmt.Sprintf(" AND (ts, id) < ($%d, $%d)", len(args)-1, len(args))
	}
	args = append(args, limit)
	rows, err := c.s.pool.Query(ctx,
		`SELECT id, ts, COALESCE(rule_id, ''), COALESCE(sev, ''), COALESCE(origin, ''), data
		   FROM audit_events WHERE `+where+
			fmt.Sprintf(` ORDER BY ts DESC, id DESC LIMIT $%d`, len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AuditEventRow, 0, limit)
	for rows.Next() {
		var r AuditEventRow
		if err := rows.Scan(&r.ID, &r.Ts, &r.RuleID, &r.Sev, &r.Origin, &r.Data); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type AuditBucket struct {
	Start     time.Time `json:"start"`
	Total     int64     `json:"total"`
	Dangerous int64     `json:"dangerous"`
}

func (c *Scoped) AuditEventHistogram(ctx context.Context, q AuditEventQuery, buckets int) ([]AuditBucket, int64, error) {
	if buckets <= 0 || buckets > 200 {
		buckets = 24
	}
	span := q.To.Sub(q.From)
	if span <= 0 {
		return nil, 0, errors.New("store: histogram needs a time range")
	}
	step := span / time.Duration(buckets)
	where, args := c.auditWhere(q)
	args = append(args, q.From, step.Seconds(), buckets)
	n := len(args)
	rows, err := c.s.pool.Query(ctx, fmt.Sprintf(
		`SELECT LEAST($%d::int - 1, FLOOR(EXTRACT(EPOCH FROM (ts - $%d::timestamptz))::float8 / $%d::float8)::int) AS b,
		        COUNT(*), COUNT(*) FILTER (WHERE %s)
		   FROM audit_events WHERE %s GROUP BY b`, n, n-2, n-1, auditDangerExpr, where), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]AuditBucket, buckets)
	for i := range out {
		out[i].Start = q.From.Add(time.Duration(i) * step)
	}
	var total int64
	for rows.Next() {
		var b int
		var all, danger int64
		if err := rows.Scan(&b, &all, &danger); err != nil {
			return nil, 0, err
		}
		if b < 0 || b >= buckets {
			continue
		}
		out[b].Total, out[b].Dangerous = all, danger
		total += all
	}
	return out, total, rows.Err()
}

type AuditGroup struct {
	Key       string    `json:"key"`
	Events    int64     `json:"events"`
	Dangerous int64     `json:"dangerous"`
	Denied    int64     `json:"denied"`
	Others    []string  `json:"others"`
	LastSeen  time.Time `json:"lastSeen"`
}

func (c *Scoped) AuditEventGroups(ctx context.Context, q AuditEventQuery, by string, limit int) ([]AuditGroup, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	key, other := `"user"`, `source_ip`
	if by == "object" {
		key = `resource || '/' || CASE WHEN COALESCE(ns, '') = '' THEN '' ELSE ns || '/' END || COALESCE(NULLIF(name, ''), '*')`
		other = `"user"`
	}
	where, args := c.auditWhere(q)
	args = append(args, limit)
	rows, err := c.s.pool.Query(ctx, fmt.Sprintf(
		`SELECT %s AS k, COUNT(*), COUNT(*) FILTER (WHERE %s),
		        COUNT(*) FILTER (WHERE COALESCE(allowed, TRUE) = FALSE),
		        COALESCE((ARRAY_AGG(DISTINCT %s) FILTER (WHERE %s IS NOT NULL AND %s != ''))[1:6], '{}'),
		        MAX(ts)
		   FROM audit_events WHERE %s GROUP BY k ORDER BY 2 DESC LIMIT $%d`,
		key, auditDangerExpr, other, other, other, where, len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditGroup{}
	for rows.Next() {
		var g AuditGroup
		if err := rows.Scan(&g.Key, &g.Events, &g.Dangerous, &g.Denied, &g.Others, &g.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (c *Scoped) AttachAuditViolationSource(ctx context.Context, eventUID, sourceIP string, data json.RawMessage) error {
	if eventUID == "" {
		return nil
	}
	_, err := c.s.pool.Exec(ctx,
		`UPDATE audit_violations
		    SET source_ip = $3, data = $4
		  WHERE cluster_id = $1 AND data->>'id' = $2 AND last_seen > $5`,
		c.id, eventUID, sourceIP, data, time.Now().Add(-auditEnrichWindow))
	return err
}

type AuditSource struct {
	Origin   string    `json:"origin"`
	LastSeen time.Time `json:"lastSeen"`
	Events   int64     `json:"events"`
}

func (c *Scoped) AuditSources(ctx context.Context) ([]AuditSource, error) {
	rows, err := c.s.pool.Query(ctx,
		`SELECT COALESCE(origin, $3), MAX(ts), COUNT(*)
		   FROM audit_events WHERE cluster_id = $1 AND ts > $2 GROUP BY 1`,
		c.id, time.Now().Add(-time.Hour), AuditOriginAdmission)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditSource{}
	for rows.Next() {
		var s AuditSource
		if err := rows.Scan(&s.Origin, &s.LastSeen, &s.Events); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
