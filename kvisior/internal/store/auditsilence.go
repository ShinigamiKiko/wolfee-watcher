package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/wolfee-watcher/pkg/auditrules"
)

const (
	AuditSilenceMaxDuration = 90 * 24 * time.Hour
	auditSilenceFieldMax    = 512
	auditSilenceReasonMax   = 500
	auditSilenceListMax     = 500
	silencedEventsPageMax   = 500
	silenceTableRecheck     = 30 * time.Second
)

var ErrAuditSilenceInvalid = errors.New("invalid silence")

type tableState struct {
	ready     atomic.Bool
	checkedAt atomic.Int64
}

func (s *Store) table(name string) *tableState {
	v, _ := s.tables.LoadOrStore(name, &tableState{})
	return v.(*tableState)
}

func (s *Store) tableReady(ctx context.Context, db auditDB, name string) (bool, error) {
	t := s.table(name)
	if t.ready.Load() {
		return true, nil
	}
	now := time.Now().UnixNano()
	if last := t.checkedAt.Load(); last != 0 && time.Duration(now-last) < silenceTableRecheck {
		return false, nil
	}
	var present bool
	if err := db.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&present); err != nil {
		return false, err
	}
	t.checkedAt.Store(now)
	if present {
		t.ready.Store(true)
	}
	return present, nil
}

func (s *Store) auditSilencesReady(ctx context.Context, db auditDB) (bool, error) {
	return s.tableReady(ctx, db, "audit_silenced_events")
}

func (s *Store) auditRollupsReady(ctx context.Context, db auditDB) (bool, error) {
	return s.tableReady(ctx, db, "audit_rollup_marks")
}

type AuditSilence struct {
	ID        int64      `json:"id"`
	Action    string     `json:"action,omitempty"`
	Object    string     `json:"object,omitempty"`
	User      string     `json:"user,omitempty"`
	SourceIP  string     `json:"sourceIP,omitempty"`
	Reason    string     `json:"reason,omitempty"`
	CreatedBy string     `json:"createdBy,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	Active    bool       `json:"active"`
	Hits      int64      `json:"hits"`
	LastHitAt *time.Time `json:"lastHitAt,omitempty"`
}

type auditSilenceTarget struct {
	action, object, user, ip string
}

func (s *AuditSilence) Normalize() error {
	s.Action = strings.ToLower(strings.TrimSpace(s.Action))
	s.Object = strings.TrimSpace(s.Object)
	s.User = strings.TrimSpace(s.User)
	s.SourceIP = strings.TrimSpace(s.SourceIP)
	s.Reason = strings.TrimSpace(s.Reason)
	if s.Action == "" && s.Object == "" && s.User == "" && s.SourceIP == "" {
		return fmt.Errorf("%w: set at least one of action, object, user or source IP", ErrAuditSilenceInvalid)
	}
	for name, value := range map[string]string{"action": s.Action, "object": s.Object, "user": s.User, "source IP": s.SourceIP} {
		if len(value) > auditSilenceFieldMax || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
			return fmt.Errorf("%w: %s is too long or not valid text", ErrAuditSilenceInvalid, name)
		}
	}
	if len(s.Reason) > auditSilenceReasonMax || !utf8.ValidString(s.Reason) || strings.ContainsRune(s.Reason, 0) {
		return fmt.Errorf("%w: reason is longer than %d characters or not valid text", ErrAuditSilenceInvalid, auditSilenceReasonMax)
	}
	if strings.ContainsAny(s.Action, " */") {
		return fmt.Errorf("%w: action is a single verb such as create, delete or exec", ErrAuditSilenceInvalid)
	}
	if s.SourceIP != "" {
		if strings.Contains(s.SourceIP, "/") {
			_, network, err := net.ParseCIDR(s.SourceIP)
			if err != nil {
				return fmt.Errorf("%w: source IP %q is not an address or CIDR", ErrAuditSilenceInvalid, s.SourceIP)
			}
			s.SourceIP = network.String()
		} else if ip := net.ParseIP(s.SourceIP); ip == nil {
			return fmt.Errorf("%w: source IP %q is not an address or CIDR", ErrAuditSilenceInvalid, s.SourceIP)
		} else {
			s.SourceIP = ip.String()
		}
	}
	return nil
}

func (s AuditSilence) matches(t auditSilenceTarget) bool {
	if s.Action != "" && s.Action != t.action {
		return false
	}
	if s.Object != "" && !globMatch(s.Object, t.object) {
		return false
	}
	if s.User != "" && !globMatch(s.User, t.user) {
		return false
	}
	if s.SourceIP != "" && !ipMatches(s.SourceIP, t.ip) {
		return false
	}
	return true
}

func ipMatches(rule, value string) bool {
	ip := net.ParseIP(value)
	if ip == nil {
		return false
	}
	if strings.Contains(rule, "/") {
		_, network, err := net.ParseCIDR(rule)
		return err == nil && network.Contains(ip)
	}
	want := net.ParseIP(rule)
	return want != nil && want.Equal(ip)
}

func globMatch(pattern, value string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == value
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(value, parts[0]) {
		return false
	}
	value = value[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, part := range parts[1 : len(parts)-1] {
		at := strings.Index(value, part)
		if at < 0 {
			return false
		}
		value = value[at+len(part):]
	}
	return len(value) >= len(last) && strings.HasSuffix(value, last)
}

func auditObjectText(resource, namespace, name string) string {
	parts := []string{resource}
	if namespace != "" {
		parts = append(parts, namespace)
	}
	if name != "" {
		parts = append(parts, name)
	}
	return strings.Join(parts, "/")
}

func eventTarget(ev *auditrules.Event) auditSilenceTarget {
	return auditSilenceTarget{
		action: strings.ToLower(ev.Kind),
		object: auditObjectText(ev.Resource, ev.Namespace, ev.Name),
		user:   ev.User,
		ip:     ev.SourceIP(),
	}
}

func (c *Scoped) activeAuditSilences(ctx context.Context) ([]AuditSilence, error) {
	ready, err := c.s.auditSilencesReady(ctx, c.db())
	if err != nil || !ready {
		return nil, err
	}
	rows, err := c.db().Query(ctx,
		`SELECT id, action, object, actor, source_ip FROM audit_silences
		  WHERE cluster_id = $1 AND (expires_at IS NULL OR expires_at > clock_timestamp())
		  ORDER BY id`, c.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditSilence
	for rows.Next() {
		var s AuditSilence
		if err := rows.Scan(&s.ID, &s.Action, &s.Object, &s.User, &s.SourceIP); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func firstSilence(silences []AuditSilence, ev *auditrules.Event) int64 {
	if len(silences) == 0 {
		return 0
	}
	target := eventTarget(ev)
	for _, s := range silences {
		if s.matches(target) {
			return s.ID
		}
	}
	return 0
}

type silencedRow struct {
	uid, origin, ruleID, sev string
	ts                       time.Time
	ev                       *auditrules.Event
	data                     json.RawMessage
}

func (c *Scoped) storeSilencedEvent(ctx context.Context, silence int64, r silencedRow) error {
	_, err := c.db().Exec(ctx,
		`INSERT INTO audit_silenced_events
		   (cluster_id, silence_id, event_uid, ts, kind, resource, ns, name, "user", source_ip, origin, rule_id, sev, data)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		 ON CONFLICT (cluster_id, event_uid) DO NOTHING`,
		c.id, silence, r.uid, r.ts, r.ev.Kind, r.ev.Resource, r.ev.Namespace, r.ev.Name, r.ev.User,
		nullable(r.ev.SourceIP()), r.origin, nullable(r.ruleID), nullable(r.sev), string(r.data))
	return err
}

func (c *Scoped) silenceStoredEvent(ctx context.Context, row *AuditEventRow, uid string) error {
	ready, err := c.s.auditSilencesReady(ctx, c.db())
	if err != nil || !ready {
		return err
	}
	ev := &auditrules.Event{}
	if err := json.Unmarshal(row.Data, ev); err != nil {
		return nil
	}
	tag, err := c.db().Exec(ctx,
		`UPDATE audit_silenced_events SET data = $3, "user" = $4, source_ip = $5, origin = $6, rule_id = $7, sev = $8
		  WHERE cluster_id = $1 AND event_uid = $2`,
		c.id, uid, string(row.Data), ev.User, nullable(ev.SourceIP()), row.Origin, nullable(row.RuleID), nullable(row.Sev))
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		row.Silenced = true
		return nil
	}
	silences, err := c.activeAuditSilences(ctx)
	if err != nil {
		return err
	}
	id := firstSilence(silences, ev)
	if id == 0 {
		return nil
	}
	if err := c.storeSilencedEvent(ctx, id, silencedRow{uid: uid, origin: row.Origin, ruleID: row.RuleID, sev: row.Sev, ts: row.Ts, ev: ev, data: row.Data}); err != nil {
		return err
	}
	if ready, err := c.s.auditRollupsReady(ctx, c.db()); err != nil {
		return err
	} else if ready {
		if _, err := c.db().Exec(ctx, `UPDATE audit_events SET silenced = TRUE WHERE cluster_id = $1 AND id = $2 AND ts = $3`,
			pgx.QueryExecModeExec, c.id, row.ID, row.Ts); err != nil {
			return err
		}
		if err := c.invalidateRollupHours(ctx, row.Ts); err != nil {
			return err
		}
	}
	row.Silenced, row.NewlySilenced = true, true
	return nil
}

func (c *Scoped) silencedFilter(ctx context.Context) string {
	if ready, err := c.s.auditRollupsReady(ctx, c.db()); err == nil && ready {
		return ` AND NOT silenced`
	}
	if ready, err := c.s.auditSilencesReady(ctx, c.db()); err != nil || !ready {
		return ""
	}
	return ` AND NOT EXISTS (SELECT 1 FROM audit_silenced_events se WHERE se.cluster_id = audit_events.cluster_id AND se.event_uid = audit_events.event_uid)`
}

const auditSilenceCols = `s.id, s.action, s.object, s.actor, s.source_ip, s.reason, s.created_by, s.created_at, s.expires_at,
	(s.expires_at IS NULL OR s.expires_at > clock_timestamp())`

func scanAuditSilence(row pgx.Row, s *AuditSilence, extra ...any) error {
	return row.Scan(append([]any{&s.ID, &s.Action, &s.Object, &s.User, &s.SourceIP, &s.Reason, &s.CreatedBy,
		&s.CreatedAt, &s.ExpiresAt, &s.Active}, extra...)...)
}

func (c *Scoped) ListAuditSilences(ctx context.Context) ([]AuditSilence, error) {
	rows, err := c.s.pool.Query(ctx,
		`SELECT `+auditSilenceCols+`, COALESCE(h.hits, 0), h.last_hit
		   FROM audit_silences s
		   LEFT JOIN LATERAL (SELECT COUNT(*) AS hits, MAX(silenced_at) AS last_hit
		                        FROM audit_silenced_events e WHERE e.silence_id = s.id) h ON TRUE
		  WHERE s.cluster_id = $1
		  ORDER BY (s.expires_at IS NULL OR s.expires_at > clock_timestamp()) DESC, s.created_at DESC
		  LIMIT $2`, c.id, auditSilenceListMax)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditSilence{}
	for rows.Next() {
		var s AuditSilence
		if err := scanAuditSilence(rows, &s, &s.Hits, &s.LastHitAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (c *Scoped) CreateAuditSilence(ctx context.Context, s AuditSilence, duration time.Duration) (AuditSilence, error) {
	if err := s.Normalize(); err != nil {
		return s, err
	}
	if duration < 0 || duration > AuditSilenceMaxDuration {
		return s, fmt.Errorf("%w: duration must be between 0 and %d days", ErrAuditSilenceInvalid, int(AuditSilenceMaxDuration.Hours()/24))
	}
	var expires *string
	if duration > 0 {
		v := fmt.Sprintf("%d seconds", int64(duration.Seconds()))
		expires = &v
	}
	var out AuditSilence
	err := scanAuditSilence(c.s.pool.QueryRow(ctx,
		`INSERT INTO audit_silences AS s (cluster_id, action, object, actor, source_ip, reason, created_by, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, clock_timestamp() + $8::interval)
		 RETURNING `+auditSilenceCols,
		c.id, s.Action, s.Object, s.User, s.SourceIP, s.Reason, s.CreatedBy, expires), &out)
	if err == nil {
		c.s.table("audit_silenced_events").ready.Store(true)
	}
	return out, err
}

func (c *Scoped) EndAuditSilence(ctx context.Context, id int64) (bool, error) {
	tag, err := c.s.pool.Exec(ctx,
		`UPDATE audit_silences SET expires_at = clock_timestamp()
		  WHERE cluster_id = $1 AND id = $2 AND (expires_at IS NULL OR expires_at > clock_timestamp())`, c.id, id)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() > 0 {
		return true, nil
	}
	var exists bool
	err = c.s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_silences WHERE cluster_id = $1 AND id = $2)`, c.id, id).Scan(&exists)
	return exists, err
}

func (c *Scoped) DeleteAuditSilence(ctx context.Context, id int64) (bool, error) {
	ready, err := c.s.auditRollupsReady(ctx, c.s.pool)
	if err != nil {
		return false, err
	}
	if !ready {
		tag, err := c.s.pool.Exec(ctx, `DELETE FROM audit_silences WHERE cluster_id = $1 AND id = $2`, c.id, id)
		return tag.RowsAffected() > 0, err
	}
	tx, err := c.s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	scoped := &Scoped{s: c.s, id: c.id, tx: tx}
	if err := scoped.unsilenceEvents(ctx, id); err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM audit_silences WHERE cluster_id = $1 AND id = $2`, c.id, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, tx.Commit(ctx)
}

func (c *Scoped) unsilenceEvents(ctx context.Context, silence int64) error {
	rows, err := c.db().Query(ctx,
		`UPDATE audit_events e SET silenced = FALSE
		   FROM audit_silenced_events se
		  WHERE se.cluster_id = $1 AND se.silence_id = $2
		    AND e.cluster_id = se.cluster_id AND e.event_uid = se.event_uid AND e.ts = se.ts AND e.silenced
		 RETURNING e.ts`, c.id, silence)
	if err != nil {
		return err
	}
	stamps, err := pgx.CollectRows(rows, pgx.RowTo[time.Time])
	if err != nil {
		return err
	}
	return c.invalidateRollupHours(ctx, stamps...)
}

type SilencedEventRow struct {
	AuditEventRow
	SilenceID  int64     `json:"silenceId"`
	SilencedAt time.Time `json:"silencedAt"`
}

func (c *Scoped) ListSilencedEvents(ctx context.Context, silence, before int64, limit int) ([]SilencedEventRow, error) {
	if limit <= 0 || limit > silencedEventsPageMax {
		limit = 200
	}
	rows, err := c.s.pool.Query(ctx,
		`SELECT id, ts, COALESCE(rule_id, ''), COALESCE(sev, ''), COALESCE(origin, ''), data, silence_id, silenced_at
		   FROM audit_silenced_events
		  WHERE cluster_id = $1 AND ($2 = 0 OR silence_id = $2) AND ($3 = 0 OR id < $3)
		  ORDER BY id DESC LIMIT $4`, c.id, silence, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SilencedEventRow{}
	for rows.Next() {
		var r SilencedEventRow
		if err := rows.Scan(&r.ID, &r.Ts, &r.RuleID, &r.Sev, &r.Origin, &r.Data, &r.SilenceID, &r.SilencedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) sweepAuditSilences(ctx context.Context, tx pgx.Tx) error {
	if ready, err := s.auditSilencesReady(ctx, tx); err != nil || !ready {
		return err
	}
	retention, known := auditRetentionInterval()
	if !known {
		return nil
	}
	if _, err := tx.Exec(ctx, `DELETE FROM audit_silenced_events WHERE ts < NOW() - $1::interval`, retention); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `DELETE FROM audit_silences WHERE expires_at < NOW() - $1::interval`, retention)
	return err
}
