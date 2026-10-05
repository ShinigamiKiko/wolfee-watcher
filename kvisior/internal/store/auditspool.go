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
)

const (
	auditSpoolAlertCooldown = time.Hour
	auditSpoolHigh          = 0.8
	auditSpoolCritical      = 0.95
)

type AuditSpoolStatus struct {
	Pod         string           `json:"pod"`
	Durable     bool             `json:"durable"`
	Pending     int              `json:"pending"`
	Bytes       int64            `json:"bytes"`
	Capacity    int64            `json:"capacity"`
	DeadBytes   int64            `json:"deadBytes"`
	Rejected    int64            `json:"rejected"`
	Shed        int64            `json:"shed"`
	Quarantined int64            `json:"quarantined"`
	ShedActors  map[string]int64 `json:"shedActors,omitempty"`
	LastError   string           `json:"lastError,omitempty"`
	UpdatedAt   time.Time        `json:"updatedAt"`
}

func (s AuditSpoolStatus) Usage() float64 {
	if s.Capacity <= 0 {
		return 0
	}
	return float64(s.Bytes+s.DeadBytes) / float64(s.Capacity)
}

var (
	auditSpoolRank       = map[string]int{"": 0, "high": 1, "critical": 2, "loss": 3}
	auditSpoolResetAfter = 10 * time.Minute
)

func grew(now, before int64) bool {
	if now < before {
		return now > 0
	}
	return now > before
}

func spoolAlert(cluster string, s AuditSpoolStatus, level string) IncomingAlert {
	rule, name, sev := "audit-delivery-queue-high", "Audit delivery queue is filling up", "MEDIUM"
	switch level {
	case "loss":
		rule, name, sev = "audit-delivery-loss", "Audit events were lost before delivery", "HIGH"
	case "critical":
		rule, name, sev = "audit-delivery-queue-critical", "Audit delivery queue is almost full", "HIGH"
	}
	detail := fmt.Sprintf("%s: queue %.0f%% full (%d of %d bytes, %d files); lost %d, shed %d, quarantined %d",
		s.Pod, 100*s.Usage(), s.Bytes+s.DeadBytes, s.Capacity, s.Pending, s.Rejected, s.Shed, s.Quarantined)
	if s.LastError != "" {
		detail += "; last error: " + s.LastError
	}
	data, _ := json.Marshal(s)
	return IncomingAlert{
		Timestamp: time.Now(), Source: "audit-delivery", DetType: "audit_delivery", RuleID: rule, RuleName: name,
		Severity: sev, Target: s.Pod, Detail: detail, Fingerprint: Fingerprint(cluster, rule, "", s.Pod), Data: data,
	}
}

func (c *Scoped) RecordAuditSpool(ctx context.Context, s AuditSpoolStatus) (*IncomingAlert, error) {
	tx, err := c.s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.Background())
	var prevRejected, prevShed, prevQuarantined int64
	var prevLevel string
	var alertedAt *time.Time
	err = tx.QueryRow(ctx,
		`SELECT rejected, shed, quarantined, alert_level, alerted_at FROM audit_spool_status
		  WHERE cluster_id=$1 AND pod=$2 FOR UPDATE`, c.id, s.Pod).
		Scan(&prevRejected, &prevShed, &prevQuarantined, &prevLevel, &alertedAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	level := ""
	switch {
	case grew(s.Rejected, prevRejected) || grew(s.Shed, prevShed) || grew(s.Quarantined, prevQuarantined):
		level = "loss"
	case s.Usage() >= auditSpoolCritical:
		level = "critical"
	case s.Usage() >= auditSpoolHigh:
		level = "high"
	}
	var alert *IncomingAlert
	alertLevel := prevLevel
	if level == "" {
		if alertedAt == nil || time.Since(*alertedAt) >= auditSpoolResetAfter {
			alertLevel = ""
		}
	} else if auditSpoolRank[level] > auditSpoolRank[prevLevel] || alertedAt == nil || time.Since(*alertedAt) >= auditSpoolAlertCooldown {
		a := spoolAlert(c.id, s, level)
		alert = &a
		now := time.Now()
		alertedAt, alertLevel = &now, level
	}
	actors, err := json.Marshal(s.ShedActors)
	if err != nil {
		return nil, err
	}
	actors = StorableJSON(actors)
	s.LastError = strings.ReplaceAll(s.LastError, "\x00", "�")
	if _, err = tx.Exec(ctx,
		`INSERT INTO audit_spool_status (cluster_id, pod, durable, pending, bytes, capacity, dead_bytes, rejected, shed,
		                                 quarantined, shed_actors, last_error, alert_level, alerted_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,clock_timestamp())
		 ON CONFLICT (cluster_id, pod) DO UPDATE SET
		    durable=EXCLUDED.durable, pending=EXCLUDED.pending, bytes=EXCLUDED.bytes, capacity=EXCLUDED.capacity,
		    dead_bytes=EXCLUDED.dead_bytes, rejected=EXCLUDED.rejected, shed=EXCLUDED.shed,
		    quarantined=EXCLUDED.quarantined, shed_actors=EXCLUDED.shed_actors, last_error=EXCLUDED.last_error,
		    alert_level=EXCLUDED.alert_level, alerted_at=EXCLUDED.alerted_at, updated_at=clock_timestamp()`,
		c.id, s.Pod, s.Durable, s.Pending, s.Bytes, s.Capacity, s.DeadBytes, s.Rejected, s.Shed, s.Quarantined,
		actors, s.LastError, alertLevel, alertedAt); err != nil {
		return nil, err
	}
	if alert != nil {
		if err = (&Scoped{s: c.s, id: c.id, tx: tx}).InsertAlerts(ctx, []IncomingAlert{*alert}); err != nil {
			return nil, err
		}
	}
	if _, err = tx.Exec(ctx,
		`DELETE FROM audit_spool_status WHERE cluster_id=$1 AND updated_at < clock_timestamp()-interval '7 days'`, c.id); err != nil {
		return nil, err
	}
	return alert, tx.Commit(ctx)
}

func (c *Scoped) ListAuditSpools(ctx context.Context) ([]AuditSpoolStatus, error) {
	rows, err := c.s.pool.Query(ctx,
		`SELECT pod, durable, pending, bytes, capacity, dead_bytes, rejected, shed, quarantined, shed_actors, last_error, updated_at
		   FROM audit_spool_status WHERE cluster_id=$1 ORDER BY pod`, c.id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42P01" {
			return []AuditSpoolStatus{}, nil
		}
		return nil, err
	}
	defer rows.Close()
	out := []AuditSpoolStatus{}
	for rows.Next() {
		var s AuditSpoolStatus
		var actors []byte
		if err := rows.Scan(&s.Pod, &s.Durable, &s.Pending, &s.Bytes, &s.Capacity, &s.DeadBytes, &s.Rejected,
			&s.Shed, &s.Quarantined, &actors, &s.LastError, &s.UpdatedAt); err != nil {
			return nil, err
		}
		if len(actors) > 0 && strings.TrimSpace(string(actors)) != "null" {
			if err := json.Unmarshal(actors, &s.ShedActors); err != nil {
				return nil, err
			}
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
