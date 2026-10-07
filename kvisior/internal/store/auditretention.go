package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	AuditRetentionMin    = 24 * time.Hour
	AuditRetentionMax    = 30 * 24 * time.Hour
	auditRetentionKey    = "audit_retention"
	auditRetentionReload = time.Minute
)

var (
	ErrAuditRetentionInvalid  = errors.New("store: audit retention is out of range")
	ErrAuditRetentionReadOnly = errors.New("store: audit retention is managed on the hub")

	auditRetention       atomic.Int64
	auditRetentionKnown  atomic.Bool
	auditRetentionWriter atomic.Bool
)

func init() { auditRetention.Store(int64(14 * 24 * time.Hour)) }

func AuditRetention() time.Duration { return time.Duration(auditRetention.Load()) }

func SetAuditRetention(d time.Duration) {
	if d >= time.Hour {
		auditRetention.Store(int64(d))
	}
}

func ConfigureAuditRetentionWriter(writer bool) { auditRetentionWriter.Store(writer) }

func AuditRetentionWriter() bool { return auditRetentionWriter.Load() }

func auditSweepRetention() (time.Duration, bool) {
	return AuditRetention(), auditRetentionKnown.Load()
}

func auditRetentionInterval() (string, bool) {
	keep, known := auditSweepRetention()
	if !known {
		return "", false
	}
	return fmt.Sprintf("%d seconds", int64(keep.Seconds())), true
}

func clampRetentionHours(h int) int {
	return max(int(AuditRetentionMin.Hours()), min(h, int(AuditRetentionMax.Hours())))
}

type AuditRetentionSetting struct {
	Hours     int        `json:"hours"`
	MinHours  int        `json:"minHours"`
	MaxHours  int        `json:"maxHours"`
	UpdatedBy string     `json:"updatedBy,omitempty"`
	UpdatedAt *time.Time `json:"updatedAt,omitempty"`
	Editable  bool       `json:"editable"`
	Synced    bool       `json:"synced"`
}

func (s *Store) LoadAuditRetention(ctx context.Context) error {
	ready, err := s.tableReady(ctx, s.pool, "platform_settings")
	if err != nil {
		return err
	}
	if !ready {
		auditRetentionKnown.Store(true)
		return nil
	}
	hours, err := s.readAuditRetentionHours(ctx)
	if errors.Is(err, pgx.ErrNoRows) && AuditRetentionWriter() {
		seed := clampRetentionHours(int(AuditRetention().Hours()))
		if _, err := s.pool.Exec(ctx,
			`INSERT INTO platform_settings (key, value, updated_by) VALUES ($1, jsonb_build_object('hours', $2::int), 'env')
			 ON CONFLICT (key) DO NOTHING`, auditRetentionKey, seed); err != nil {
			return err
		}
		hours, err = s.readAuditRetentionHours(ctx)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	SetAuditRetention(time.Duration(clampRetentionHours(hours)) * time.Hour)
	auditRetentionKnown.Store(true)
	return nil
}

func (s *Store) readAuditRetentionHours(ctx context.Context) (int, error) {
	var hours int
	err := s.pool.QueryRow(ctx,
		`SELECT (value->>'hours')::int FROM platform_settings WHERE key = $1`, auditRetentionKey).Scan(&hours)
	return hours, err
}

func (s *Store) RunAuditRetentionSync(ctx context.Context) {
	t := time.NewTicker(auditRetentionReload)
	defer t.Stop()
	for {
		before := AuditRetention()
		if err := s.LoadAuditRetention(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("audit_retention_load_failed", "component", "kvisior/store", "error", err)
		} else if after := AuditRetention(); after != before {
			slog.Info("audit_retention_changed", "component", "kvisior/store", "hours", int(after.Hours()))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Store) AuditRetentionSetting(ctx context.Context) (AuditRetentionSetting, error) {
	out := AuditRetentionSetting{
		Hours:    int(AuditRetention().Hours()),
		MinHours: int(AuditRetentionMin.Hours()),
		MaxHours: int(AuditRetentionMax.Hours()),
		Editable: AuditRetentionWriter(),
		Synced:   auditRetentionKnown.Load(),
	}
	ready, err := s.tableReady(ctx, s.pool, "platform_settings")
	if err != nil || !ready {
		out.Editable = false
		return out, err
	}
	var by string
	var at time.Time
	err = s.pool.QueryRow(ctx,
		`SELECT (value->>'hours')::int, updated_by, updated_at FROM platform_settings WHERE key = $1`,
		auditRetentionKey).Scan(&out.Hours, &by, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.UpdatedBy, out.UpdatedAt = by, &at
	return out, nil
}

func (s *Store) UpdateAuditRetention(ctx context.Context, hours int, by string) (AuditRetentionSetting, error) {
	if !AuditRetentionWriter() {
		return AuditRetentionSetting{}, ErrAuditRetentionReadOnly
	}
	if hours < int(AuditRetentionMin.Hours()) || hours > int(AuditRetentionMax.Hours()) {
		return AuditRetentionSetting{}, fmt.Errorf("%w: choose between %d and %d days", ErrAuditRetentionInvalid,
			int(AuditRetentionMin.Hours()/24), int(AuditRetentionMax.Hours()/24))
	}
	if ready, err := s.tableReady(ctx, s.pool, "platform_settings"); err != nil {
		return AuditRetentionSetting{}, err
	} else if !ready {
		return AuditRetentionSetting{}, fmt.Errorf("%w: the database schema predates shared settings", ErrAuditRetentionReadOnly)
	}
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO platform_settings (key, value, updated_by, updated_at) VALUES ($1, jsonb_build_object('hours', $2::int), $3, NOW())
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at`,
		auditRetentionKey, hours, by); err != nil {
		return AuditRetentionSetting{}, err
	}
	SetAuditRetention(time.Duration(hours) * time.Hour)
	auditRetentionKnown.Store(true)
	return s.AuditRetentionSetting(ctx)
}
