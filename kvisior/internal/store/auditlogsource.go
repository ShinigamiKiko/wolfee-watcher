package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	auditLogNodeTTL = 24 * time.Hour
	maxAuditLogPath = 512
)

var auditLogPathRe = regexp.MustCompile(`^/[A-Za-z0-9._/@:+-]+$`)

func ValidAuditLogPath(p string) error {
	switch {
	case len(p) > maxAuditLogPath:
		return fmt.Errorf("path is longer than %d characters", maxAuditLogPath)
	case !auditLogPathRe.MatchString(p):
		return errors.New("path must be absolute and may contain only letters, digits and . _ / @ : + -")
	case path.Clean(p) != p:
		return errors.New("path must not contain .., double slashes or a trailing slash")
	case path.Dir(p) == "/":
		return errors.New("the log file must be inside a directory, not directly under /")
	}
	return nil
}

type AuditLogSettings struct {
	Enabled    bool              `json:"enabled"`
	Path       string            `json:"path"`
	NodePaths  map[string]string `json:"nodePaths"`
	UpdatedBy  string            `json:"updatedBy,omitempty"`
	UpdatedAt  *time.Time        `json:"updatedAt,omitempty"`
	AppliedRev string            `json:"appliedRev,omitempty"`
	AppliedAt  *time.Time        `json:"appliedAt,omitempty"`
	ApplyError string            `json:"applyError,omitempty"`
}

type AuditLogNode struct {
	Node         string     `json:"node"`
	APIServer    bool       `json:"apiServer"`
	AuditEnabled bool       `json:"auditEnabled"`
	DetectedPath string     `json:"detectedPath"`
	DetectedAt   *time.Time `json:"detectedAt,omitempty"`
	TailPath     string     `json:"tailPath"`
	TailState    string     `json:"tailState"`
	TailError    string     `json:"tailError,omitempty"`
	LastRecordAt *time.Time `json:"lastRecordAt,omitempty"`
	Lines        int64      `json:"lines"`
	Sent         int64      `json:"sent"`
	Rejected     int64      `json:"rejected"`
	BacklogBytes int64      `json:"backlogBytes"`
	BacklogFiles int        `json:"backlogFiles"`
	LagSeconds   int64      `json:"lagSeconds"`
	Headroom     *int       `json:"headroom,omitempty"`
	TailSeenAt   *time.Time `json:"tailSeenAt,omitempty"`
	ProbeDone    string     `json:"probeDone,omitempty"`
	ProbeOK      bool       `json:"probeOk"`
	ProbeDetail  string     `json:"probeDetail,omitempty"`
	ProbeAt      *time.Time `json:"probeAt,omitempty"`
}

const (
	AuditLogTailFresh  = 30 * time.Second
	auditLogProbeValid = 2 * time.Minute
)

var ErrAuditLogReaderOffline = errors.New("store: audit log reader is not running on this node")

type AuditLogPlan struct {
	Managed   bool              `json:"managed"`
	Enabled   bool              `json:"enabled"`
	Path      string            `json:"path"`
	NodePaths map[string]string `json:"nodePaths"`
	Rev       string            `json:"rev"`
}

func PlanAuditLog(s AuditLogSettings, managed bool, nodes []AuditLogNode) AuditLogPlan {
	plan := AuditLogPlan{Managed: managed, Enabled: managed && s.Enabled, Path: s.Path, NodePaths: map[string]string{}}
	effective := map[string]string{}
	for _, n := range nodes {
		path := s.NodePaths[n.Node]
		if path == "" {
			path = s.Path
		}
		if path == "" {
			path = n.DetectedPath
		}
		if path != "" {
			effective[n.Node] = path
		}
	}
	for node, path := range s.NodePaths {
		if path != "" {
			effective[node] = path
		}
	}
	if plan.Path == "" {
		counts := map[string]int{}
		for _, path := range effective {
			counts[path]++
		}
		for path, n := range counts {
			if n > counts[plan.Path] || (n == counts[plan.Path] && path < plan.Path) || plan.Path == "" {
				plan.Path = path
			}
		}
	}
	names := make([]string, 0, len(effective))
	for node, path := range effective {
		if path != plan.Path {
			plan.NodePaths[node] = path
			names = append(names, node)
		}
	}
	sort.Strings(names)
	h := sha256.New()
	fmt.Fprintf(h, "%v|%s", plan.Enabled, plan.Path)
	for _, node := range names {
		fmt.Fprintf(h, "|%s=%s", node, plan.NodePaths[node])
	}
	plan.Rev = fmt.Sprintf("%x", h.Sum(nil))[:16]
	return plan
}

func (c *Scoped) AuditLogSettings(ctx context.Context) (AuditLogSettings, bool, error) {
	s := AuditLogSettings{NodePaths: map[string]string{}}
	var nodePaths []byte
	err := c.s.pool.QueryRow(ctx,
		`SELECT enabled, path, node_paths, updated_by, updated_at, applied_rev, applied_at, apply_error
		   FROM audit_log_settings WHERE cluster_id = $1`, c.id).
		Scan(&s.Enabled, &s.Path, &nodePaths, &s.UpdatedBy, &s.UpdatedAt, &s.AppliedRev, &s.AppliedAt, &s.ApplyError)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, false, nil
	}
	if err != nil {
		return s, false, err
	}
	if len(nodePaths) > 0 {
		if err := json.Unmarshal(nodePaths, &s.NodePaths); err != nil {
			return s, true, fmt.Errorf("audit log node paths: %w", err)
		}
	}
	if s.NodePaths == nil {
		s.NodePaths = map[string]string{}
	}
	return s, true, nil
}

func (c *Scoped) SaveAuditLogSettings(ctx context.Context, s AuditLogSettings) error {
	nodePaths, err := json.Marshal(s.NodePaths)
	if err != nil {
		return err
	}
	_, err = c.s.pool.Exec(ctx,
		`INSERT INTO audit_log_settings (cluster_id, enabled, path, node_paths, updated_by, updated_at)
		 VALUES ($1, $2, $3, $4, $5, NOW())
		 ON CONFLICT (cluster_id) DO UPDATE SET
		    enabled = EXCLUDED.enabled, path = EXCLUDED.path, node_paths = EXCLUDED.node_paths,
		    updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
		c.id, s.Enabled, s.Path, nodePaths, s.UpdatedBy)
	return err
}

type AuditProxySettings struct {
	Proxies          string
	HeadersSanitized bool
}

func (c *Scoped) AuditTrustedProxies(ctx context.Context) (AuditProxySettings, error) {
	var settings AuditProxySettings
	err := c.s.pool.QueryRow(ctx,
		`SELECT proxies, headers_sanitized FROM audit_trusted_proxies WHERE cluster_id = $1`, c.id).
		Scan(&settings.Proxies, &settings.HeadersSanitized)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "42P01":
			return AuditProxySettings{}, nil
		case "42703":
			err = c.s.pool.QueryRow(ctx,
				`SELECT proxies FROM audit_trusted_proxies WHERE cluster_id = $1`, c.id).Scan(&settings.Proxies)
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return AuditProxySettings{}, nil
	}
	return settings, err
}

func (c *Scoped) SaveAuditTrustedProxies(ctx context.Context, settings AuditProxySettings, by string) error {
	_, err := c.s.pool.Exec(ctx,
		`INSERT INTO audit_trusted_proxies (cluster_id, proxies, headers_sanitized, updated_by, updated_at)
		 VALUES ($1, $2, $3, $4, NOW())
		 ON CONFLICT (cluster_id) DO UPDATE SET
		    proxies = EXCLUDED.proxies, headers_sanitized = EXCLUDED.headers_sanitized,
		    updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
		c.id, settings.Proxies, settings.HeadersSanitized, by)
	return err
}

func (c *Scoped) MarkAuditLogApplied(ctx context.Context, rev, applyError string) error {
	_, err := c.s.pool.Exec(ctx,
		`UPDATE audit_log_settings
		    SET applied_rev = CASE WHEN $3 = '' THEN $2 ELSE applied_rev END,
		        applied_at  = CASE WHEN $3 = '' THEN NOW() ELSE applied_at END,
		        apply_error = $3
		  WHERE cluster_id = $1 AND (applied_rev IS DISTINCT FROM $2 OR apply_error IS DISTINCT FROM $3)`,
		c.id, rev, applyError)
	return err
}

func (c *Scoped) ReplaceDetectedAuditLogNodes(ctx context.Context, nodes []AuditLogNode) error {
	tx, err := c.s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx,
		`UPDATE audit_log_nodes
		    SET api_server = FALSE, audit_enabled = FALSE, detected_path = '', detected_at = NULL
		  WHERE cluster_id = $1`, c.id); err != nil {
		return err
	}
	for _, n := range nodes {
		if _, err := tx.Exec(ctx,
			`INSERT INTO audit_log_nodes (cluster_id, node, api_server, audit_enabled, detected_path, detected_at)
			 VALUES ($1, $2, $3, $4, $5, NOW())
			 ON CONFLICT (cluster_id, node) DO UPDATE SET
			    api_server = EXCLUDED.api_server, audit_enabled = EXCLUDED.audit_enabled,
			    detected_path = EXCLUDED.detected_path, detected_at = NOW()`,
			c.id, n.Node, n.APIServer, n.AuditEnabled, n.DetectedPath); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM audit_log_nodes
		  WHERE cluster_id = $1 AND detected_at IS NULL
		    AND (tail_seen_at IS NULL OR tail_seen_at < NOW() - $2::interval)`,
		c.id, fmt.Sprintf("%d seconds", int64(auditLogNodeTTL.Seconds()))); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (c *Scoped) UpsertAuditLogTail(ctx context.Context, n AuditLogNode) (string, error) {
	var pending string
	err := c.s.pool.QueryRow(ctx,
		`INSERT INTO audit_log_nodes
		   (cluster_id, node, tail_path, tail_state, tail_error, last_record_at, lines, sent, rejected, tail_seen_at,
		    probe_done, probe_ok, probe_detail, probe_at, backlog_bytes, backlog_files, lag_seconds, headroom)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), $10, $11, $12, CASE WHEN $10 = '' THEN NULL ELSE NOW() END,
		         $14, $15, $16, $17)
		 ON CONFLICT (cluster_id, node) DO UPDATE SET
		    tail_path = EXCLUDED.tail_path, tail_state = EXCLUDED.tail_state, tail_error = EXCLUDED.tail_error,
		    last_record_at = COALESCE(EXCLUDED.last_record_at, audit_log_nodes.last_record_at),
		    lines = EXCLUDED.lines, sent = EXCLUDED.sent, rejected = EXCLUDED.rejected, tail_seen_at = NOW(),
		    backlog_bytes = EXCLUDED.backlog_bytes, backlog_files = EXCLUDED.backlog_files,
		    lag_seconds = EXCLUDED.lag_seconds, headroom = EXCLUDED.headroom,
		    probe_done   = CASE WHEN EXCLUDED.probe_done = '' THEN audit_log_nodes.probe_done ELSE EXCLUDED.probe_done END,
		    probe_ok     = CASE WHEN EXCLUDED.probe_done = '' THEN audit_log_nodes.probe_ok ELSE EXCLUDED.probe_ok END,
		    probe_detail = CASE WHEN EXCLUDED.probe_done = '' THEN audit_log_nodes.probe_detail ELSE EXCLUDED.probe_detail END,
		    probe_at     = CASE WHEN EXCLUDED.probe_done = '' THEN audit_log_nodes.probe_at ELSE NOW() END
		 RETURNING CASE WHEN probe_id <> '' AND probe_id <> probe_done AND probe_requested_at > NOW() - $13::interval
		                THEN probe_id ELSE '' END`,
		c.id, n.Node, n.TailPath, n.TailState, n.TailError, n.LastRecordAt, n.Lines, n.Sent, n.Rejected,
		n.ProbeDone, n.ProbeOK, n.ProbeDetail, fmt.Sprintf("%d seconds", int64(auditLogProbeValid.Seconds())),
		n.BacklogBytes, n.BacklogFiles, n.LagSeconds, n.Headroom).Scan(&pending)
	return pending, err
}

func (c *Scoped) RequestAuditLogProbe(ctx context.Context, node, id string) error {
	tag, err := c.s.pool.Exec(ctx,
		`UPDATE audit_log_nodes SET probe_id = $3, probe_requested_at = NOW()
		  WHERE cluster_id = $1 AND node = $2 AND tail_seen_at > NOW() - $4::interval`,
		c.id, node, id, fmt.Sprintf("%d seconds", int64(AuditLogTailFresh.Seconds())))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrAuditLogReaderOffline
	}
	return nil
}

func (c *Scoped) ListAuditLogNodes(ctx context.Context) ([]AuditLogNode, error) {
	rows, err := c.s.pool.Query(ctx,
		`SELECT node, api_server, audit_enabled, detected_path, detected_at, tail_path, tail_state, tail_error,
		        last_record_at, lines, sent, rejected, tail_seen_at, probe_done, probe_ok, probe_detail, probe_at,
		        backlog_bytes, backlog_files, lag_seconds, headroom
		   FROM audit_log_nodes WHERE cluster_id = $1 ORDER BY node`, c.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditLogNode{}
	for rows.Next() {
		var n AuditLogNode
		if err := rows.Scan(&n.Node, &n.APIServer, &n.AuditEnabled, &n.DetectedPath, &n.DetectedAt, &n.TailPath,
			&n.TailState, &n.TailError, &n.LastRecordAt, &n.Lines, &n.Sent, &n.Rejected, &n.TailSeenAt,
			&n.ProbeDone, &n.ProbeOK, &n.ProbeDetail, &n.ProbeAt,
			&n.BacklogBytes, &n.BacklogFiles, &n.LagSeconds, &n.Headroom); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
