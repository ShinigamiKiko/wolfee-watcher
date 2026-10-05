package store

import (
	"context"
	"encoding/json"
	"errors"
	"log"

	"github.com/jackc/pgx/v5"
	"regexp"
	"sync"
	"time"
)

const DefaultCluster = "default"

var ErrUnknownCluster = errors.New("store: unknown cluster")

var clusterIDRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func ValidClusterID(id string) bool { return clusterIDRe.MatchString(id) }

type Scoped struct {
	s  *Store
	id string
	tx pgx.Tx
}

const clusterTouchInterval = 5 * time.Minute

var seenClusters sync.Map

func (s *Store) EnsureClusterCached(id string) {
	if s == nil || id == "" {
		return
	}
	if v, ok := seenClusters.Load(id); ok {
		if t, _ := v.(time.Time); time.Since(t) < clusterTouchInterval {
			return
		}
	}
	seenClusters.Store(id, time.Now())
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.EnsureCluster(ctx, id); err != nil {
			seenClusters.Delete(id)
			log.Printf("[store] register cluster %q: %v", id, err)
		}
	}()
}

func (s *Store) Cluster(id string) *Scoped {
	if s == nil {
		return nil
	}
	if id == "" {
		id = DefaultCluster
	}
	return &Scoped{s: s, id: id}
}

func (c *Scoped) ID() string { return c.id }

func (c *Scoped) listJSONBlobs(ctx context.Context, query string, args ...interface{}) ([]json.RawMessage, error) {
	return c.s.listJSONBlobs(ctx, query, args...)
}

type ClusterRow struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Endpoint    string     `json:"endpoint"`
	Enabled     bool       `json:"enabled"`
	CreatedAt   time.Time  `json:"createdAt"`
	LastSeenAt  *time.Time `json:"lastSeenAt,omitempty"`
}

func (s *Store) ListClusters(ctx context.Context) ([]ClusterRow, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, description, endpoint, enabled, created_at, last_seen_at
		   FROM clusters ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ClusterRow{}
	for rows.Next() {
		var r ClusterRow
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.Endpoint, &r.Enabled, &r.CreatedAt, &r.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) UpsertCluster(ctx context.Context, id, name, description string, enabled bool) error {
	if !ValidClusterID(id) {
		return ErrUnknownCluster
	}
	if name == "" {
		name = id
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO clusters (id, name, description, enabled)
		 VALUES ($1,$2,$3,$4)
		 ON CONFLICT (id) DO UPDATE SET
		   name = EXCLUDED.name, description = EXCLUDED.description, enabled = EXCLUDED.enabled`,
		id, name, description, enabled)
	return err
}

func (s *Store) DeleteCluster(ctx context.Context, id string) error {
	if id == DefaultCluster {
		return errors.New("store: the default cluster cannot be deleted")
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM clusters WHERE id = $1`, id)
	return err
}

func (s *Store) EnsureCluster(ctx context.Context, id string) error {
	if !ValidClusterID(id) {
		return ErrUnknownCluster
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO clusters (id, name, description, last_seen_at)
		 VALUES ($1, $1, 'Auto-registered on first push', NOW())
		 ON CONFLICT (id) DO UPDATE SET last_seen_at = NOW()`,
		id)
	return err
}

func (s *Store) KnownClusters(ctx context.Context) (map[string]bool, error) {
	rows, err := s.pool.Query(ctx, `SELECT id FROM clusters WHERE enabled`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

func (c *Scoped) Touch(ctx context.Context) {
	_, _ = c.s.pool.Exec(ctx, `UPDATE clusters SET last_seen_at = NOW() WHERE id = $1`, c.id)
}

func (s *Store) SetClusterEndpoint(ctx context.Context, id, endpoint string) error {
	if !ValidClusterID(id) {
		return ErrUnknownCluster
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO clusters (id, name, description, endpoint, last_seen_at)
		 VALUES ($1, $1, 'Registered by its kvisior', $2, NOW())
		 ON CONFLICT (id) DO UPDATE SET endpoint = EXCLUDED.endpoint, last_seen_at = NOW()`,
		id, endpoint)
	return err
}

func (s *Store) ClusterEndpoint(ctx context.Context, id string) (string, bool, error) {
	var ep string
	var enabled bool
	err := s.pool.QueryRow(ctx,
		`SELECT endpoint, enabled FROM clusters WHERE id = $1`, id).Scan(&ep, &enabled)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}
	return ep, enabled, nil
}
