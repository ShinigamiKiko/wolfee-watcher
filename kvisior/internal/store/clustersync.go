package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type replicatedTable struct {
	name  string
	key   string
	prune bool
}

var replicatedTables = []replicatedTable{
	{name: "runtime_policies", key: "id", prune: true},
	{name: "audit_rules", key: "id", prune: true},
	{name: "platform_settings", key: "key", prune: false},
}

type ClusterSyncResult struct {
	Cluster string
	Copied  []string
	Err     error
}

type replicaSource struct {
	columns []string
	digest  string
	rows    []byte
}

func (s *Store) SyncRoutedClusters(ctx context.Context) []ClusterSyncResult {
	ids := s.router.Clusters()
	if len(ids) == 0 {
		return nil
	}
	sources := map[string]*replicaSource{}
	var srcErr error
	for _, t := range replicatedTables {
		src, err := loadReplicaSource(ctx, s.pool, t)
		if err != nil {
			srcErr = errors.Join(srcErr, fmt.Errorf("%s: %w", t.name, err))
			continue
		}
		sources[t.name] = src
	}
	out := make([]ClusterSyncResult, 0, len(ids))
	for _, id := range ids {
		dst := s.router.store(id)
		if dst == nil {
			continue
		}
		res := ClusterSyncResult{Cluster: id, Err: srcErr}
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		if err := s.pullClusterRow(cctx, id, dst); err != nil {
			res.Err = errors.Join(res.Err, fmt.Errorf("cluster registry: %w", err))
		}
		for _, t := range replicatedTables {
			src := sources[t.name]
			if src == nil {
				continue
			}
			copied, err := replicateTable(cctx, dst.pool, t, src)
			if err != nil {
				res.Err = errors.Join(res.Err, fmt.Errorf("%s: %w", t.name, err))
				continue
			}
			if copied {
				res.Copied = append(res.Copied, t.name)
			}
		}
		cancel()
		out = append(out, res)
	}
	return out
}

func (s *Store) pullClusterRow(ctx context.Context, id string, dst *Store) error {
	var endpoint string
	var seen *time.Time
	err := dst.pool.QueryRow(ctx,
		`SELECT endpoint, last_seen_at FROM clusters WHERE id = $1`, id).Scan(&endpoint, &seen)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO clusters (id, name, description, endpoint, last_seen_at)
		 VALUES ($1, $1, 'Dedicated database', $2, $3)
		 ON CONFLICT (id) DO UPDATE SET
		   endpoint = CASE WHEN EXCLUDED.endpoint <> '' THEN EXCLUDED.endpoint ELSE clusters.endpoint END,
		   last_seen_at = GREATEST(clusters.last_seen_at, EXCLUDED.last_seen_at)`,
		id, endpoint, seen)
	return err
}

func loadReplicaSource(ctx context.Context, pool *pgxpool.Pool, t replicatedTable) (*replicaSource, error) {
	src := &replicaSource{}
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL TimeZone = 'UTC'`); err != nil {
			return err
		}
		rows, err := tx.Query(ctx,
			`SELECT column_name FROM information_schema.columns
			  WHERE table_schema = current_schema() AND table_name = $1 AND is_generated = 'NEVER'
			  ORDER BY ordinal_position`, t.name)
		if err != nil {
			return err
		}
		cols, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		if len(cols) == 0 {
			return fmt.Errorf("table not found")
		}
		src.columns = cols
		if src.digest, err = tableDigest(ctx, tx, t, cols); err != nil {
			return err
		}
		return tx.QueryRow(ctx, fmt.Sprintf(
			`SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.%s), '[]'::jsonb) FROM %s t`,
			ident(t.key), ident(t.name))).Scan(&src.rows)
	})
	if err != nil {
		return nil, err
	}
	return src, nil
}

func tableDigest(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, t replicatedTable, cols []string) (string, error) {
	var digest string
	err := q.QueryRow(ctx, fmt.Sprintf(
		`SELECT COALESCE(md5(string_agg(json_build_array(%s)::text, ',' ORDER BY t.%s)), '') FROM %s t`,
		qualified("t", cols), ident(t.key), ident(t.name))).Scan(&digest)
	return digest, err
}

func replicateTable(ctx context.Context, pool *pgxpool.Pool, t replicatedTable, src *replicaSource) (bool, error) {
	copied := false
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL TimeZone = 'UTC'`); err != nil {
			return err
		}
		digest, err := tableDigest(ctx, tx, t, src.columns)
		if err != nil {
			return err
		}
		if digest == src.digest {
			return nil
		}
		var rest []string
		for _, c := range src.columns {
			if c != t.key {
				rest = append(rest, c)
			}
		}
		cols := qualified("", src.columns)
		upsert := fmt.Sprintf(
			`INSERT INTO %[1]s AS dst (%[2]s)
			 SELECT %[2]s FROM jsonb_populate_recordset(NULL::%[1]s, $1)
			 ON CONFLICT (%[3]s) DO UPDATE SET (%[4]s) = ROW(%[5]s)
			 WHERE (%[6]s) IS DISTINCT FROM (%[5]s)`,
			ident(t.name), cols, ident(t.key),
			qualified("", rest), qualified("EXCLUDED", rest), qualified("dst", rest))
		if _, err := tx.Exec(ctx, upsert, src.rows); err != nil {
			return err
		}
		if t.prune {
			if _, err := tx.Exec(ctx, fmt.Sprintf(
				`DELETE FROM %[1]s WHERE %[2]s NOT IN (SELECT %[2]s FROM jsonb_populate_recordset(NULL::%[1]s, $1))`,
				ident(t.name), ident(t.key)), src.rows); err != nil {
				return err
			}
		}
		copied = true
		return nil
	})
	return copied, err
}

func ident(name string) string { return pgx.Identifier{name}.Sanitize() }

func qualified(prefix string, cols []string) string {
	parts := make([]string, len(cols))
	for i, c := range cols {
		if prefix == "" {
			parts[i] = ident(c)
		} else {
			parts[i] = prefix + "." + ident(c)
		}
	}
	return strings.Join(parts, ", ")
}
