package store

import (
	"context"
	"strings"
)

func (s *Store) ClusterDisplayName(ctx context.Context, id string) string {
	if id = strings.TrimSpace(id); id == "" {
		id = DefaultCluster
	}
	if s == nil || s.pool == nil {
		return id
	}
	return s.clusterNames.Resolve(ctx, s.pool, id)
}
