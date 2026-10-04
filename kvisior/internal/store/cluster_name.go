package store

import (
	"context"
	"strings"
	"time"

	alertspkg "github.com/wolfee-watcher/pkg/alerts"
)

type cachedClusterName struct {
	name    string
	expires time.Time
}

// ClusterDisplayName follows cluster renames without a lookup for every alert.
func (s *Store) ClusterDisplayName(ctx context.Context, id string) string {
	if id = strings.TrimSpace(id); id == "" {
		id = DefaultCluster
	}
	if s == nil || s.pool == nil {
		return id
	}
	if v, ok := s.clusterNames.Load(id); ok {
		if cached := v.(cachedClusterName); time.Now().Before(cached.expires) {
			return cached.name
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	name := alertspkg.ResolveClusterName(ctx, s.pool, id)
	s.clusterNames.Store(id, cachedClusterName{name: name, expires: time.Now().Add(30 * time.Second)})
	return name
}
