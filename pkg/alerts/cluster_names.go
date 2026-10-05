package alerts

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	defaultClusterNameTTL    = 30 * time.Second
	clusterNameFailureTTL    = 5 * time.Second
	clusterNameLookupTimeout = 2 * time.Second
)

type ClusterNameDB interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type ClusterNameCache struct {
	TTL time.Duration

	mu      sync.Mutex
	entries map[string]*clusterNameEntry
}

type clusterNameEntry struct {
	mu      sync.Mutex
	name    string
	expires time.Time
}

func (c *ClusterNameCache) Resolve(ctx context.Context, db ClusterNameDB, id string) string {
	id = firstNonEmpty(id, "default")
	if db == nil {
		return id
	}
	entry := c.entry(id)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if time.Now().Before(entry.expires) {
		return entry.name
	}
	lookupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), clusterNameLookupTimeout)
	defer cancel()
	name, err := lookupClusterName(lookupCtx, db, id)
	switch {
	case err == nil:
		entry.name, entry.expires = name, time.Now().Add(c.ttl())
	case errors.Is(err, pgx.ErrNoRows):
		entry.name, entry.expires = id, time.Now().Add(c.ttl())
	default:
		if entry.name == "" {
			entry.name = id
		}
		entry.expires = time.Now().Add(clusterNameFailureTTL)
	}
	return entry.name
}

func (c *ClusterNameCache) Invalidate(id string) {
	id = firstNonEmpty(id, "default")
	c.mu.Lock()
	delete(c.entries, id)
	c.mu.Unlock()
}

func (c *ClusterNameCache) entry(id string) *clusterNameEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]*clusterNameEntry)
	}
	entry := c.entries[id]
	if entry == nil {
		entry = &clusterNameEntry{}
		c.entries[id] = entry
	}
	return entry
}

func (c *ClusterNameCache) ttl() time.Duration {
	if c.TTL > 0 {
		return c.TTL
	}
	return defaultClusterNameTTL
}

func ResolveClusterName(ctx context.Context, db ClusterNameDB, id string) string {
	id = firstNonEmpty(id, "default")
	if db == nil {
		return id
	}
	name, err := lookupClusterName(ctx, db, id)
	if err != nil {
		return id
	}
	return name
}

func lookupClusterName(ctx context.Context, db ClusterNameDB, id string) (string, error) {
	var name string
	if err := db.QueryRow(ctx, "SELECT name FROM clusters WHERE id = $1", id).Scan(&name); err != nil {
		return "", err
	}
	return firstNonEmpty(strings.TrimSpace(name), id), nil
}
