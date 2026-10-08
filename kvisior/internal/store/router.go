package store

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	routedPoolMaxConns   = 8
	routedPoolIdleTime   = 5 * time.Minute
	routedPoolCloseDelay = 2 * time.Minute
)

type Router struct {
	mu      sync.RWMutex
	targets map[string]*routedTarget
}

type routedTarget struct {
	dsn   string
	store *Store
}

func NewRouter() *Router { return &Router{targets: map[string]*routedTarget{}} }

func (s *Store) SetRouter(r *Router) {
	if s != nil {
		s.router = r
	}
}

func (s *Store) Router() *Router {
	if s == nil {
		return nil
	}
	return s.router
}

func (s *Store) forCluster(id string) *Store {
	if s == nil || s.router == nil {
		return s
	}
	if t := s.router.store(id); t != nil {
		return t
	}
	return s
}

func (s *Store) Routed(id string) bool {
	return s != nil && s.router != nil && s.router.store(id) != nil
}

func (r *Router) store(id string) *Store {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if t := r.targets[id]; t != nil {
		return t.store
	}
	return nil
}

func (r *Router) Clusters() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	out := make([]string, 0, len(r.targets))
	for id := range r.targets {
		out = append(out, id)
	}
	r.mu.RUnlock()
	sort.Strings(out)
	return out
}

func (r *Router) Apply(ctx context.Context, dsns map[string]string) (added, removed []string, err error) {
	if r == nil {
		return nil, nil, nil
	}
	fresh := map[string]*routedTarget{}
	var errs []error
	r.mu.RLock()
	for id, dsn := range dsns {
		if t := r.targets[id]; t != nil && t.dsn == dsn {
			continue
		}
		pool, perr := openRoutedPool(ctx, dsn)
		if perr != nil {
			errs = append(errs, fmt.Errorf("cluster %q: %w", id, perr))
			continue
		}
		fresh[id] = &routedTarget{dsn: dsn, store: &Store{pool: pool}}
	}
	r.mu.RUnlock()

	var retired []*Store
	r.mu.Lock()
	for id, t := range r.targets {
		_, keep := dsns[id]
		if _, replaced := fresh[id]; keep && !replaced {
			continue
		}
		retired = append(retired, t.store)
		delete(r.targets, id)
		if !keep {
			removed = append(removed, id)
		}
	}
	for id, t := range fresh {
		r.targets[id] = t
		added = append(added, id)
	}
	r.mu.Unlock()

	if len(retired) > 0 {
		go func() {
			time.Sleep(routedPoolCloseDelay)
			for _, st := range retired {
				st.pool.Close()
			}
		}()
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed, errors.Join(errs...)
}

func (r *Router) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, t := range r.targets {
		t.store.pool.Close()
		delete(r.targets, id)
	}
}

func openRoutedPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("invalid DSN")
	}
	if cfg.MaxConns > routedPoolMaxConns {
		cfg.MaxConns = routedPoolMaxConns
	}
	cfg.MaxConnIdleTime = routedPoolIdleTime
	return pgxpool.NewWithConfig(ctx, cfg)
}

func LoadClusterDatabases(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseClusterDatabases(f)
}

func ParseClusterDatabases(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 2 {
			return nil, fmt.Errorf("line %d: expected \"<cluster-id> <dsn>\"", line)
		}
		id, dsn := fields[0], fields[1]
		if !ValidClusterID(id) {
			return nil, fmt.Errorf("line %d: invalid cluster id %q", line, id)
		}
		if id == DefaultCluster {
			return nil, fmt.Errorf("line %d: the default cluster always uses the hub database", line)
		}
		if _, dup := out[id]; dup {
			return nil, fmt.Errorf("line %d: cluster %q is listed twice", line, id)
		}
		if _, err := pgxpool.ParseConfig(dsn); err != nil {
			return nil, fmt.Errorf("line %d: invalid DSN for cluster %q", line, id)
		}
		out[id] = dsn
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
