package alerts

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type countingClusterDB struct {
	mu    sync.Mutex
	row   clusterNameTestRow
	calls atomic.Int64
	delay time.Duration
}

func (db *countingClusterDB) QueryRow(ctx context.Context, _ string, _ ...any) pgx.Row {
	db.calls.Add(1)
	if db.delay > 0 {
		time.Sleep(db.delay)
	}
	if ctx.Err() != nil {
		return clusterNameTestRow{err: ctx.Err()}
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.row
}

func (db *countingClusterDB) set(row clusterNameTestRow) {
	db.mu.Lock()
	db.row = row
	db.mu.Unlock()
}

func TestClusterNameCacheReusesLookupUntilInvalidated(t *testing.T) {
	var cache ClusterNameCache
	db := &countingClusterDB{row: clusterNameTestRow{name: "Production EU"}}
	for i := 0; i < 5; i++ {
		if got := cache.Resolve(context.Background(), db, "prod-eu"); got != "Production EU" {
			t.Fatalf("name = %q", got)
		}
	}
	if calls := db.calls.Load(); calls != 1 {
		t.Fatalf("lookups = %d, want 1", calls)
	}
	db.set(clusterNameTestRow{name: "Renamed EU"})
	cache.Invalidate("prod-eu")
	if got := cache.Resolve(context.Background(), db, "prod-eu"); got != "Renamed EU" {
		t.Fatalf("after invalidate = %q", got)
	}
}

func TestClusterNameCacheCoalescesConcurrentMisses(t *testing.T) {
	var cache ClusterNameCache
	db := &countingClusterDB{row: clusterNameTestRow{name: "Production EU"}, delay: 20 * time.Millisecond}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cache.Resolve(context.Background(), db, "prod-eu")
		}()
	}
	wg.Wait()
	if calls := db.calls.Load(); calls != 1 {
		t.Fatalf("lookups = %d, want 1", calls)
	}
}

func TestClusterNameCacheKeepsLastNameOnFailure(t *testing.T) {
	cache := ClusterNameCache{TTL: time.Nanosecond}
	db := &countingClusterDB{row: clusterNameTestRow{name: "Production EU"}}
	cache.Resolve(context.Background(), db, "prod-eu")
	time.Sleep(time.Millisecond)
	db.set(clusterNameTestRow{err: errors.New("database unavailable")})
	if got := cache.Resolve(context.Background(), db, "prod-eu"); got != "Production EU" {
		t.Fatalf("name during outage = %q", got)
	}
	calls := db.calls.Load()
	cache.Resolve(context.Background(), db, "prod-eu")
	if db.calls.Load() != calls {
		t.Fatal("failed lookup was retried immediately")
	}
}

func TestClusterNameCacheIgnoresCanceledCaller(t *testing.T) {
	var cache ClusterNameCache
	db := &countingClusterDB{row: clusterNameTestRow{name: "Production EU"}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := cache.Resolve(ctx, db, "prod-eu"); got != "Production EU" {
		t.Fatalf("name = %q", got)
	}
}

func TestClusterNameCacheUnknownCluster(t *testing.T) {
	var cache ClusterNameCache
	db := &countingClusterDB{row: clusterNameTestRow{err: pgx.ErrNoRows}}
	if got := cache.Resolve(context.Background(), db, " "); got != "default" {
		t.Fatalf("name = %q", got)
	}
	if got := cache.Resolve(context.Background(), nil, "prod-eu"); got != "prod-eu" {
		t.Fatalf("name without database = %q", got)
	}
}
