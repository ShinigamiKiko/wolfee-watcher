package store

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestMissingPodWatchIsNotAnError(t *testing.T) {
	selection, err := podWatchError(pgx.ErrNoRows)
	if err != nil {
		t.Fatalf("missing watch returned error: %v", err)
	}
	if len(selection.Syscalls)+len(selection.LSMHooks)+len(selection.Tracepoints) != 0 {
		t.Fatalf("missing watch returned non-empty selection: %+v", selection)
	}
}

func TestPartitionedTS(t *testing.T) {
	now := time.Now()
	if _, keep := partitionedTS(now.Add(-48*time.Hour), 24*time.Hour); keep {
		t.Fatal("rows older than the TTL must be dropped: no partition holds them")
	}
	if ts, keep := partitionedTS(now.Add(-time.Hour), 24*time.Hour); !keep || !ts.Equal(now.Add(-time.Hour)) {
		t.Fatal("rows inside the retention window must be kept unchanged")
	}
	if ts, keep := partitionedTS(now.Add(72*time.Hour), 24*time.Hour); !keep || ts.After(time.Now()) {
		t.Fatal("rows from the future must be clamped to now")
	}
}
