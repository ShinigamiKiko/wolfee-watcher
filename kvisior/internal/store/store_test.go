package store

import (
	"testing"

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
