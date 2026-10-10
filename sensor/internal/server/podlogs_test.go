package server

import (
	"strings"
	"testing"

	"github.com/wolfee-watcher/sensor/internal/logstore"
)

func TestKeepNewestWithinDropsOldestLines(t *testing.T) {
	var lines []logstore.LogLine
	for i := 0; i < 100; i++ {
		lines = append(lines, logstore.LogLine{Timestamp: "2026-10-10T08:00:00Z", Log: strings.Repeat("x", 100)})
	}
	lines[99].Log = "newest"
	kept, cut := keepNewestWithin(lines, 1000)
	if !cut || len(kept) == 0 || kept[len(kept)-1].Log != "newest" {
		t.Fatalf("kept=%d cut=%v last=%q", len(kept), cut, kept[len(kept)-1].Log)
	}
	if all, cut := keepNewestWithin(lines[:3], 1<<20); cut || len(all) != 3 {
		t.Fatalf("small input must be kept whole, got %d cut=%v", len(all), cut)
	}
}

func TestTailWithinCutsAtLineBoundary(t *testing.T) {
	raw := []byte("old line one\nold line two\nnew line\n")
	got, cut := tailWithin(raw, 15)
	if !cut || string(got) != "new line\n" {
		t.Fatalf("got %q cut=%v", got, cut)
	}
}
