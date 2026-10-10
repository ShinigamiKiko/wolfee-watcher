package logcollect

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadsRotatedFilesAndSkipsCompressed(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"0.log":                    "2026-10-10T08:00:03.000000000Z stdout F third\n",
		"0.log.20261010-080002":    "2026-10-10T08:00:01.000000000Z stdout F first\n2026-10-10T08:00:02.000000000Z stdout F second\n",
		"0.log.20261009-120000.gz": "binary",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files := logFiles(dir)
	if len(files) != 2 {
		t.Fatalf("files = %v", files)
	}
	c := &Collector{files: map[string]*fileState{}, cursors: map[string]time.Time{}}
	var all []string
	for _, f := range files {
		entries, _, err := c.readFile(f, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			all = append(all, e.Log)
		}
	}
	if len(all) != 3 {
		t.Fatalf("lines = %v", all)
	}
}

func TestCursorSkipsAlreadyStoredLines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "0.log")
	body := "2026-10-10T08:00:01.000000000Z stdout F old\n2026-10-10T08:00:05.000000000Z stdout F new\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &Collector{files: map[string]*fileState{}, cursors: map[string]time.Time{}}
	cursor, _ := time.Parse(time.RFC3339Nano, "2026-10-10T08:00:01.000000000Z")
	entries, _, err := c.readFile(p, cursor)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Log != "new" {
		t.Fatalf("entries = %+v", entries)
	}
}
