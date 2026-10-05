package logtail

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProbe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	if ok, detail := Probe(path); ok || !strings.Contains(detail, "does not exist") {
		t.Errorf("missing file: ok=%v detail=%q", ok, detail)
	}
	if ok, detail := Probe(dir); ok || !strings.Contains(detail, "directory") {
		t.Errorf("directory: ok=%v detail=%q", ok, detail)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, detail := Probe(path); ok || !strings.Contains(detail, "empty") {
		t.Errorf("empty file: ok=%v detail=%q", ok, detail)
	}
	if err := os.WriteFile(path, []byte("plain text log\nnot json at all\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, detail := Probe(path); ok || !strings.Contains(detail, "not a Kubernetes audit record") {
		t.Errorf("foreign file: ok=%v detail=%q", ok, detail)
	}
	appendLine(t, path, line("create", "alice", "configmaps", "prod", "one", "", 201, "")+"\n")
	appendLine(t, path, strings.Replace(line("get", "alice", "pods", "prod", "two", "", 200, ""),
		`"annotations"`, `"stageTimestamp":"2026-10-01T10:00:00.000000Z","annotations"`, 1)+"\n")
	ok, detail := Probe(path)
	if !ok || !strings.Contains(detail, "is readable") || !strings.Contains(detail, "last record") {
		t.Errorf("audit log: ok=%v detail=%q", ok, detail)
	}
}
