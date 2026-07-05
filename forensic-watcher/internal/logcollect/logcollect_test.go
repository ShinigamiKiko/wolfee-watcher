package logcollect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wolfee-watcher/forensic-watcher/internal/fswatch"
)

func startCentral(t *testing.T, fail func(req int) bool) (*[][]fswatch.LogEntry, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	batches := &[][]fswatch.LogEntry{}
	req := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Node    string             `json:"node"`
			Entries []fswatch.LogEntry `json:"entries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode push body: %v", err)
		}
		if body.Node != "node-test" {
			t.Errorf("push body node = %q, want %q", body.Node, "node-test")
		}
		mu.Lock()
		defer mu.Unlock()
		req++
		if fail != nil && fail(req) {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		*batches = append(*batches, body.Entries)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("KVISIOR_URL", srv.URL)
	return batches, &mu
}

func writeBurst(t *testing.T, dir string, base time.Time, total int) (string, int) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	for i := 0; i < total; i++ {
		fmt.Fprintf(&sb, "%s stdout F line-%d\n",
			base.Add(time.Duration(i)*time.Millisecond).Format(time.RFC3339Nano), i)
	}
	logPath := filepath.Join(dir, "0.log")
	if err := os.WriteFile(logPath, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return logPath, sb.Len()
}

func flatten(batches [][]fswatch.LogEntry) []string {
	var out []string
	for _, b := range batches {
		for _, e := range b {
			out = append(out, e.Log)
		}
	}
	return out
}

func TestCollectContainerCommitsOffsetsWhenAllLinesPredateCursor(t *testing.T) {
	batches, mu := startCentral(t, nil)

	root := t.TempDir()
	dir := filepath.Join(root, "ns_pod_uid", "app")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "0.log")
	old := "2026-06-10T11:59:00.000000000Z stdout F already stored\n" +
		"2026-06-10T12:00:00.000000000Z stdout F cursor line\n"
	if err := os.WriteFile(logPath, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}

	c := New(root, "node-test", fswatch.NewCentralClient(), nil)
	cursor := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	c.cursors["ns/pod/app"] = cursor

	ct := container{ns: "ns", pod: "pod", name: "app", dir: dir}
	if err := c.collectContainer(context.Background(), ct); err != nil {
		t.Fatalf("collectContainer: %v", err)
	}
	mu.Lock()
	got := len(*batches)
	mu.Unlock()
	if got != 0 {
		t.Fatalf("pushed %d batch(es), want 0: every line is at or before the cursor", got)
	}
	st := c.files[logPath]
	if st == nil || st.offset != int64(len(old)) {
		t.Fatalf("offset not committed after empty batch: got %+v, want offset=%d", st, len(old))
	}

	fresh := "2026-06-10T12:01:00.000000000Z stdout F fresh line\n"
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(fresh); err != nil {
		t.Fatal(err)
	}
	f.Close()

	if err := c.collectContainer(context.Background(), ct); err != nil {
		t.Fatalf("collectContainer: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if lines := flatten(*batches); len(lines) != 1 || lines[0] != "fresh line" {
		t.Fatalf("delivered = %v, want exactly the fresh line", lines)
	}
	if want := int64(len(old) + len(fresh)); st.offset != want {
		t.Fatalf("offset = %d after push, want %d", st.offset, want)
	}
}

func TestCollectContainerDrainsBurstBeyondMaxLinesPerBatch(t *testing.T) {
	batches, mu := startCentral(t, nil)

	root := t.TempDir()
	dir := filepath.Join(root, "ns_pod_uid", "app")
	total := maxLinesPerBatch + 3
	base := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	logPath, size := writeBurst(t, dir, base, total)

	c := New(root, "node-test", fswatch.NewCentralClient(), nil)
	ct := container{ns: "ns", pod: "pod", name: "app", dir: dir}
	if err := c.collectContainer(context.Background(), ct); err != nil {
		t.Fatalf("collectContainer: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*batches) != 2 || len((*batches)[0]) != maxLinesPerBatch || len((*batches)[1]) != total-maxLinesPerBatch {
		sizes := make([]int, 0, len(*batches))
		for _, b := range *batches {
			sizes = append(sizes, len(b))
		}
		t.Fatalf("batch sizes = %v, want [%d %d]", sizes, maxLinesPerBatch, total-maxLinesPerBatch)
	}
	for i, line := range flatten(*batches) {
		if want := fmt.Sprintf("line-%d", i); line != want {
			t.Fatalf("delivered[%d] = %q, want %q (a line was dropped or reordered)", i, line, want)
		}
	}
	if st := c.files[logPath]; st == nil || st.offset != int64(size) {
		t.Fatalf("offset = %+v after full drain, want %d", st, size)
	}
	if want := base.Add(time.Duration(total-1) * time.Millisecond); !c.cursors["ns/pod/app"].Equal(want) {
		t.Fatalf("cursor = %v, want %v", c.cursors["ns/pod/app"], want)
	}
}

func TestCollectContainerSplitsChunksByBytes(t *testing.T) {
	batches, mu := startCentral(t, nil)

	root := t.TempDir()
	dir := filepath.Join(root, "ns_pod_uid", "app")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	big := strings.Repeat("x", maxLineBytes)
	total := maxChunkBytes/maxLineBytes + 40
	var sb strings.Builder
	for i := 0; i < total; i++ {
		fmt.Fprintf(&sb, "%s stdout F %s\n",
			base.Add(time.Duration(i)*time.Millisecond).Format(time.RFC3339Nano), big)
	}
	if err := os.WriteFile(filepath.Join(dir, "0.log"), []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	c := New(root, "node-test", fswatch.NewCentralClient(), nil)
	ct := container{ns: "ns", pod: "pod", name: "app", dir: dir}
	if err := c.collectContainer(context.Background(), ct); err != nil {
		t.Fatalf("collectContainer: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*batches) < 2 {
		t.Fatalf("got %d batch(es), want the poll split into byte-bounded chunks", len(*batches))
	}
	delivered := 0
	for i, b := range *batches {
		raw := 0
		for _, e := range b {
			raw += len(e.Log) + logEntryJSONOverhead
		}

		if raw > maxChunkBytes+maxLineBytes+logEntryJSONOverhead {
			t.Fatalf("chunk %d carries %d raw bytes, over the byte budget", i, raw)
		}
		delivered += len(b)
	}
	if delivered != total {
		t.Fatalf("delivered %d line(s), want %d", delivered, total)
	}
}

func TestCollectContainerResumesAfterMidDrainFailure(t *testing.T) {
	batches, mu := startCentral(t, func(req int) bool { return req == 2 })

	root := t.TempDir()
	dir := filepath.Join(root, "ns_pod_uid", "app")
	total := maxLinesPerBatch + 3
	base := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	logPath, _ := writeBurst(t, dir, base, total)

	c := New(root, "node-test", fswatch.NewCentralClient(), nil)
	ct := container{ns: "ns", pod: "pod", name: "app", dir: dir}
	if err := c.collectContainer(context.Background(), ct); err == nil {
		t.Fatal("collectContainer must report the failed chunk")
	}
	if st := c.files[logPath]; st == nil || st.offset != 0 {
		t.Fatalf("offset = %+v after failed drain, want rollback to 0", st)
	}

	if err := c.collectContainer(context.Background(), ct); err != nil {
		t.Fatalf("retry poll: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	lines := flatten(*batches)
	if len(lines) != total {
		t.Fatalf("delivered %d line(s) across the retry, want %d (loss or duplication)", len(lines), total)
	}
	for i, line := range lines {
		if want := fmt.Sprintf("line-%d", i); line != want {
			t.Fatalf("delivered[%d] = %q, want %q", i, line, want)
		}
	}
}
