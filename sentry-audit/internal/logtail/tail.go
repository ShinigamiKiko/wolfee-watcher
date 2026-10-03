package logtail

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	pollInterval   = time.Second
	maxLineBytes   = 1 << 20
	maxBatch       = 200
	checkpointName = "audit-tail.json"
	saveEvery      = 5 * time.Second
)

type Sink func(records []Record)

type Stats struct {
	Lines   atomic.Int64
	Sent    atomic.Int64
	Skipped atomic.Int64
	LastAt  atomic.Int64
}

type checkpoint struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

type Tailer struct {
	path     string
	stateDir string
	filter   Filter
	sink     Sink
	Stats    Stats

	file   *os.File
	reader *bufio.Reader
	line   []byte
	inode  uint64
	offset int64
	saved  time.Time
}

func New(path, stateDir string, filter Filter, sink Sink) *Tailer {
	return &Tailer{path: path, stateDir: stateDir, filter: filter, sink: sink}
}

func inodeOf(info os.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

func (t *Tailer) loadCheckpoint() (checkpoint, bool) {
	if t.stateDir == "" {
		return checkpoint{}, false
	}
	raw, err := os.ReadFile(filepath.Join(t.stateDir, checkpointName))
	if err != nil {
		return checkpoint{}, false
	}
	var cp checkpoint
	if json.Unmarshal(raw, &cp) != nil {
		return checkpoint{}, false
	}
	return cp, true
}

func (t *Tailer) saveCheckpoint(force bool) {
	if t.stateDir == "" || t.file == nil || (!force && time.Since(t.saved) < saveEvery) {
		return
	}
	t.saved = time.Now()
	raw, err := json.Marshal(checkpoint{Inode: t.inode, Offset: t.offset})
	if err != nil {
		return
	}
	tmp := filepath.Join(t.stateDir, checkpointName+".tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, filepath.Join(t.stateDir, checkpointName))
}

func (t *Tailer) open(first bool) error {
	f, err := os.Open(t.path)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	offset := int64(0)
	inode := inodeOf(info)
	if first {
		offset = info.Size()
		if cp, ok := t.loadCheckpoint(); ok && cp.Inode == inode && cp.Offset <= info.Size() {
			offset = cp.Offset
		}
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		f.Close()
		return err
	}
	if t.file != nil {
		t.file.Close()
	}
	t.file, t.reader, t.inode, t.offset = f, bufio.NewReaderSize(f, 256<<10), inode, offset
	slog.Info("audit_log_opened",
		"component", "sentry-audit/logtail",
		"path", t.path, "inode", inode, "offset", offset)
	return nil
}

func (t *Tailer) readLine() ([]byte, bool) {
	t.line = t.line[:0]
	consumed, tooLong := 0, false
	for {
		chunk, err := t.reader.ReadSlice('\n')
		consumed += len(chunk)
		if !tooLong {
			if len(t.line)+len(chunk) > maxLineBytes {
				tooLong = true
				t.line = t.line[:0]
			} else {
				t.line = append(t.line, chunk...)
			}
		}
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if _, seekErr := t.file.Seek(t.offset, io.SeekStart); seekErr == nil {
			t.reader.Reset(t.file)
		}
		return nil, false
	}
	t.offset += int64(consumed)
	t.Stats.Lines.Add(1)
	return t.line, true
}

func (t *Tailer) drain() {
	batch := make([]Record, 0, maxBatch)
	for {
		line, ok := t.readLine()
		if !ok {
			break
		}
		rec, keep := t.filter.Parse(line)
		if !keep {
			t.Stats.Skipped.Add(1)
			continue
		}
		batch = append(batch, rec)
		if len(batch) == maxBatch {
			t.sink(batch)
			t.Stats.Sent.Add(int64(len(batch)))
			batch = make([]Record, 0, maxBatch)
		}
	}
	if len(batch) > 0 {
		t.sink(batch)
		t.Stats.Sent.Add(int64(len(batch)))
	}
	t.Stats.LastAt.Store(time.Now().Unix())
}

func (t *Tailer) rotated() bool {
	info, err := os.Stat(t.path)
	if err != nil {
		return false
	}
	return inodeOf(info) != t.inode || info.Size() < t.offset
}

func (t *Tailer) Run(ctx context.Context) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	first, warned := true, false
	for {
		if t.file == nil {
			if err := t.open(first); err != nil {
				if !warned {
					slog.Warn("audit_log_unavailable",
						"component", "sentry-audit/logtail",
						"path", t.path, "error", err,
						"hint", "start kube-apiserver with --audit-log-path and --audit-policy-file")
					warned = true
				}
			} else {
				first, warned = false, false
			}
		}
		if t.file != nil {
			t.drain()
			if t.rotated() {
				t.drain()
				if err := t.open(false); err != nil {
					t.file.Close()
					t.file = nil
				}
			}
			t.saveCheckpoint(false)
		}
		select {
		case <-ctx.Done():
			t.saveCheckpoint(true)
			if t.file != nil {
				t.file.Close()
			}
			return
		case <-ticker.C:
		}
	}
}
