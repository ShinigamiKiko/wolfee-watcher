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
	"sort"
	"strings"
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
	maxBackoff     = 30 * time.Second
	probeInterval  = 2 * time.Second
)

var ErrRejected = errors.New("logtail: batch rejected by receiver")

type Sink func(context.Context, []Record) error

const (
	StateStarting = "starting"
	StateReading  = "reading"
	StateNoFile   = "no-file"
	StateFailing  = "delivery-failing"
)

type Stats struct {
	Lines        atomic.Int64
	Sent         atomic.Int64
	Skipped      atomic.Int64
	Rejected     atomic.Int64
	LastAt       atomic.Int64
	LastSentAt   atomic.Int64
	LastRecordTs atomic.Int64
}

type Status struct {
	Path         string     `json:"path"`
	State        string     `json:"state"`
	Error        string     `json:"error,omitempty"`
	LastRecordAt *time.Time `json:"lastRecordAt,omitempty"`
	Lines        int64      `json:"lines"`
	Sent         int64      `json:"sent"`
	Rejected     int64      `json:"rejected"`
	BacklogBytes int64      `json:"backlogBytes"`
	BacklogFiles int        `json:"backlogFiles"`
	LagSeconds   int64      `json:"lagSeconds"`
	Headroom     *int       `json:"headroom,omitempty"`
}

type backlog struct {
	bytes    int64
	files    int
	rotated  bool
	headroom int
}

type checkpoint struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
	Mtime  int64  `json:"mtime,omitempty"`
}

type logFile struct {
	path  string
	inode uint64
	mtime time.Time
	size  int64
}

type Tailer struct {
	path     string
	stateDir string
	filter   Filter
	sink     Sink
	Stats    Stats
	Probe    func(context.Context) error

	file       *os.File
	reader     *bufio.Reader
	line       []byte
	inode      uint64
	offset     int64
	committed  int64
	pending    []Record
	pendingEnd int64
	saved      time.Time
	written    checkpoint
	state      atomic.Value
	backlog    atomic.Value
	riskWarned time.Time
}

type tailState struct {
	name string
	err  string
}

func New(path, stateDir string, filter Filter, sink Sink) *Tailer {
	t := &Tailer{path: path, stateDir: stateDir, filter: filter, sink: sink}
	t.setState(StateStarting, nil)
	return t
}

func (t *Tailer) setState(name string, err error) {
	s := tailState{name: name}
	if err != nil {
		s.err = err.Error()
	}
	t.state.Store(s)
}

func (t *Tailer) Status() Status {
	s, _ := t.state.Load().(tailState)
	out := Status{
		Path: t.path, State: s.name, Error: s.err,
		Lines: t.Stats.Lines.Load(), Sent: t.Stats.Sent.Load(), Rejected: t.Stats.Rejected.Load(),
	}
	if ns := t.Stats.LastSentAt.Load(); ns > 0 {
		at := time.Unix(0, ns).UTC()
		out.LastRecordAt = &at
	}
	if b, ok := t.backlog.Load().(backlog); ok {
		out.BacklogBytes, out.BacklogFiles = b.bytes, b.files
		if b.rotated {
			headroom := b.headroom
			out.Headroom = &headroom
		}
		if ns := t.Stats.LastRecordTs.Load(); b.bytes > 0 && ns > 0 {
			out.LagSeconds = max(int64(time.Since(time.Unix(0, ns)).Seconds()), 0)
		}
	}
	return out
}

func (t *Tailer) measure() {
	if t.file == nil {
		t.backlog.Store(backlog{})
		return
	}
	cur, err := t.file.Stat()
	if err != nil {
		return
	}
	b := backlog{bytes: max(cur.Size()-t.committed, 0)}
	if b.bytes > 0 {
		b.files = 1
	}
	live, liveErr := os.Stat(t.path)
	if liveErr != nil || inodeOf(live) != t.inode {
		b.rotated = true
		for _, f := range t.retained() {
			if f.inode != t.inode && f.mtime.After(cur.ModTime()) {
				b.bytes += f.size
				b.files++
			} else {
				b.headroom++
			}
		}
		if liveErr == nil {
			b.bytes += live.Size()
			b.files++
		}
	}
	t.backlog.Store(b)
	if b.rotated && b.headroom <= 1 && time.Since(t.riskWarned) > time.Minute {
		t.riskWarned = time.Now()
		slog.Warn("audit_log_backlog_at_risk",
			"component", "sentry-audit/logtail",
			"backlog_bytes", b.bytes, "backlog_files", b.files, "headroom", b.headroom)
	}
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
	if json.Unmarshal(raw, &cp) != nil || cp.Inode == 0 || cp.Offset < 0 {
		return checkpoint{}, false
	}
	return cp, true
}

func (t *Tailer) saveCheckpoint(force bool) {
	if t.stateDir == "" || t.file == nil || (!force && time.Since(t.saved) < saveEvery) {
		return
	}
	if !t.saved.IsZero() && t.written.Inode == t.inode && t.written.Offset == t.committed {
		return
	}
	cp := checkpoint{Inode: t.inode, Offset: t.committed}
	if info, err := t.file.Stat(); err == nil {
		cp.Mtime = info.ModTime().UnixNano()
	}
	raw, _ := json.Marshal(cp)
	tmp := filepath.Join(t.stateDir, checkpointName+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err == nil {
		_, err = f.Write(raw)
		if err == nil {
			err = f.Sync()
		}
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(t.stateDir, checkpointName))
	}
	if err == nil {
		if dir, openErr := os.Open(t.stateDir); openErr == nil {
			err = dir.Sync()
			dir.Close()
		} else {
			err = openErr
		}
	}
	if err != nil {
		slog.Warn("audit_checkpoint_failed", "component", "sentry-audit/logtail", "error", err)
		return
	}
	t.saved, t.written = time.Now(), cp
}

func (t *Tailer) retained() []logFile {
	dir, base := filepath.Split(t.path)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []logFile
	for _, entry := range entries {
		name := entry.Name()
		if name == base || strings.HasSuffix(name, ".gz") {
			continue
		}
		timestamped := strings.HasPrefix(name, stem+"-") && filepath.Ext(name) == ext
		numbered := strings.HasPrefix(name, base+".")
		if !timestamped && !numbered {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		out = append(out, logFile{path: filepath.Join(dir, name), inode: inodeOf(info), mtime: info.ModTime(), size: info.Size()})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].mtime.Equal(out[j].mtime) {
			return out[i].mtime.Before(out[j].mtime)
		}
		return out[i].path < out[j].path
	})
	return out
}

func (t *Tailer) successor() string {
	cur, err := t.file.Stat()
	if err != nil {
		return t.path
	}
	files := t.retained()
	curPath := ""
	for _, f := range files {
		if f.inode == t.inode {
			curPath = f.path
		}
	}
	for _, f := range files {
		if f.inode == t.inode {
			continue
		}
		if f.mtime.After(cur.ModTime()) || (curPath != "" && f.mtime.Equal(cur.ModTime()) && f.path > curPath) {
			return f.path
		}
	}
	return t.path
}

func (t *Tailer) start() (string, int64, error) {
	info, err := os.Stat(t.path)
	if err != nil {
		return "", 0, err
	}
	cp, ok := t.loadCheckpoint()
	if !ok {
		return t.path, info.Size(), nil
	}
	if cp.Inode == inodeOf(info) {
		if cp.Offset <= info.Size() {
			return t.path, cp.Offset, nil
		}
		return t.path, 0, nil
	}
	files := t.retained()
	for _, f := range files {
		if f.inode == cp.Inode && cp.Offset <= f.size {
			return f.path, cp.Offset, nil
		}
	}
	if cp.Mtime != 0 {
		last := time.Unix(0, cp.Mtime)
		for _, f := range files {
			if !f.mtime.Before(last) {
				slog.Warn("audit_log_checkpoint_file_gone",
					"component", "sentry-audit/logtail",
					"inode", cp.Inode, "resume_from", f.path)
				return f.path, 0, nil
			}
		}
	}
	return t.path, 0, nil
}

func (t *Tailer) open(first bool) error {
	path, offset := t.path, int64(0)
	if first {
		var err error
		if path, offset, err = t.start(); err != nil {
			return err
		}
	} else if t.file != nil {
		path = t.successor()
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	if offset > info.Size() {
		offset = 0
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		f.Close()
		return err
	}
	if t.file != nil {
		t.file.Close()
	}
	t.file, t.reader, t.inode, t.offset, t.committed = f, bufio.NewReaderSize(f, 256<<10), inodeOf(info), offset, offset
	t.pending, t.pendingEnd = nil, 0
	t.saveCheckpoint(true)
	slog.Info("audit_log_opened",
		"component", "sentry-audit/logtail",
		"path", path, "inode", t.inode, "offset", offset)
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

func (t *Tailer) send(ctx context.Context, batch []Record) error {
	err := t.sink(ctx, batch)
	if err == nil {
		t.Stats.Sent.Add(int64(len(batch)))
		t.Stats.LastSentAt.Store(time.Now().UnixNano())
		if ts := batch[len(batch)-1].Event.Timestamp; !ts.IsZero() {
			t.Stats.LastRecordTs.Store(ts.UnixNano())
		}
		return nil
	}
	if !errors.Is(err, ErrRejected) {
		return err
	}
	if len(batch) == 1 {
		t.Stats.Rejected.Add(1)
		slog.Error("audit_record_rejected",
			"component", "sentry-audit/logtail",
			"audit_id", batch[0].Event.AuditID, "error", err)
		return nil
	}
	mid := len(batch) / 2
	if err := t.send(ctx, batch[:mid]); err != nil {
		return err
	}
	return t.send(ctx, batch[mid:])
}

func (t *Tailer) drain(ctx context.Context) error {
	if len(t.pending) > 0 {
		if err := t.send(ctx, t.pending); err != nil {
			return err
		}
		t.committed = t.pendingEnd
		t.pending, t.pendingEnd = nil, 0
		t.saveCheckpoint(false)
	}
	batch := make([]Record, 0, maxBatch)
	flush := func() error {
		if len(batch) != 0 {
			if err := t.send(ctx, batch); err != nil {
				t.pending, t.pendingEnd = batch, t.offset
				return err
			}
			batch = make([]Record, 0, maxBatch)
		}
		t.committed = t.offset
		t.saveCheckpoint(false)
		return nil
	}
	for {
		if ctx.Err() != nil {
			return flush()
		}
		line, ok := t.readLine()
		if !ok {
			break
		}
		rec, keep := t.filter.Parse(line)
		if !keep {
			t.Stats.Skipped.Add(1)
			if len(batch) == 0 {
				t.committed = t.offset
			}
			continue
		}
		batch = append(batch, rec)
		if len(batch) == maxBatch {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := flush(); err != nil {
		return err
	}
	t.Stats.LastAt.Store(time.Now().Unix())
	return nil
}

func (t *Tailer) rotated() bool {
	info, err := os.Stat(t.path)
	if err != nil {
		return false
	}
	return inodeOf(info) != t.inode || info.Size() < t.offset
}

func (t *Tailer) Run(ctx context.Context) {
	defer func() {
		t.saveCheckpoint(true)
		if t.file != nil {
			t.file.Close()
		}
	}()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	first, warned := true, false
	var backoff time.Duration
	var retryAt, probedAt time.Time
	for {
		if t.file == nil {
			if err := t.open(first); err != nil {
				t.setState(StateNoFile, err)
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
		if t.file != nil && t.Probe != nil && time.Now().Before(retryAt) && time.Since(probedAt) >= probeInterval {
			probedAt = time.Now()
			probeCtx, cancel := context.WithTimeout(ctx, probeInterval)
			if t.Probe(probeCtx) == nil {
				retryAt = time.Time{}
			}
			cancel()
		}
		if t.file != nil && !time.Now().Before(retryAt) {
			err := t.drain(ctx)
			for err == nil && t.rotated() {
				if err = t.drain(ctx); err != nil {
					break
				}
				if openErr := t.open(false); openErr != nil {
					t.file.Close()
					t.file = nil
					break
				}
				err = t.drain(ctx)
			}
			if err == nil {
				backoff = 0
				t.setState(StateReading, nil)
			} else if ctx.Err() == nil {
				t.setState(StateFailing, err)
				backoff = min(max(2*backoff, pollInterval), maxBackoff)
				retryAt = time.Now().Add(backoff)
				slog.Warn("audit_delivery_failed",
					"component", "sentry-audit/logtail",
					"error", err, "retry_in", backoff.String())
			}
			t.saveCheckpoint(false)
		}
		t.measure()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
