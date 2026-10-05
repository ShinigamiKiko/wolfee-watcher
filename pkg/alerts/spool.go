package alerts

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	ErrSpoolFull         = errors.New("audit spool capacity exhausted")
	ErrPermanentDelivery = errors.New("delivery permanently rejected")
	errSpoolCorrupt      = errors.New("unreadable spool file")
)

const (
	spoolDeadDir      = "dead"
	spoolBlock        = 4096
	segmentMaxRecords = 4000
	segmentMaxBytes   = 8 << 20
	compactMinFiles   = 16
	compactEagerFiles = 256
)

func blocks(n int64) int64 { return (n + spoolBlock - 1) / spoolBlock * spoolBlock }

type DiskSpool struct {
	dir                    string
	limit                  int64
	deliver                func(context.Context, []json.RawMessage) error
	lock                   *os.File
	jobs                   chan spoolJob
	wake                   chan struct{}
	pressure               chan struct{}
	ctx                    context.Context
	cancel                 context.CancelFunc
	writerDone, senderDone chan struct{}
	admissionMu            sync.RWMutex
	closed                 bool
	mu                     sync.Mutex
	files                  []spoolFile
	bytes                  int64
	deadFiles              int
	deadBytes              int64
	quarantined            uint64
	sequence               int64
	lastError              string
	rejected               uint64
	late                   uint64
	compacted              uint64
	probe                  func(context.Context) error
}
type spoolFile struct {
	name string
	size int64
}
type spoolJob struct {
	raw  json.RawMessage
	done chan error
}
type SpoolStatus struct {
	Durable     bool   `json:"durable"`
	Pending     int    `json:"pending"`
	Bytes       int64  `json:"bytes"`
	Capacity    int64  `json:"capacity"`
	Rejected    uint64 `json:"rejected"`
	Late        uint64 `json:"late"`
	Quarantined uint64 `json:"quarantined"`
	DeadFiles   int    `json:"deadFiles"`
	DeadBytes   int64  `json:"deadBytes"`
	Compacted   uint64 `json:"compacted"`
	LastError   string `json:"lastError,omitempty"`
}

func NewDiskSpool(dir string, limit int64, deliver func(context.Context, []json.RawMessage) error) (*DiskSpool, error) {
	if dir == "" || limit <= 0 || deliver == nil {
		return nil, fmt.Errorf("invalid spool configuration")
	}
	if err := os.MkdirAll(filepath.Join(dir, spoolDeadDir), 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("spool already in use: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	q := &DiskSpool{dir: dir, limit: limit, deliver: deliver, lock: lock, jobs: make(chan spoolJob, 256), wake: make(chan struct{}, 1), pressure: make(chan struct{}, 1), ctx: ctx, cancel: cancel, writerDone: make(chan struct{}), senderDone: make(chan struct{}), sequence: time.Now().UnixNano()}
	fail := func(err error) (*DiskSpool, error) {
		lock.Close()
		cancel()
		return nil, err
	}
	pending, size, err := q.scan(dir, true)
	if err != nil {
		return fail(err)
	}
	dead, deadSize, err := q.scan(filepath.Join(dir, spoolDeadDir), false)
	if err != nil {
		return fail(err)
	}
	q.files, q.bytes, q.deadFiles, q.deadBytes = pending, size, len(dead), deadSize
	go q.writeLoop()
	go q.sendLoop()
	return q, nil
}

func (q *DiskSpool) scan(dir string, strict bool) ([]spoolFile, int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, err
	}
	var files []spoolFile
	var total int64
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".tmp") {
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				return nil, 0, err
			}
			continue
		}
		if !strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".json.gz") {
			continue
		}
		seq, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimSuffix(name, ".gz"), ".json"), 10, 64)
		if err != nil || entry.IsDir() {
			if strict {
				return nil, 0, fmt.Errorf("invalid spool file %q", name)
			}
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, 0, err
		}
		files = append(files, spoolFile{name, blocks(info.Size())})
		total += blocks(info.Size())
		if seq > q.sequence {
			q.sequence = seq
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	return files, total, nil
}

func (q *DiskSpool) Enqueue(ctx context.Context, raw json.RawMessage) error {
	if !json.Valid(raw) || len(raw) > 1<<20 {
		return fmt.Errorf("invalid or oversized spool record")
	}
	job := spoolJob{raw: append(json.RawMessage(nil), raw...), done: make(chan error, 1)}
	q.admissionMu.RLock()
	if q.closed {
		q.admissionMu.RUnlock()
		return fmt.Errorf("spool closed")
	}
	select {
	case q.jobs <- job:
	default:
		q.admissionMu.RUnlock()
		q.reject(ErrSpoolFull, 1)
		return ErrSpoolFull
	}
	q.admissionMu.RUnlock()
	select {
	case err := <-job.done:
		return err
	case <-ctx.Done():
		q.mu.Lock()
		q.late++
		q.mu.Unlock()
		return ctx.Err()
	}
}
func (q *DiskSpool) reject(err error, records int) {
	q.mu.Lock()
	q.rejected += uint64(records)
	q.lastError = err.Error()
	q.mu.Unlock()
}
func (q *DiskSpool) Status() SpoolStatus {
	q.mu.Lock()
	defer q.mu.Unlock()
	return SpoolStatus{
		Durable: true, Pending: len(q.files), Bytes: q.bytes, Capacity: q.limit, Rejected: q.rejected, Late: q.late,
		Quarantined: q.quarantined, DeadFiles: q.deadFiles, DeadBytes: q.deadBytes, Compacted: q.compacted, LastError: q.lastError,
	}
}
func (q *DiskSpool) writeLoop() {
	defer close(q.writerDone)
	for first := range q.jobs {
		jobs := []spoolJob{first}
		size := len(first.raw)
		for len(jobs) < 64 && size < 512<<10 {
			select {
			case job, ok := <-q.jobs:
				if !ok {
					goto persist
				}
				jobs = append(jobs, job)
				size += len(job.raw)
			default:
				goto persist
			}
		}
	persist:
		raws := make([]json.RawMessage, 0, len(jobs))
		for _, job := range jobs {
			raws = append(raws, job.raw)
		}
		err := q.persist(raws)
		if err != nil {
			q.reject(err, len(jobs))
		}
		for _, job := range jobs {
			job.done <- err
		}
	}
}
func (q *DiskSpool) persist(raws []json.RawMessage) error {
	data, err := json.Marshal(raws)
	if err != nil {
		return err
	}
	size := blocks(int64(len(data)))
	q.mu.Lock()
	if q.bytes+q.deadBytes+size > q.limit {
		q.mu.Unlock()
		return ErrSpoolFull
	}
	q.sequence++
	name := fmt.Sprintf("%020d.json", q.sequence)
	q.mu.Unlock()
	if err := writeSynced(q.dir, name, data); err != nil {
		return err
	}
	syncErr := syncSpoolDir(q.dir)
	q.mu.Lock()
	q.files = append(q.files, spoolFile{name, size})
	q.bytes += size
	crowded := q.bytes+q.deadBytes >= q.limit/2
	if syncErr != nil {
		q.lastError = "sync spool directory: " + syncErr.Error()
	}
	q.mu.Unlock()
	if syncErr != nil {
		slog.Warn("audit_spool_dir_sync_failed", "component", "alerts/spool", "file", name, "error", syncErr)
	}
	select {
	case q.wake <- struct{}{}:
	default:
	}
	if crowded {
		select {
		case q.pressure <- struct{}{}:
		default:
		}
	}
	return nil
}
func writeSynced(dir, name string, data []byte) error {
	tmp := filepath.Join(dir, name+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(dir, name))
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}
func syncSpoolDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func (q *DiskSpool) head() string {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.files) == 0 {
		return ""
	}
	return q.files[0].name
}
func (q *DiskSpool) sendLoop() {
	defer close(q.senderDone)
	retry := time.Second
	for q.ctx.Err() == nil {
		name := q.head()
		if name == "" {
			select {
			case <-q.ctx.Done():
				return
			case <-q.wake:
			}
			continue
		}
		if q.pending() >= compactEagerFiles {
			q.compact(compactMinFiles)
		}
		err := q.send(name)
		if err == nil {
			retry = time.Second
			continue
		}
		q.mu.Lock()
		q.lastError = err.Error()
		q.mu.Unlock()
		q.compact(compactMinFiles)
		for deadline := time.Now().Add(retry); time.Now().Before(deadline); {
			wait := time.Until(deadline)
			probe := q.prober()
			if probe != nil {
				wait = min(wait, SpoolProbeInterval)
			}
			select {
			case <-q.ctx.Done():
				return
			case <-time.After(wait):
				if probe != nil && time.Now().Before(deadline) && q.reachable(probe) {
					deadline = time.Now()
				}
			case <-q.pressure:
				q.compact(2)
			}
		}
		retry = min(2*retry, 30*time.Second)
	}
}

const SpoolProbeInterval = 2 * time.Second

func (q *DiskSpool) SetProbe(probe func(context.Context) error) {
	q.mu.Lock()
	q.probe = probe
	q.mu.Unlock()
}

func (q *DiskSpool) prober() func(context.Context) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.probe
}

func (q *DiskSpool) reachable(probe func(context.Context) error) bool {
	ctx, cancel := context.WithTimeout(q.ctx, SpoolProbeInterval)
	defer cancel()
	return probe(ctx) == nil
}
func (q *DiskSpool) pending() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.files)
}

func readSpoolFile(path string) ([]json.RawMessage, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	if strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, 0, fmt.Errorf("%w: %v", errSpoolCorrupt, err)
		}
		if data, err = io.ReadAll(zr); err != nil {
			return nil, 0, fmt.Errorf("%w: %v", errSpoolCorrupt, err)
		}
	}
	var raws []json.RawMessage
	if err := json.Unmarshal(data, &raws); err != nil {
		return nil, 0, fmt.Errorf("%w: %v", errSpoolCorrupt, err)
	}
	return raws, len(data), nil
}

func (q *DiskSpool) send(name string) error {
	raws, _, err := readSpoolFile(filepath.Join(q.dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return q.forget(name)
	}
	if errors.Is(err, errSpoolCorrupt) {
		return q.quarantineFile(name, err)
	}
	if err != nil {
		return err
	}
	err = q.deliver(q.ctx, raws)
	if errors.Is(err, ErrPermanentDelivery) {
		dead := raws
		if len(raws) > 1 {
			dead = nil
			for _, raw := range raws {
				switch single := q.deliver(q.ctx, []json.RawMessage{raw}); {
				case single == nil:
				case errors.Is(single, ErrPermanentDelivery):
					dead = append(dead, raw)
				default:
					return single
				}
			}
		}
		if err = q.quarantineRecords(name, dead, err); err != nil {
			return err
		}
	}
	if err != nil {
		return err
	}
	if err = os.Remove(filepath.Join(q.dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return q.forget(name)
}
func (q *DiskSpool) dropHead(name string) int64 {
	if len(q.files) == 0 || q.files[0].name != name {
		return 0
	}
	size := q.files[0].size
	q.files = q.files[1:]
	q.bytes -= size
	return size
}
func (q *DiskSpool) forget(name string) error {
	syncErr := syncSpoolDir(q.dir)
	q.mu.Lock()
	defer q.mu.Unlock()
	q.dropHead(name)
	if syncErr == nil {
		q.lastError = ""
	} else {
		q.lastError = syncErr.Error()
	}
	return nil
}
func (q *DiskSpool) quarantineRecords(name string, dead []json.RawMessage, cause error) error {
	if len(dead) == 0 {
		return nil
	}
	data, err := json.Marshal(dead)
	if err != nil {
		return err
	}
	deadDir := filepath.Join(q.dir, spoolDeadDir)
	deadName := strings.TrimSuffix(name, ".gz")
	if _, err := os.Stat(filepath.Join(deadDir, deadName)); err == nil {
		return nil
	}
	if err = writeSynced(deadDir, deadName, data); err != nil {
		return err
	}
	if err = syncSpoolDir(deadDir); err != nil {
		return err
	}
	q.mu.Lock()
	q.deadFiles++
	q.deadBytes += blocks(int64(len(data)))
	q.quarantined += uint64(len(dead))
	q.mu.Unlock()
	slog.Error("audit_spool_records_quarantined", "component", "alerts/spool", "file", name, "records", len(dead), "error", cause)
	return nil
}
func (q *DiskSpool) quarantineFile(name string, cause error) error {
	deadDir := filepath.Join(q.dir, spoolDeadDir)
	if err := os.Rename(filepath.Join(q.dir, name), filepath.Join(deadDir, name)); err != nil {
		return err
	}
	if err := syncSpoolDir(deadDir); err != nil {
		return err
	}
	q.mu.Lock()
	size := q.dropHead(name)
	q.deadFiles++
	q.deadBytes += size
	q.quarantined++
	q.mu.Unlock()
	slog.Error("audit_spool_file_quarantined", "component", "alerts/spool", "file", name, "error", cause)
	return syncSpoolDir(q.dir)
}
func (q *DiskSpool) compact(minFiles int) {
	q.mu.Lock()
	snapshot := append([]spoolFile(nil), q.files...)
	q.mu.Unlock()
	if len(snapshot) < minFiles {
		return
	}
	for i := 0; i < len(snapshot) && q.ctx.Err() == nil; {
		run, records := q.collectRun(snapshot[i:])
		if len(run) < 2 {
			i += max(len(run), 1)
			continue
		}
		if err := q.writeSegment(run, records); err != nil {
			q.mu.Lock()
			q.lastError = "compact: " + err.Error()
			q.mu.Unlock()
			return
		}
		i += len(run)
	}
}

func (q *DiskSpool) collectRun(files []spoolFile) ([]spoolFile, []json.RawMessage) {
	var run []spoolFile
	var records []json.RawMessage
	size := 0
	for _, f := range files {
		raws, n, err := readSpoolFile(filepath.Join(q.dir, f.name))
		if err != nil {
			if len(run) == 0 {
				return []spoolFile{f}, nil
			}
			break
		}
		if len(run) > 0 && (len(records)+len(raws) > segmentMaxRecords || size+n > segmentMaxBytes) {
			break
		}
		run = append(run, f)
		records = append(records, raws...)
		size += n
		if len(records) >= segmentMaxRecords || size >= segmentMaxBytes {
			break
		}
	}
	return run, records
}

func (q *DiskSpool) writeSegment(run []spoolFile, records []json.RawMessage) error {
	data, err := json.Marshal(records)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err = zw.Write(data); err == nil {
		err = zw.Close()
	}
	if err != nil {
		return err
	}
	name := strings.TrimSuffix(strings.TrimSuffix(run[0].name, ".gz"), ".json") + ".json.gz"
	if err = writeSynced(q.dir, name, buf.Bytes()); err != nil {
		return err
	}
	if err = syncSpoolDir(q.dir); err != nil {
		return err
	}
	segment := spoolFile{name, blocks(int64(buf.Len()))}
	q.mu.Lock()
	at := -1
	for i := range q.files {
		if q.files[i].name == run[0].name {
			at = i
			break
		}
	}
	if at < 0 || at+len(run) > len(q.files) {
		q.mu.Unlock()
		return fmt.Errorf("spool changed during compaction")
	}
	var removed int64
	for i, f := range run {
		if q.files[at+i].name != f.name {
			q.mu.Unlock()
			return fmt.Errorf("spool changed during compaction")
		}
		removed += q.files[at+i].size
	}
	q.files = append(append(append([]spoolFile(nil), q.files[:at]...), segment), q.files[at+len(run):]...)
	q.bytes += segment.size - removed
	q.compacted += uint64(len(run))
	q.mu.Unlock()
	for _, f := range run {
		if f.name != name {
			os.Remove(filepath.Join(q.dir, f.name))
		}
	}
	return syncSpoolDir(q.dir)
}

func (q *DiskSpool) Close() {
	q.admissionMu.Lock()
	if q.closed {
		q.admissionMu.Unlock()
		<-q.senderDone
		return
	}
	q.closed = true
	close(q.jobs)
	q.admissionMu.Unlock()
	<-q.writerDone
	q.cancel()
	<-q.senderDone
	syscall.Flock(int(q.lock.Fd()), syscall.LOCK_UN)
	q.lock.Close()
}
