package logcollect

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wolfee-watcher/forensic-watcher/internal/fswatch"
)

const (
	pollInterval     = 2 * time.Minute
	seedRetry        = 15 * time.Second
	maxLinesPerBatch = 5_000

	maxChunkBytes        = 8 << 20
	logEntryJSONOverhead = 64
	maxLineBytes         = 16 * 1024
	maxReadPerPoll       = 32 << 20
	pushTimeout          = 15 * time.Second
	pollConcurrency      = 4
)

type fileState struct {
	offset int64
	size   int64
}

type Collector struct {
	root    string
	node    string
	central *fswatch.CentralClient
	exclude map[string]bool

	mu      sync.Mutex
	cursors map[string]time.Time
	files   map[string]*fileState
}

func New(root, node string, central *fswatch.CentralClient, excludeNamespaces []string) *Collector {
	if central == nil {
		return nil
	}
	ex := make(map[string]bool, len(excludeNamespaces))
	for _, ns := range excludeNamespaces {
		if ns = strings.TrimSpace(ns); ns != "" {
			ex[ns] = true
		}
	}
	return &Collector{
		root:    root,
		node:    node,
		central: central,
		exclude: ex,
		cursors: make(map[string]time.Time),
		files:   make(map[string]*fileState),
	}
}

func (c *Collector) Run(ctx context.Context) {
	if _, err := os.Stat(c.root); err != nil {
		log.Printf("[logcollect] %s not readable (%v) — log collection disabled on node %s", c.root, err, c.node)
		return
	}

	if !c.seedCursors(ctx) {
		return
	}
	log.Printf("[logcollect] started on node=%s root=%s interval=%s exclude=%d ns", c.node, c.root, pollInterval, len(c.exclude))
	c.poll(ctx)
	t := time.NewTicker(pollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.poll(ctx)
		}
	}
}

func (c *Collector) seedCursors(ctx context.Context) bool {
	for {
		opCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		cursors, err := c.central.PullLogCursors(opCtx, c.node)
		cancel()
		if err == nil {
			if cursors == nil {
				cursors = make(map[string]time.Time)
			}
			c.mu.Lock()
			c.cursors = cursors
			c.mu.Unlock()
			log.Printf("[logcollect] seeded %d ingest cursor(s) from kvisior", len(cursors))
			return true
		}
		log.Printf("[logcollect] cursor seed failed: %v — retrying in %s", err, seedRetry)
		select {
		case <-ctx.Done():
			return false
		case <-time.After(seedRetry):
		}
	}
}

type container struct {
	ns, pod, name, dir string
}

func (c *Collector) poll(ctx context.Context) {
	containers := c.discover()

	seen := make(map[string]bool)
	for _, ct := range containers {
		seen[ct.dir] = true
	}
	c.pruneFiles(seen)

	sem := make(chan struct{}, pollConcurrency)
	var wg sync.WaitGroup
	for _, ct := range containers {
		wg.Add(1)
		sem <- struct{}{}
		go func(ct container) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := c.collectContainer(ctx, ct); err != nil && ctx.Err() == nil {
				log.Printf("[logcollect] %s/%s/%s: %v — cursor kept, retrying next poll", ct.ns, ct.pod, ct.name, err)
			}
		}(ct)
	}
	wg.Wait()
}

func (c *Collector) discover() []container {
	podDirs, err := os.ReadDir(c.root)
	if err != nil {
		log.Printf("[logcollect] read %s: %v", c.root, err)
		return nil
	}
	var out []container
	for _, pd := range podDirs {
		if !pd.IsDir() {
			continue
		}
		parts := strings.SplitN(pd.Name(), "_", 3)
		if len(parts) != 3 {
			continue
		}
		ns, pod := parts[0], parts[1]
		if c.exclude[ns] {
			continue
		}
		cDirs, err := os.ReadDir(filepath.Join(c.root, pd.Name()))
		if err != nil {
			continue
		}
		for _, cd := range cDirs {
			if !cd.IsDir() {
				continue
			}
			out = append(out, container{
				ns: ns, pod: pod, name: cd.Name(),
				dir: filepath.Join(c.root, pd.Name(), cd.Name()),
			})
		}
	}
	return out
}

func (c *Collector) collectContainer(ctx context.Context, ct container) error {
	key := ct.ns + "/" + ct.pod + "/" + ct.name
	c.mu.Lock()
	cursor := c.cursors[key]
	c.mu.Unlock()

	files, err := filepath.Glob(filepath.Join(ct.dir, "*.log"))
	if err != nil || len(files) == 0 {
		return nil
	}
	sort.Strings(files)

	var entries []fswatch.LogEntry
	for _, path := range files {
		fe, _, err := c.readFile(path, cursor)
		if err != nil {
			continue
		}
		entries = append(entries, fe...)
	}
	if len(entries) == 0 {

		c.commitFiles(files)
		return nil
	}

	for start := 0; start < len(entries); {
		end, chunkBytes := start, 0
		for end < len(entries) && end-start < maxLinesPerBatch && chunkBytes < maxChunkBytes {
			chunkBytes += len(entries[end].Log) + logEntryJSONOverhead
			end++
		}

		for end < len(entries) && entries[end].Ts.Equal(entries[end-1].Ts) {
			end++
		}
		chunk := entries[start:end]
		pushCtx, cancel := context.WithTimeout(ctx, pushTimeout)
		err := c.central.PushLogEntries(pushCtx, c.node, ct.ns, ct.pod, ct.name, chunk)
		cancel()
		if err != nil {

			c.rollbackFiles(files)
			return err
		}
		var chunkMax time.Time
		for _, e := range chunk {
			if e.Ts.After(chunkMax) {
				chunkMax = e.Ts
			}
		}
		c.mu.Lock()
		if chunkMax.After(c.cursors[key]) {
			c.cursors[key] = chunkMax
		}
		c.mu.Unlock()
		start = end
	}
	c.commitFiles(files)
	return nil
}

func (c *Collector) readFile(path string, cursor time.Time) ([]fswatch.LogEntry, time.Time, error) {
	var maxTs time.Time
	info, err := os.Stat(path)
	if err != nil {
		return nil, maxTs, err
	}
	c.mu.Lock()
	st, ok := c.files[path]
	if !ok {
		st = &fileState{}
		c.files[path] = st
	}
	start := st.offset
	if info.Size() < st.offset {
		start = 0
	}
	c.mu.Unlock()
	if info.Size() == start {
		return nil, maxTs, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, maxTs, err
	}
	defer f.Close()
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, maxTs, err
	}

	buf, err := io.ReadAll(io.LimitReader(f, maxReadPerPoll))
	if err != nil {
		return nil, maxTs, err
	}

	end := lastNewline(buf)
	if end < 0 {
		return nil, maxTs, nil
	}
	var entries []fswatch.LogEntry
	for _, line := range strings.Split(string(buf[:end]), "\n") {

		parts := strings.SplitN(line, " ", 4)
		if len(parts) < 4 {
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, parts[0])
		if err != nil {
			continue
		}
		if !ts.After(cursor) {
			continue
		}
		msg := strings.TrimSpace(parts[3])
		if msg == "" {
			continue
		}
		if len(msg) > maxLineBytes {
			msg = msg[:maxLineBytes]
		}
		entries = append(entries, fswatch.LogEntry{Ts: ts, Log: msg})
		if ts.After(maxTs) {
			maxTs = ts
		}
	}
	c.mu.Lock()
	st.size = start + int64(end) + 1
	c.mu.Unlock()
	return entries, maxTs, nil
}

func lastNewline(b []byte) int {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == '\n' {
			return i
		}
	}
	return -1
}

func (c *Collector) commitFiles(files []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range files {
		if st, ok := c.files[p]; ok {
			st.offset = st.size
		}
	}
}

func (c *Collector) rollbackFiles(files []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range files {
		if st, ok := c.files[p]; ok {
			st.size = st.offset
		}
	}
}

func (c *Collector) pruneFiles(liveDirs map[string]bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for p := range c.files {
		if !liveDirs[filepath.Dir(p)] {
			delete(c.files, p)
		}
	}
}
