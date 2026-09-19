package bdu

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

const (
	maxArchiveSize = 200 << 20
	maxXMLSize     = 1 << 30
)

func logRefreshFailure(prefix string, err error) {
	log.Printf("[bdu] %s: %v (keeping previous map)", prefix, err)
}

type source struct {
	r     io.Reader
	name  string
	close func()
}

type cappedReader struct {
	r    io.Reader
	max  int64
	read int64
	what string
}

func (c *cappedReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += int64(n)
	if c.read > c.max {
		return n, fmt.Errorf("%s exceeds %d bytes", c.what, c.max)
	}
	return n, err
}

func (e *Enricher) refresh(ctx context.Context) error {
	src, err := e.openSource(ctx)
	if err != nil {
		e.setLastErr(err)
		return err
	}
	newMap, newDetails, err := parseBDU(src.r, e.noDetail)
	src.close()
	if err != nil {
		e.setLastErr(err)
		return fmt.Errorf("parse: %w", err)
	}

	e.mu.Lock()
	e.cveToBdu = newMap
	e.bduDetails = newDetails
	e.lastFetch = time.Now()
	e.lastErr = nil
	e.mu.Unlock()

	runtime.GC()
	debug.FreeOSMemory()

	if e.noDetail {
		log.Printf("[bdu] refreshed: %d CVE->BDU mappings loaded from %s (detail disabled)", len(newMap), src.name)
	} else {
		log.Printf("[bdu] refreshed: %d CVE->BDU mappings, %d full details loaded from %s", len(newMap), len(newDetails), src.name)
	}
	return nil
}

func (e *Enricher) openSource(ctx context.Context) (*source, error) {
	if e.localPath != "" {
		f, err := os.Open(e.localPath)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", e.localPath, err)
		}
		src, err := xmlSource(f, e.localPath, nil)
		if err != nil {
			f.Close()
			return nil, err
		}
		return src, nil
	}
	return e.download(ctx)
}

func (e *Enricher) download(ctx context.Context) (*source, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.archiveURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "wolfee-watcher-scanner-agent/1.0 (+bdu-enricher)")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d from %s", resp.StatusCode, e.archiveURL)
	}

	tmp, err := os.CreateTemp("", "bdu-*.archive")
	if err != nil {
		return nil, err
	}
	remove := func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}
	if _, err := io.Copy(tmp, &cappedReader{r: resp.Body, max: maxArchiveSize, what: "archive"}); err != nil {
		remove()
		return nil, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		remove()
		return nil, err
	}
	src, err := xmlSource(tmp, e.archiveURL, remove)
	if err != nil {
		remove()
		return nil, err
	}
	return src, nil
}

func xmlSource(f *os.File, name string, cleanup func()) (*source, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	closeAll := func() {
		if cleanup != nil {
			cleanup()
			return
		}
		f.Close()
	}

	var magic [2]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if magic[0] != 'P' || magic[1] != 'K' {
		if st.Size() > maxXMLSize {
			return nil, fmt.Errorf("%s exceeds %d bytes", name, int64(maxXMLSize))
		}
		return &source{r: f, name: name, close: closeAll}, nil
	}

	zr, err := zip.NewReader(f, st.Size())
	if err != nil {
		return nil, err
	}
	for _, zf := range zr.File {
		if !strings.HasSuffix(strings.ToLower(zf.Name), ".xml") {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, err
		}
		return &source{
			r:    &cappedReader{r: rc, max: maxXMLSize, what: "decompressed xml"},
			name: name,
			close: func() {
				rc.Close()
				closeAll()
			},
		}, nil
	}
	return nil, fmt.Errorf("no .xml inside zip")
}

func (e *Enricher) setLastErr(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastErr = err
}
