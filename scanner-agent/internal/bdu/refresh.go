package bdu

import (
	"archive/zip"
	"bytes"
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

func logRefreshFailure(prefix string, err error) {
	log.Printf("[bdu] %s: %v (keeping previous map)", prefix, err)
}

func (e *Enricher) refresh(ctx context.Context) error {
	raw, source, err := e.fetchSource(ctx)
	if err != nil {
		e.setLastErr(err)
		return err
	}
	xmlBytes, err := unwrapZipIfNeeded(raw)
	if err != nil {
		e.setLastErr(err)
		return fmt.Errorf("unzip: %w", err)
	}
	newMap, newDetails, err := parseBDU(xmlBytes, e.noDetail)
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
		log.Printf("[bdu] refreshed: %d CVE->BDU mappings loaded from %s (detail disabled)", len(newMap), source)
	} else {
		log.Printf("[bdu] refreshed: %d CVE->BDU mappings, %d full details loaded from %s", len(newMap), len(newDetails), source)
	}
	return nil
}

func (e *Enricher) fetchSource(ctx context.Context) ([]byte, string, error) {
	if e.localPath != "" {
		raw, err := e.readLocal()
		return raw, e.localPath, err
	}
	raw, err := e.download(ctx)
	return raw, e.archiveURL, err
}

func (e *Enricher) setLastErr(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastErr = err
}

func (e *Enricher) readLocal() ([]byte, error) {
	f, err := os.Open(e.localPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", e.localPath, err)
	}
	defer f.Close()
	const maxSize = 1 << 30
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", e.localPath, err)
	}
	if len(data) > maxSize {
		return nil, fmt.Errorf("local archive %s exceeds %d bytes", e.localPath, maxSize)
	}
	return data, nil
}

func (e *Enricher) download(ctx context.Context) ([]byte, error) {
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
	const maxSize = 200 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSize))
	if err != nil {
		return nil, err
	}
	if len(data) == maxSize {
		return nil, fmt.Errorf("archive exceeds %d bytes, aborting", maxSize)
	}
	return data, nil
}

func unwrapZipIfNeeded(data []byte) ([]byte, error) {
	if len(data) >= 4 && data[0] == 'P' && data[1] == 'K' {
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			if strings.HasSuffix(strings.ToLower(f.Name), ".xml") {
				rc, err := f.Open()
				if err != nil {
					return nil, err
				}
				defer rc.Close()

				const maxXMLSize = 1 << 30
				out, err := io.ReadAll(io.LimitReader(rc, maxXMLSize+1))
				if err != nil {
					return nil, err
				}
				if int64(len(out)) > maxXMLSize {
					return nil, fmt.Errorf("decompressed xml exceeds %d bytes (possible zip bomb)", maxXMLSize)
				}
				return out, nil
			}
		}
		return nil, fmt.Errorf("no .xml inside zip")
	}
	return data, nil
}
