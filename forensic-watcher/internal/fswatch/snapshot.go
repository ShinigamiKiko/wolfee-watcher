package fswatch

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	maxHashBytes  = 10 << 20
	aufsWhiteout  = ".wh."
	aufsOpaque    = ".wh..wh..opq"
	overlayOpaque = "trusted.overlay.opaque"
)

const (
	kindFile = iota
	kindWhiteout
	kindOpaqueDir
)

func (w *Watcher) snapDir(dir string, prev map[string]FileEntry) (map[string]FileEntry, error) {
	if _, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("upperdir not found: %s: %w", dir, err)
	}
	out := make(map[string]FileEntry)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == dir {
			return nil
		}
		if len(out) >= maxFilesPerDiff {
			return filepath.SkipAll
		}
		rel := "/" + strings.TrimPrefix(strings.TrimPrefix(path, dir), "/")
		if d.IsDir() {
			if isOpaqueDir(path) {
				out[rel+"/"] = FileEntry{Path: rel + "/", kind: kindOpaqueDir}
			}
			return nil
		}
		base := filepath.Base(rel)
		if base == aufsOpaque {
			parent := filepath.Dir(rel)
			out[parent+"/"] = FileEntry{Path: parent + "/", kind: kindOpaqueDir}
			return nil
		}
		if strings.HasPrefix(base, aufsWhiteout) {
			target := filepath.Join(filepath.Dir(rel), strings.TrimPrefix(base, aufsWhiteout))
			out[target] = FileEntry{Path: target, kind: kindWhiteout}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if isOverlayWhiteout(info) {
			out[rel] = FileEntry{Path: rel, kind: kindWhiteout}
			return nil
		}
		e := FileEntry{
			Path:  rel,
			Size:  info.Size(),
			Mtime: info.ModTime().UTC().Format(time.RFC3339Nano),
		}
		if info.Mode().IsRegular() && info.Size() > 0 && info.Size() <= maxHashBytes {
			if p, ok := prev[rel]; ok && p.kind == kindFile && p.Size == e.Size && p.Mtime == e.Mtime && p.SHA256 != "" {
				e.SHA256 = p.SHA256
			} else {
				e.SHA256 = hashFile(path)
			}
		}
		out[rel] = e
		return nil
	})
	return out, err
}

func isOverlayWhiteout(info fs.FileInfo) bool {
	if info.Mode()&fs.ModeCharDevice == 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Rdev == 0
}

func isOpaqueDir(path string) bool {
	buf := make([]byte, 4)
	n, err := syscall.Getxattr(path, overlayOpaque, buf)
	return err == nil && n > 0 && buf[0] == 'y'
}

func hashFile(path string) string {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
