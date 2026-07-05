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
	"time"
)

func (w *Watcher) snapDir(dir string) ([]FileEntry, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, fmt.Errorf("upperdir not found: %s", dir)
	}

	var entries []FileEntry
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if len(entries) >= maxFilesPerDiff {
			return filepath.SkipAll
		}
		rel := strings.TrimPrefix(path, dir)
		info, err := d.Info()
		if err != nil {
			return nil
		}
		e := FileEntry{
			Path:  rel,
			Size:  info.Size(),
			Mtime: info.ModTime().UTC().Format(time.RFC3339),
		}
		if info.Size() > 0 && info.Size() <= 10*1024*1024 {
			e.SHA256 = hashFile(path)
		}
		if strings.HasPrefix(filepath.Base(path), ".wh.") {
			e.Op = "whiteout"
		}
		entries = append(entries, e)
		return nil
	})
	return validateTTL(entries), err
}

func hashFile(path string) string {
	f, err := os.Open(path)
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
