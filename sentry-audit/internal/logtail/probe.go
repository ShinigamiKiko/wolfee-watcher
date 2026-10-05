package logtail

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"
)

const probeTail = 512 << 10

func since(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < 0:
		return "just now"
	case d < 90*time.Second:
		return fmt.Sprintf("%d s ago", int(d.Seconds()))
	case d < 90*time.Minute:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 36*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	}
	return fmt.Sprintf("%d d ago", int(d.Hours()/24))
}

func lastLine(buf []byte) []byte {
	buf = bytes.TrimRight(buf, "\n")
	if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
		return buf[i+1:]
	}
	return buf
}

func Probe(path string) (bool, string) {
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, fmt.Sprintf("%s does not exist on this node", path)
	case errors.Is(err, fs.ErrPermission):
		return false, fmt.Sprintf("no permission to read %s", path)
	case err != nil:
		return false, err.Error()
	case info.IsDir():
		return false, fmt.Sprintf("%s is a directory, not a log file", path)
	case info.Size() == 0:
		return false, fmt.Sprintf("%s is empty: the API server has not written to it", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return false, err.Error()
	}
	defer f.Close()
	start := info.Size() - probeTail
	if start < 0 {
		start = 0
	}
	buf := make([]byte, info.Size()-start)
	if _, err := f.ReadAt(buf, start); err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Sprintf("cannot read %s: %v", path, err)
	}
	var record struct {
		Kind           string    `json:"kind"`
		APIVersion     string    `json:"apiVersion"`
		StageTimestamp time.Time `json:"stageTimestamp"`
	}
	if json.Unmarshal(lastLine(buf), &record) != nil || record.Kind != "Event" || record.APIVersion == "" {
		return false, fmt.Sprintf("%s is readable but its last line is not a Kubernetes audit record", path)
	}
	written := info.ModTime()
	if !record.StageTimestamp.IsZero() {
		written = record.StageTimestamp
	}
	return true, fmt.Sprintf("%s is readable, %d MB, last record %s", path, info.Size()>>20, since(written))
}
