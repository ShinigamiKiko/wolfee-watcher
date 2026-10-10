package fswatch

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func writeFile(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func whiteout(t *testing.T, root, rel string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mknod(p, syscall.S_IFCHR|0o000, 0); err != nil {
		t.Skipf("mknod needs CAP_MKNOD: %v", err)
	}
}

func opsByPath(entries []FileEntry) map[string]string {
	out := map[string]string{}
	for _, e := range entries {
		out[e.Path] = e.Op
	}
	return out
}

func TestBaselineClassifiesAgainstImageLayers(t *testing.T) {
	lower := t.TempDir()
	upper := t.TempDir()
	writeFile(t, lower, "etc/passwd", "root:x:0:0")
	writeFile(t, lower, "etc/issue.net", "Debian")
	writeFile(t, upper, "etc/passwd", "root:x:0:0\nevil:x:0:0")
	writeFile(t, upper, "tmp/.x/agent", "ELF")
	whiteout(t, upper, "etc/issue.net")

	w := &Watcher{}
	snap, err := w.snapDir(upper, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := baselineEntries(snap, lowerLookup([]string{lower}), "2026-10-10T08:00:00Z", "abc")
	got := opsByPath(base)
	want := map[string]string{"/etc/passwd": OpModified, "/tmp/.x/agent": OpAdded, "/etc/issue.net": OpDeleted}
	for path, op := range want {
		if got[path] != op {
			t.Fatalf("%s: op=%q want %q (all=%v)", path, got[path], op, got)
		}
	}
	for _, e := range base {
		if !e.Baseline || e.ContainerID != "abc" {
			t.Fatalf("baseline entry not marked: %+v", e)
		}
	}
}

func TestDiffAfterWatchStart(t *testing.T) {
	lower := t.TempDir()
	upper := t.TempDir()
	writeFile(t, lower, "etc/hosts", "127.0.0.1 localhost")
	writeFile(t, lower, "etc/motd", "hello")
	writeFile(t, upper, "app/state", "v1")

	w := &Watcher{}
	prev, err := w.snapDir(upper, nil)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, upper, "app/state", "v2-changed")
	writeFile(t, upper, "etc/hosts", "1.2.3.4 evil")
	writeFile(t, upper, "usr/bin/miner", "ELF")
	whiteout(t, upper, "etc/motd")

	cur, err := w.snapDir(upper, prev)
	if err != nil {
		t.Fatal(err)
	}
	got := opsByPath(buildDiffs(cur, prev, lowerLookup([]string{lower}), "now"))
	want := map[string]string{
		"/app/state":     OpModified,
		"/etc/hosts":     OpModified,
		"/usr/bin/miner": OpAdded,
		"/etc/motd":      OpDeleted,
	}
	if len(got) != len(want) {
		t.Fatalf("diff = %v, want %v", got, want)
	}
	for path, op := range want {
		if got[path] != op {
			t.Fatalf("%s: op=%q want %q (all=%v)", path, got[path], op, got)
		}
	}

	if err := os.Remove(filepath.Join(upper, "usr/bin/miner")); err != nil {
		t.Fatal(err)
	}
	next, err := w.snapDir(upper, cur)
	if err != nil {
		t.Fatal(err)
	}
	got = opsByPath(buildDiffs(next, cur, lowerLookup([]string{lower}), "later"))
	if len(got) != 1 || got["/usr/bin/miner"] != OpDeleted {
		t.Fatalf("removing an added file must be one delete, got %v", got)
	}
}

func TestUnchangedFilesAreNotRehashed(t *testing.T) {
	upper := t.TempDir()
	writeFile(t, upper, "data/blob", strings.Repeat("x", 4096))
	w := &Watcher{}
	first, err := w.snapDir(upper, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := first["/data/blob"]
	e.SHA256 = "cached"
	first["/data/blob"] = e
	second, err := w.snapDir(upper, first)
	if err != nil {
		t.Fatal(err)
	}
	if second["/data/blob"].SHA256 != "cached" {
		t.Fatal("hash of an unchanged file must be reused")
	}
	if len(buildDiffs(second, first, func(string) bool { return false }, "now")) != 0 {
		t.Fatal("unchanged layer must produce no diff")
	}
}

func TestLayerParsesLowerDirs(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "io.containerd.snapshotter.v1.overlayfs", "snapshots")
	for _, n := range []string{"10", "11", "12"} {
		if err := os.MkdirAll(filepath.Join(base, n, "fs"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	id := strings.Repeat("d", 64)
	host := "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/"
	mounts := "overlay /run/containerd/io.containerd.runtime.v2.task/k8s.io/" + id + "/rootfs overlay rw,lowerdir=" +
		host + "11/fs:" + host + "10/fs,upperdir=" + host + "12/fs,workdir=" + host + "12/work 0 0"
	l, err := findLayerFromMountData(id, root, base, mounts)
	if err != nil {
		t.Fatal(err)
	}
	if l.upperDir != filepath.Join(base, "12", "fs") || len(l.lowerDirs) != 2 || l.lowerDirs[0] != filepath.Join(base, "11", "fs") {
		t.Fatalf("layer = %+v", l)
	}
}
