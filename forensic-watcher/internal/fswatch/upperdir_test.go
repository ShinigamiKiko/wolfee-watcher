package fswatch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindUpperDirFromMountData(t *testing.T) {
	root := t.TempDir()
	snapshot := filepath.Join(root, "io.containerd.snapshotter.v1.overlayfs", "snapshots", "42", "fs")
	if err := os.MkdirAll(filepath.Join(snapshot, "tmp"), 0o755); err != nil {
		t.Fatal(err)
	}

	containerID := strings.Repeat("a", 64)
	mounts := strings.Join([]string{
		"overlay / overlay rw,lowerdir=/wrong,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/7/fs 0 0",
		"overlay /run/containerd/io.containerd.runtime.v2.task/k8s.io/" + containerID + "/rootfs overlay rw,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/42/fs 0 0",
	}, "\n")

	got, err := findUpperDirFromMountData(
		containerID,
		root,
		filepath.Join(root, "io.containerd.snapshotter.v1.overlayfs", "snapshots"),
		mounts,
	)
	if err != nil {
		t.Fatalf("find upperdir: %v", err)
	}
	if got != snapshot {
		t.Fatalf("upperdir = %q, want %q", got, snapshot)
	}
}

func TestFindUpperDirRejectsUnrelatedOverlay(t *testing.T) {
	root := t.TempDir()
	snapshots := filepath.Join(root, "snapshots")
	if err := os.MkdirAll(snapshots, 0o755); err != nil {
		t.Fatal(err)
	}
	containerID := strings.Repeat("b", 64)
	mounts := "overlay /wrong/" + strings.Repeat("c", 64) + "/rootfs overlay rw,upperdir=/var/lib/containerd/snapshots/1/fs 0 0"

	if _, err := findUpperDirFromMountData(containerID, root, snapshots, mounts); err == nil {
		t.Fatal("expected unrelated overlay to be rejected")
	}
}
