package fswatch

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/wolfee-watcher/pkg/env"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	errPodGone    = errors.New("pod no longer exists")
	errNotRunning = errors.New("pod has no running container")
	errOtherNode  = errors.New("pod runs on another node")
)

type layer struct {
	containerID string
	upperDir    string
	lowerDirs   []string
}

func (w *Watcher) findUpperDir(ctx context.Context, ns, pod string) (string, error) {
	l, err := w.resolveLayer(ctx, ns, pod, false)
	if err != nil {
		return "", err
	}
	return l.upperDir, nil
}

func (w *Watcher) resolveLayer(ctx context.Context, ns, pod string, runningOnly bool) (layer, error) {
	p, err := w.client.CoreV1().Pods(ns).Get(ctx, pod, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return layer{}, fmt.Errorf("%s/%s: %w", ns, pod, errPodGone)
		}
		return layer{}, fmt.Errorf("get pod: %w", err)
	}
	if p.Spec.NodeName != w.nodeName {
		return layer{}, fmt.Errorf("%s/%s is on node %s, not %s: %w", ns, pod, p.Spec.NodeName, w.nodeName, errOtherNode)
	}
	containerID := findRunningContainerID(p)
	if containerID == "" && !runningOnly {
		containerID = findAnyContainerID(p)
	}
	if containerID == "" {
		return layer{}, fmt.Errorf("%s/%s: %w", ns, pod, errNotRunning)
	}
	id := strings.TrimPrefix(containerID, "containerd://")
	if !isValidContainerID(id) {
		return layer{}, fmt.Errorf("invalid containerID: %s", containerID)
	}
	snapshotsBase := filepath.Join(w.containerdRoot, "io.containerd.snapshotter.v1.overlayfs", "snapshots")
	if _, err := os.Stat(snapshotsBase); os.IsNotExist(err) {
		return layer{}, fmt.Errorf("snapshots dir not found: %s", snapshotsBase)
	}
	l, err := findLayerFromHostMounts(id, w.containerdRoot, snapshotsBase)
	if err != nil {
		if runningOnly {
			return layer{}, fmt.Errorf("layer lookup for %s/%s (id=%s): %v: %w", ns, pod, id[:12], err, errNotRunning)
		}
		return layer{}, fmt.Errorf("upperdir lookup failed for %s/%s (id=%s): %w", ns, pod, id[:12], err)
	}
	l.containerID = id
	return l, nil
}

func isValidContainerID(id string) bool {
	if len(id) < 12 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func findLayerFromHostMounts(containerID, containerdRoot, snapshotsBase string) (layer, error) {
	procMounts := env.Str("PROC_MOUNTS", "/proc/self/mounts")
	data, err := os.ReadFile(procMounts)
	if err != nil {
		return layer{}, fmt.Errorf("read %s: %w", procMounts, err)
	}
	return findLayerFromMountData(containerID, containerdRoot, snapshotsBase, string(data))
}

func findUpperDirFromMountData(containerID, containerdRoot, snapshotsBase, data string) (string, error) {
	l, err := findLayerFromMountData(containerID, containerdRoot, snapshotsBase, data)
	return l.upperDir, err
}

func findLayerFromMountData(containerID, containerdRoot, snapshotsBase, data string) (layer, error) {
	absSnapshots, err := filepath.Abs(snapshotsBase)
	if err != nil {
		return layer{}, fmt.Errorf("abs snapshotsBase: %w", err)
	}
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[2] != "overlay" {
			continue
		}
		if !mountpointMatchesContainer(unescapeMount(fields[1]), containerID) {
			continue
		}
		var l layer
		for _, opt := range strings.Split(fields[3], ",") {
			switch {
			case strings.HasPrefix(opt, "upperdir="):
				upper, err := localSnapshotPath(strings.TrimPrefix(opt, "upperdir="), containerdRoot, absSnapshots)
				if err != nil {
					return layer{}, err
				}
				if _, err := os.Stat(upper); err != nil {
					return layer{}, fmt.Errorf("upperdir does not exist: %s: %w", upper, err)
				}
				l.upperDir = upper
			case strings.HasPrefix(opt, "lowerdir="):
				for _, lower := range strings.Split(strings.TrimPrefix(opt, "lowerdir="), ":") {
					if lower == "" {
						continue
					}
					if local, err := localSnapshotPath(lower, containerdRoot, absSnapshots); err == nil {
						l.lowerDirs = append(l.lowerDirs, local)
					}
				}
			}
		}
		if l.upperDir == "" {
			return layer{}, fmt.Errorf("overlay mount for %s has no upperdir option", containerID[:12])
		}
		log.Printf("[fswatch] upperdir=%s lowers=%d for containerID=%s", l.upperDir, len(l.lowerDirs), containerID[:12])
		return l, nil
	}
	return layer{}, fmt.Errorf("no overlay mount found for containerID=%s", containerID[:12])
}

func localSnapshotPath(hostPath, containerdRoot, absSnapshots string) (string, error) {
	local := strings.Replace(unescapeMount(hostPath), "/var/lib/containerd", containerdRoot, 1)
	abs, err := filepath.Abs(local)
	if err != nil {
		return "", fmt.Errorf("abs %q: %w", local, err)
	}
	if !isUnder(abs, absSnapshots) {
		return "", fmt.Errorf("%q is outside snapshots root %q", abs, absSnapshots)
	}
	return abs, nil
}

func mountpointMatchesContainer(mountPoint, containerID string) bool {
	for _, seg := range strings.Split(mountPoint, "/") {
		if seg == containerID {
			return true
		}
	}
	return false
}

func isUnder(path, root string) bool {
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	if path == root {
		return true
	}
	return strings.HasPrefix(path, root+string(os.PathSeparator))
}

func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			a, b1, c := s[i+1], s[i+2], s[i+3]
			if a >= '0' && a <= '3' && b1 >= '0' && b1 <= '7' && c >= '0' && c <= '7' {
				b.WriteByte(((a - '0') << 6) | ((b1 - '0') << 3) | (c - '0'))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func findRunningContainerID(p *corev1.Pod) string {
	for _, cs := range p.Status.ContainerStatuses {
		if cs.State.Running != nil && cs.ContainerID != "" {
			return cs.ContainerID
		}
	}
	return ""
}

func findAnyContainerID(p *corev1.Pod) string {
	for _, cs := range p.Status.ContainerStatuses {
		if cs.ContainerID != "" {
			return cs.ContainerID
		}
	}
	return ""
}
