package fswatch

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/wolfee-watcher/pkg/env"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (w *Watcher) findUpperDir(ctx context.Context, ns, pod string) (string, error) {
	p, err := w.client.CoreV1().Pods(ns).Get(ctx, pod, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get pod: %w", err)
	}
	if p.Spec.NodeName != w.nodeName {
		return "", fmt.Errorf("pod %s/%s is on node %s, not %s", ns, pod, p.Spec.NodeName, w.nodeName)
	}
	containerID := findRunningContainerID(p)
	if containerID == "" {
		return "", fmt.Errorf("no running containers found in pod %s/%s", ns, pod)
	}
	id := strings.TrimPrefix(containerID, "containerd://")
	if !isValidContainerID(id) {
		return "", fmt.Errorf("invalid containerID: %s", containerID)
	}
	snapshotsBase := filepath.Join(w.containerdRoot, "io.containerd.snapshotter.v1.overlayfs", "snapshots")
	if _, err := os.Stat(snapshotsBase); os.IsNotExist(err) {
		return "", fmt.Errorf("snapshots dir not found: %s", snapshotsBase)
	}
	upperDir, err := findUpperDirFromHostMounts(id, w.containerdRoot, snapshotsBase)
	if err != nil {
		return "", fmt.Errorf("upperdir lookup failed for %s/%s (id=%s): %w", ns, pod, id[:12], err)
	}
	log.Printf("[fswatch] findUpperDir containerID=%s upperDir=%q", id[:12], upperDir)
	return upperDir, nil
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

func findUpperDirFromHostMounts(containerID, containerdRoot, snapshotsBase string) (string, error) {
	procMounts := env.Str("PROC_MOUNTS", "/proc/self/mounts")
	data, err := os.ReadFile(procMounts)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", procMounts, err)
	}
	absSnapshots, err := filepath.Abs(snapshotsBase)
	if err != nil {
		return "", fmt.Errorf("abs snapshotsBase: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[2] != "overlay" {
			continue
		}
		mountPoint := unescapeMount(fields[1])
		if !mountpointMatchesContainer(mountPoint, containerID) {
			continue
		}
		for _, opt := range strings.Split(fields[3], ",") {
			if !strings.HasPrefix(opt, "upperdir=") {
				continue
			}
			hostUpper := unescapeMount(strings.TrimPrefix(opt, "upperdir="))
			localUpper := strings.Replace(hostUpper, "/var/lib/containerd", containerdRoot, 1)
			absUpper, err := filepath.Abs(localUpper)
			if err != nil {
				return "", fmt.Errorf("abs upperdir %q: %w", localUpper, err)
			}
			if !isUnder(absUpper, absSnapshots) {
				return "", fmt.Errorf("upperdir %q is outside snapshots root %q", absUpper, absSnapshots)
			}
			if _, err := os.Stat(absUpper); err != nil {
				return "", fmt.Errorf("upperdir does not exist: %s: %w", absUpper, err)
			}
			log.Printf("[fswatch] upperdir=%s for containerID=%s", absUpper, containerID[:12])
			return absUpper, nil
		}
		return "", fmt.Errorf("overlay mount for %s has no upperdir option", containerID[:12])
	}
	return "", fmt.Errorf("no overlay mount found for containerID=%s in %s", containerID[:12], procMounts)
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
	for _, cs := range p.Status.ContainerStatuses {
		if cs.ContainerID != "" {
			return cs.ContainerID
		}
	}
	return ""
}
