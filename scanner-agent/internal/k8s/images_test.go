package k8s

import (
	"testing"

	internal "github.com/wolfee-watcher/scanner-agent/internal"
	corev1 "k8s.io/api/core/v1"
)

func TestWorkloadSlicePreservesPodIdentity(t *testing.T) {
	workloads := map[string]internal.ImageWorkload{
		"prod\x00uid-a":  newWorkload("registry/app:v1", "prod", "app", "uid-a", "10.0.0.1", "node-a"),
		"stage\x00uid-b": newWorkload("registry/app:v1", "stage", "app", "uid-b", "10.0.0.2", "node-b"),
	}

	got := workloadSlice(workloads)
	if len(got) != 2 {
		t.Fatalf("workloadSlice returned %d records, want 2", len(got))
	}
	seen := make(map[string]bool, len(got))
	for _, workload := range got {
		seen[workload.Namespace+"/"+workload.PodUID] = true
	}
	if !seen["prod/uid-a"] || !seen["stage/uid-b"] {
		t.Fatalf("pod identity was lost: %#v", seen)
	}
}

func TestResolveImageMatchesContainerByName(t *testing.T) {
	statuses := []corev1.ContainerStatus{
		{Name: "envoy", Image: "docker.io/envoyproxy/envoy:v1.30", ImageID: "docker.io/envoyproxy/envoy@sha256:1111"},
		{Name: "app", Image: "registry.local/app:1.2", ImageID: "registry.local/app@sha256:2222"},
	}

	ref, digest := resolveImage("app", "app:1.2", statuses)
	if ref != "registry.local/app:1.2" || digest != "sha256:2222" {
		t.Fatalf("app: got ref=%q digest=%q", ref, digest)
	}

	ref, digest = resolveImage("envoy", "envoyproxy/envoy:v1.30", statuses)
	if ref != "docker.io/envoyproxy/envoy:v1.30" || digest != "sha256:1111" {
		t.Fatalf("envoy: got ref=%q digest=%q", ref, digest)
	}
}

func TestResolveImageFallsBackToSpecWithoutStatus(t *testing.T) {
	ref, digest := resolveImage("init", "busybox:1.36", nil)
	if ref != "busybox:1.36" || digest != "" {
		t.Fatalf("got ref=%q digest=%q", ref, digest)
	}

	statuses := []corev1.ContainerStatus{{Name: "other", Image: "nginx:1.25", ImageID: "nginx@sha256:3333"}}
	ref, digest = resolveImage("init", "busybox:1.36", statuses)
	if ref != "busybox:1.36" || digest != "" {
		t.Fatalf("unmatched status: got ref=%q digest=%q", ref, digest)
	}
}
