package k8s

import (
	"testing"

	internal "github.com/wolfee-watcher/scanner-agent/internal"
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
