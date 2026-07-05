package k8s

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"

	internal "github.com/wolfee-watcher/scanner-agent/internal"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const defaultPodListChunkSize = 500

func podListChunkSize() int64 {
	v := os.Getenv("SCANNER_POD_LIST_CHUNK_SIZE")
	if v == "" {
		return defaultPodListChunkSize
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		slog.Warn("invalid_int_env",
			"component", "scanner-agent/k8s",
			"key", "SCANNER_POD_LIST_CHUNK_SIZE",
			"value", v,
			"default", defaultPodListChunkSize)
		return defaultPodListChunkSize
	}
	return int64(n)
}

func (c *Client) ListImages(ctx context.Context) ([]internal.ClusterImage, error) {
	pods, err := c.listPodsPaged(ctx, podListChunkSize())
	if err != nil {
		return nil, err
	}

	type meta struct {
		pods       map[string]struct{}
		namespaces map[string]struct{}
		nodes      map[string]struct{}
		pullPolicy string
		digest     string
	}
	seen := make(map[string]*meta)

	add := func(ref, digest, ns, pod, node, policy string) {
		if ref == "" {
			return
		}
		if m, ok := seen[ref]; ok {
			m.pods[pod] = struct{}{}
			m.namespaces[ns] = struct{}{}
			m.nodes[node] = struct{}{}
			if m.digest == "" && digest != "" {
				m.digest = digest
			}
		} else {
			seen[ref] = &meta{
				pods:       map[string]struct{}{pod: {}},
				namespaces: map[string]struct{}{ns: {}},
				nodes:      map[string]struct{}{node: {}},
				pullPolicy: policy,
				digest:     digest,
			}
		}
	}

	for _, pod := range pods {
		if pod.Status.Phase != corev1.PodRunning && pod.Status.Phase != corev1.PodPending {
			continue
		}
		ns, name, node := pod.Namespace, pod.Name, pod.Spec.NodeName
		for _, cs := range pod.Spec.InitContainers {
			ref, digest := resolveImage(cs.Image, pod.Status.InitContainerStatuses)
			add(ref, digest, ns, name, node, string(cs.ImagePullPolicy))
		}
		for _, cs := range pod.Spec.Containers {
			ref, digest := resolveImage(cs.Image, pod.Status.ContainerStatuses)
			add(ref, digest, ns, name, node, string(cs.ImagePullPolicy))
		}
	}

	result := make([]internal.ClusterImage, 0, len(seen))
	for ref, m := range seen {
		name, tag, digestFromRef := parseRef(ref)

		digest := m.digest
		if digest == "" {
			digest = digestFromRef
		}
		result = append(result, internal.ClusterImage{
			Ref:        ref,
			Name:       name,
			Tag:        tag,
			Digest:     digest,
			Pods:       setToSlice(m.pods),
			Namespaces: setToSlice(m.namespaces),
			Nodes:      setToSlice(m.nodes),
			PullPolicy: m.pullPolicy,
		})
	}
	return result, nil
}

func (c *Client) listPodsPaged(ctx context.Context, chunkSize int64) ([]corev1.Pod, error) {
	opts := metav1.ListOptions{Limit: chunkSize}
	var out []corev1.Pod
	for {
		pods, err := c.cs.CoreV1().Pods("").List(ctx, opts)
		if err != nil {
			return nil, err
		}
		out = append(out, pods.Items...)
		if pods.Continue == "" {
			return out, nil
		}
		opts.Continue = pods.Continue
	}
}

func resolveImage(specImage string, statuses []corev1.ContainerStatus) (ref, digest string) {
	for _, s := range statuses {
		if s.Image != "" {
			ref = s.Image
		}

		if s.ImageID != "" {
			if idx := strings.Index(s.ImageID, "sha256:"); idx >= 0 {
				digest = s.ImageID[idx:]
			}
		}
		if ref != "" {
			return
		}
	}
	return specImage, digest
}

func parseRef(ref string) (name, tag, digest string) {
	if idx := strings.Index(ref, "@"); idx >= 0 {
		digest = ref[idx+1:]
		ref = ref[:idx]
	}
	lastSlash := strings.LastIndex(ref, "/")
	sub := ref[lastSlash+1:]
	if idx := strings.LastIndex(sub, ":"); idx >= 0 {
		tag = sub[idx+1:]
		name = ref[:lastSlash+1] + sub[:idx]
	} else {
		tag = "latest"
		name = ref
	}
	return
}

func setToSlice(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
