package k8s

import (
	"context"
	"log"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (pc *PodCache) refresh() {
	if pc.cs == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pods, err := pc.cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{FieldSelector: "status.phase=Running"})
	if err != nil {
		log.Printf("[podcache] refresh error: %v", err)
		return
	}

	next := make(map[string]PodInfo, len(pods.Items)*3)
	for _, pod := range pods.Items {
		info := PodInfo{PodName: pod.Name, Namespace: pod.Namespace, NodeName: pod.Spec.NodeName}
		for _, cs := range pod.Status.ContainerStatuses {
			indexContainerID(next, cs.ContainerID, info)
		}
		for _, cs := range pod.Status.InitContainerStatuses {
			indexContainerID(next, cs.ContainerID, info)
		}
	}

	pc.mu.Lock()
	pc.cache = next
	pc.mu.Unlock()
	log.Printf("[podcache] refreshed — %d containers indexed", len(next))
}

func indexContainerID(m map[string]PodInfo, raw string, info PodInfo) {
	id := raw
	if idx := strings.Index(id, "://"); idx >= 0 {
		id = id[idx+3:]
	}
	if id != "" {
		m[shortID(id)] = info
	}
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
