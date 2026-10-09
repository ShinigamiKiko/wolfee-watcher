package podindex

import (
	"encoding/json"
	"strings"
	"sync"
	"time"
)

const clockSlack = 5 * time.Second

type Client struct {
	Namespace      string    `json:"namespace"`
	Pod            string    `json:"pod"`
	UID            string    `json:"uid,omitempty"`
	Workload       string    `json:"workload,omitempty"`
	ServiceAccount string    `json:"serviceAccount,omitempty"`
	Node           string    `json:"node,omitempty"`
	Image          string    `json:"image,omitempty"`
	CreatedAt      time.Time `json:"createdAt,omitempty"`
	FinishedAt     time.Time `json:"finishedAt,omitempty"`
	SeenAt         time.Time `json:"seenAt"`

	running bool
}

type Index struct {
	keep time.Duration

	mu        sync.RWMutex
	byCluster map[string]map[string]Client
}

func New(keep time.Duration) *Index {
	return &Index{keep: keep, byCluster: map[string]map[string]Client{}}
}

type snapshotPod struct {
	Metadata struct {
		Name              string    `json:"name"`
		Namespace         string    `json:"namespace"`
		UID               string    `json:"uid"`
		CreationTimestamp time.Time `json:"creationTimestamp"`
		OwnerReferences   []struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		ServiceAccountName string `json:"serviceAccountName"`
		NodeName           string `json:"nodeName"`
		HostNetwork        bool   `json:"hostNetwork"`
		Containers         []struct {
			Image string `json:"image"`
		} `json:"containers"`
	} `json:"spec"`
	Status struct {
		Phase             string `json:"phase"`
		PodIP             string `json:"podIP"`
		ContainerStatuses []struct {
			State struct {
				Terminated *struct {
					FinishedAt time.Time `json:"finishedAt"`
				} `json:"terminated"`
			} `json:"state"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

func (x *Index) Update(cluster string, snapshot json.RawMessage, now time.Time) error {
	var body struct {
		Pods []snapshotPod `json:"pods"`
	}
	if err := json.Unmarshal(snapshot, &body); err != nil {
		return err
	}
	best := map[string]Client{}
	for _, p := range body.Pods {
		if p.Status.PodIP == "" || p.Spec.HostNetwork {
			continue
		}
		c := clientOf(p, now)
		if cur, ok := best[p.Status.PodIP]; ok && !preferred(c, cur) {
			continue
		}
		best[p.Status.PodIP] = c
	}

	x.mu.Lock()
	defer x.mu.Unlock()
	pods := x.byCluster[cluster]
	if pods == nil {
		pods = map[string]Client{}
		x.byCluster[cluster] = pods
	}
	for ip, c := range best {
		pods[ip] = c
	}
	for ip, c := range pods {
		if _, current := best[ip]; !current && c.FinishedAt.IsZero() {
			c.FinishedAt = now
			c.running = false
			pods[ip] = c
		}
		if now.Sub(c.SeenAt) > x.keep {
			delete(pods, ip)
		}
	}
	return nil
}

func (x *Index) Lookup(cluster, ip string, at time.Time) (Client, bool) {
	x.mu.RLock()
	c, ok := x.byCluster[cluster][ip]
	x.mu.RUnlock()
	if !ok {
		return Client{}, false
	}
	if !c.CreatedAt.IsZero() && c.CreatedAt.After(at.Add(clockSlack)) {
		return Client{}, false
	}
	if !c.FinishedAt.IsZero() && c.FinishedAt.Before(at.Add(-clockSlack)) {
		return Client{}, false
	}
	return c, true
}

func clientOf(p snapshotPod, now time.Time) Client {
	c := Client{
		Namespace:      p.Metadata.Namespace,
		Pod:            p.Metadata.Name,
		UID:            p.Metadata.UID,
		Workload:       workload(p),
		ServiceAccount: p.Spec.ServiceAccountName,
		Node:           p.Spec.NodeName,
		CreatedAt:      p.Metadata.CreationTimestamp,
		SeenAt:         now,
		running:        p.Status.Phase != "Succeeded" && p.Status.Phase != "Failed",
	}
	if len(p.Spec.Containers) > 0 {
		c.Image = p.Spec.Containers[0].Image
	}
	if !c.running {
		for _, cs := range p.Status.ContainerStatuses {
			if t := cs.State.Terminated; t != nil && t.FinishedAt.After(c.FinishedAt) {
				c.FinishedAt = t.FinishedAt
			}
		}
	}
	return c
}

func preferred(a, b Client) bool {
	if a.running != b.running {
		return a.running
	}
	return a.CreatedAt.After(b.CreatedAt)
}

func workload(p snapshotPod) string {
	for _, ref := range p.Metadata.OwnerReferences {
		if ref.Kind == "ReplicaSet" {
			if i := strings.LastIndex(ref.Name, "-"); i > 0 {
				return ref.Name[:i]
			}
			return ref.Name
		}
		if ref.Name != "" {
			return ref.Name
		}
	}
	return ""
}
