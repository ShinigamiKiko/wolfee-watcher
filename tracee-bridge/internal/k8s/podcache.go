package k8s

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	metricsclient "k8s.io/metrics/pkg/client/clientset/versioned"
)

type PodInfo struct {
	PodName   string
	Namespace string
	NodeName  string
	PodUID    string
	PodIP     string
}

type PodCache struct {
	mu         sync.RWMutex
	cache      map[string]PodInfo
	learned    map[string]learnedInfo
	pidCache   map[int]learnedInfo
	fallbackMu sync.Mutex
	fallbackAt map[string]time.Time
	cs         *kubernetes.Clientset
	mc         *metricsclient.Clientset
	restCfg    *rest.Config
}

type learnedInfo struct {
	info PodInfo
	at   time.Time
}

const (
	learnedTTL = 10 * time.Minute
	pidTTL     = 5 * time.Minute
	pidCacheMax = 20000
)

var systemNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
	"calico-system":   true,
	"cilium":          true,
	"cert-manager":    true,
	"monitoring":      true,
	"ingress-nginx":   true,
}

func New(ctx context.Context) *PodCache {
	pc := &PodCache{
		cache:      make(map[string]PodInfo),
		learned:    make(map[string]learnedInfo),
		pidCache:   make(map[int]learnedInfo),
		fallbackAt: make(map[string]time.Time),
	}

	cfg, err := rest.InClusterConfig()
	if err != nil {
		home, _ := os.UserHomeDir()
		kc := filepath.Join(home, ".kube", "config")
		if ev := os.Getenv("KUBECONFIG"); ev != "" {
			kc = ev
		}
		cfg, err = clientcmd.BuildConfigFromFlags("", kc)
		if err != nil {
			log.Printf("[podcache] K8s API unavailable — pod enrichment disabled: %v", err)
			return pc
		}
	}
	pc.restCfg = cfg

	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Printf("[podcache] K8s client error: %v", err)
		return pc
	}
	pc.cs = cs

	mc, err := metricsclient.NewForConfig(cfg)
	if err == nil {
		pc.mc = mc
	}

	pc.refresh()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				pc.refresh()
			}
		}
	}()

	log.Printf("[podcache] started — watching all pods for container enrichment")
	return pc
}

type ComponentStatus struct {
	Alive int32  `json:"alive"`
	Total int32  `json:"total"`
	Kind  string `json:"kind"`
	Found bool   `json:"found"`
}

func (pc *PodCache) ComponentStatus(ns, name, kind string) ComponentStatus {
	out := ComponentStatus{Kind: kind}
	if pc.cs == nil || ns == "" || name == "" {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	switch kind {
	case "deployment":
		d, err := pc.cs.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return out
		}
		out.Alive = d.Status.ReadyReplicas
		if d.Spec.Replicas != nil {
			out.Total = *d.Spec.Replicas
		} else {
			out.Total = d.Status.Replicas
		}
		out.Found = true
	case "daemonset":
		d, err := pc.cs.AppsV1().DaemonSets(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return out
		}
		out.Alive = d.Status.NumberReady
		out.Total = d.Status.DesiredNumberScheduled
		out.Found = true
	case "statefulset":
		s, err := pc.cs.AppsV1().StatefulSets(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return out
		}
		out.Alive = s.Status.ReadyReplicas
		if s.Spec.Replicas != nil {
			out.Total = *s.Spec.Replicas
		} else {
			out.Total = s.Status.Replicas
		}
		out.Found = true
	}
	return out
}

func (pc *PodCache) Lookup(containerID string) (PodInfo, bool) {
	if containerID == "" {
		return PodInfo{}, false
	}
	key := shortID(containerID)
	pc.mu.RLock()
	info, ok := pc.cache[key]
	if !ok {
		if l, found := pc.learned[key]; found && time.Since(l.at) < learnedTTL {
			info, ok = l.info, true
		}
	}
	pc.mu.RUnlock()
	return info, ok
}

func (pc *PodCache) LookupPID(pids ...int) (PodInfo, bool) {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	for _, pid := range pids {
		if pid <= 0 {
			continue
		}
		if l, ok := pc.pidCache[pid]; ok && time.Since(l.at) < pidTTL {
			return l.info, true
		}
	}
	return PodInfo{}, false
}

func (pc *PodCache) Remember(containerID string, pid int, info PodInfo) {
	if info.PodUID == "" {
		return
	}
	now := time.Now()
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if containerID != "" {
		key := shortID(containerID)
		if _, known := pc.cache[key]; !known {
			if pc.learned == nil {
				pc.learned = make(map[string]learnedInfo)
			}
			pc.learned[key] = learnedInfo{info: info, at: now}
		}
	}
	if pid > 0 {
		if pc.pidCache == nil {
			pc.pidCache = make(map[int]learnedInfo)
		}
		if len(pc.pidCache) >= pidCacheMax {
			for k, v := range pc.pidCache {
				if now.Sub(v.at) >= pidTTL {
					delete(pc.pidCache, k)
				}
			}
		}
		pc.pidCache[pid] = learnedInfo{info: info, at: now}
	}
}

func (pc *PodCache) Apply(info PodInfo, podName, namespace, node, podUID, podIP *string) {
	if *podName == "" {
		*podName = info.PodName
	}
	if *namespace == "" {
		*namespace = info.Namespace
	}
	if *node == "" {
		*node = info.NodeName
	}
	if *podUID == "" {
		*podUID = info.PodUID
	}
	if *podIP == "" {
		*podIP = info.PodIP
	}
}

func (pc *PodCache) prune() {
	now := time.Now()
	pc.mu.Lock()
	for k, v := range pc.learned {
		if now.Sub(v.at) >= learnedTTL {
			delete(pc.learned, k)
		}
	}
	for k, v := range pc.pidCache {
		if now.Sub(v.at) >= pidTTL {
			delete(pc.pidCache, k)
		}
	}
	pc.mu.Unlock()
}

func (pc *PodCache) Enrich(containerID string, podName, namespace, node, podUID, podIP *string) bool {
	info, ok := pc.Lookup(containerID)
	if !ok && *podName != "" && *namespace != "" {
		pc.mu.RLock()
		for _, candidate := range pc.cache {
			if candidate.PodName == *podName && candidate.Namespace == *namespace {
				info, ok = candidate, true
				break
			}
		}
		pc.mu.RUnlock()
	}
	if !ok && pc.cs != nil && *podName != "" && *namespace != "" {
		key := *namespace + "/" + *podName
		now := time.Now()
		pc.fallbackMu.Lock()
		allowed := now.After(pc.fallbackAt[key])
		if allowed {
			pc.fallbackAt[key] = now.Add(5 * time.Second)
		}
		pc.fallbackMu.Unlock()
		if allowed {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			pod, err := pc.cs.CoreV1().Pods(*namespace).Get(ctx, *podName, metav1.GetOptions{})
			cancel()
			if err == nil {
				info = PodInfo{PodName: pod.Name, Namespace: pod.Namespace, NodeName: pod.Spec.NodeName, PodUID: string(pod.UID), PodIP: pod.Status.PodIP}
				ok = true
				pc.Remember(containerID, 0, info)
			}
		}
	}
	if !ok {
		return false
	}
	pc.Apply(info, podName, namespace, node, podUID, podIP)
	return true
}

func (pc *PodCache) IsSystemNS(ns string) bool {
	return systemNamespaces[ns]
}
