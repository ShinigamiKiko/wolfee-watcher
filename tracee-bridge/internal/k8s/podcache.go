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
}

type PodCache struct {
	mu      sync.RWMutex
	cache   map[string]PodInfo
	cs      *kubernetes.Clientset
	mc      *metricsclient.Clientset
	restCfg *rest.Config
}

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
	pc := &PodCache{cache: make(map[string]PodInfo)}

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
	pc.mu.RLock()
	info, ok := pc.cache[shortID(containerID)]
	pc.mu.RUnlock()
	return info, ok
}

func (pc *PodCache) Enrich(containerID string, podName, namespace, node *string) bool {
	info, ok := pc.Lookup(containerID)
	if !ok {
		return false
	}
	if *podName == "" {
		*podName = info.PodName
	}
	if *namespace == "" {
		*namespace = info.Namespace
	}
	if *node == "" {
		*node = info.NodeName
	}
	return true
}

func (pc *PodCache) IsSystemNS(ns string) bool {
	return systemNamespaces[ns]
}
