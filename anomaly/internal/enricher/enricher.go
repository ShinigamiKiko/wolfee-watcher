package enricher

import (
	"context"
	"log"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	cacheTTL        = 30 * time.Second
	podRefetchEvery = 5 * time.Second
	podIPPollEvery  = 300 * time.Millisecond
	podMissCap      = 4096
)

type PodInfo struct {
	Deployment     string
	Node           string
	Namespace      string
	PodIP          string
	UID            string
	Labels         map[string]string
	ServiceAccount string
}

type SvcInfo struct {
	Name      string
	Namespace string
	Selector  map[string]string
}

type Enricher struct {
	client kubernetes.Interface

	muPods sync.RWMutex
	pods   map[string]PodInfo
	podsAt time.Time

	muMiss sync.Mutex
	missAt map[string]time.Time

	muSvcs sync.RWMutex
	svcs   map[string]SvcInfo
	svcsAt time.Time
}

func New(client kubernetes.Interface) *Enricher {
	return &Enricher{
		client: client,
		pods:   make(map[string]PodInfo),
		missAt: make(map[string]time.Time),
		svcs:   make(map[string]SvcInfo),
	}
}

func (e *Enricher) Pod(ctx context.Context, ns, podName string) PodInfo {
	return e.PodByUID(ctx, ns, podName, "")
}

func (e *Enricher) PodByUID(ctx context.Context, ns, podName, uid string) PodInfo {
	e.refreshPods(ctx)

	e.muPods.RLock()
	info, ok := e.pods[ns+"/"+podName]
	e.muPods.RUnlock()

	stale := ok && uid != "" && info.UID != "" && info.UID != uid
	if !ok || info.PodIP == "" || stale {
		if fresh, found := e.fetchPod(ctx, ns, podName, uid); found {
			return fresh
		}
	}
	if stale {
		return PodInfo{Deployment: info.Deployment, Namespace: ns, Node: info.Node}
	}
	if ok {
		return info
	}

	return PodInfo{
		Deployment: DeploymentFromPod(podName),
		Namespace:  ns,
	}
}

func (e *Enricher) fetchPod(ctx context.Context, ns, podName, uid string) (PodInfo, bool) {
	key := ns + "/" + podName
	missKey := key + "/" + uid
	e.muMiss.Lock()
	if at, ok := e.missAt[missKey]; ok && time.Since(at) < podRefetchEvery {
		e.muMiss.Unlock()
		return PodInfo{}, false
	}
	e.missAt[missKey] = time.Now()
	if len(e.missAt) > podMissCap {
		for k, at := range e.missAt {
			if time.Since(at) >= podRefetchEvery {
				delete(e.missAt, k)
			}
		}
	}
	e.muMiss.Unlock()

	pod, err := e.client.CoreV1().Pods(ns).Get(ctx, podName, metav1.GetOptions{})
	if err != nil || pod.Status.PodIP == "" || (uid != "" && string(pod.UID) != uid) {
		return PodInfo{}, false
	}
	dep := DeploymentFromPod(pod.Name)
	for _, ref := range pod.OwnerReferences {
		if ref.Kind == "ReplicaSet" {
			if rs, err := e.client.AppsV1().ReplicaSets(ns).Get(ctx, ref.Name, metav1.GetOptions{}); err == nil {
				for _, rsRef := range rs.OwnerReferences {
					if rsRef.Kind == "Deployment" {
						dep = rsRef.Name
					}
				}
			}
			break
		}
	}
	info := PodInfo{
		Deployment:     dep,
		Node:           pod.Spec.NodeName,
		Namespace:      pod.Namespace,
		PodIP:          pod.Status.PodIP,
		UID:            string(pod.UID),
		Labels:         pod.Labels,
		ServiceAccount: pod.Spec.ServiceAccountName,
	}
	e.muPods.Lock()
	e.pods[key] = info
	e.muPods.Unlock()
	return info, true
}

func (e *Enricher) WaitPodIP(ctx context.Context, ns, podName, uid string, wait time.Duration) (PodInfo, bool) {
	deadline := time.Now().Add(wait)
	for {
		pod, err := e.client.CoreV1().Pods(ns).Get(ctx, podName, metav1.GetOptions{})
		if err == nil && (uid == "" || string(pod.UID) == uid) && pod.Status.PodIP != "" {
			info := PodInfo{
				Deployment:     DeploymentFromPod(pod.Name),
				Node:           pod.Spec.NodeName,
				Namespace:      pod.Namespace,
				PodIP:          pod.Status.PodIP,
				UID:            string(pod.UID),
				Labels:         pod.Labels,
				ServiceAccount: pod.Spec.ServiceAccountName,
			}
			e.muPods.Lock()
			if cur, ok := e.pods[ns+"/"+podName]; ok && cur.UID == info.UID && cur.Deployment != "" {
				info.Deployment = cur.Deployment
			}
			e.pods[ns+"/"+podName] = info
			e.muPods.Unlock()
			return info, true
		}
		if time.Now().After(deadline) {
			return PodInfo{}, false
		}
		select {
		case <-ctx.Done():
			return PodInfo{}, false
		case <-time.After(podIPPollEvery):
		}
	}
}

func (e *Enricher) IP(ctx context.Context, ip string) (SvcInfo, bool) {
	e.refreshSvcs(ctx)
	e.muSvcs.RLock()
	info, ok := e.svcs[ip]
	e.muSvcs.RUnlock()
	return info, ok
}

func (e *Enricher) refreshPods(ctx context.Context) {
	e.muPods.RLock()
	stale := time.Since(e.podsAt) > cacheTTL
	e.muPods.RUnlock()
	if !stale {
		return
	}

	list, err := e.client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Printf("[enricher] pod list: %v", err)
		return
	}

	fresh := make(map[string]PodInfo, len(list.Items))
	for _, pod := range list.Items {
		dep := DeploymentFromPod(pod.Name)

		for _, ref := range pod.OwnerReferences {
			if ref.Kind == "ReplicaSet" {
				rs, err := e.client.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
				if err == nil {
					for _, rsRef := range rs.OwnerReferences {
						if rsRef.Kind == "Deployment" {
							dep = rsRef.Name
							break
						}
					}
				}
				break
			}
			if ref.Kind == "Deployment" {
				dep = ref.Name
				break
			}
		}
		fresh[pod.Namespace+"/"+pod.Name] = PodInfo{
			Deployment:     dep,
			Node:           pod.Spec.NodeName,
			Namespace:      pod.Namespace,
			PodIP:          pod.Status.PodIP,
			UID:            string(pod.UID),
			Labels:         pod.Labels,
			ServiceAccount: pod.Spec.ServiceAccountName,
		}
	}

	e.muPods.Lock()
	e.pods = fresh
	e.podsAt = time.Now()
	e.muPods.Unlock()

	log.Printf("[enricher] pod cache refreshed: %d pods", len(fresh))
}

func (e *Enricher) refreshSvcs(ctx context.Context) {
	e.muSvcs.RLock()
	stale := time.Since(e.svcsAt) > cacheTTL
	e.muSvcs.RUnlock()
	if !stale {
		return
	}

	e.muSvcs.Lock()
	if time.Since(e.svcsAt) < cacheTTL {
		e.muSvcs.Unlock()
		return
	}
	e.muSvcs.Unlock()

	list, err := e.client.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Printf("[enricher] svc list: %v", err)
		return
	}

	fresh := make(map[string]SvcInfo, len(list.Items))
	for _, svc := range list.Items {
		ip := svc.Spec.ClusterIP
		if ip == "" || ip == "None" {
			continue
		}
		fresh[ip] = SvcInfo{
			Name:      svc.Name,
			Namespace: svc.Namespace,
			Selector:  svc.Spec.Selector,
		}
	}

	for _, svc := range list.Items {
		for _, ing := range svc.Status.LoadBalancer.Ingress {
			if ing.IP != "" {
				fresh[ing.IP] = SvcInfo{Name: svc.Name, Namespace: svc.Namespace}
			}
		}
		for _, eip := range svc.Spec.ExternalIPs {
			if eip != "" {
				fresh[eip] = SvcInfo{Name: svc.Name, Namespace: svc.Namespace}
			}
		}
	}

	e.muSvcs.Lock()
	e.svcs = fresh
	e.svcsAt = time.Now()
	e.muSvcs.Unlock()

	log.Printf("[enricher] svc cache refreshed: %d services", len(fresh))
}

func (e *Enricher) StartBackgroundRefresh(ctx context.Context) {
	go func() {
		t := time.NewTicker(cacheTTL / 2)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				e.refreshPods(ctx)
				e.refreshSvcs(ctx)
			}
		}
	}()
}

func (e *Enricher) ResolveNode(ctx context.Context, ns, podName string) string {
	info := e.Pod(ctx, ns, podName)
	return info.Node
}

func DeploymentFromPod(podName string) string {
	n := len(podName)
	dashes := 0
	for i := n - 1; i >= 0; i-- {
		if podName[i] == '-' {
			dashes++
			if dashes == 2 {
				return podName[:i]
			}
		}
	}
	return podName
}

func (e *Enricher) PodsBySelector(ctx context.Context, ns string, sel map[string]string) []corev1.Pod {
	e.refreshPods(ctx)
	list, err := e.client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
		LabelSelector: selectorString(sel),
	})
	if err != nil {
		return nil
	}
	return list.Items
}

func selectorString(sel map[string]string) string {
	out := ""
	for k, v := range sel {
		if out != "" {
			out += ","
		}
		out += k + "=" + v
	}
	return out
}

func (e *Enricher) PodIPsMatching(ctx context.Context, ns string, sel map[string]string) []string {
	if len(sel) == 0 {
		return nil
	}
	e.refreshPods(ctx)
	e.muPods.RLock()
	defer e.muPods.RUnlock()
	var out []string
	for _, p := range e.pods {
		if p.Namespace != ns || p.PodIP == "" {
			continue
		}
		match := true
		for k, v := range sel {
			if p.Labels[k] != v {
				match = false
				break
			}
		}
		if match {
			out = append(out, p.PodIP)
		}
	}
	return out
}
