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

const cacheTTL = 30 * time.Second

type PodInfo struct {
	Deployment string
	Node       string
	Namespace  string
	PodIP      string
	Labels     map[string]string
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

	muSvcs sync.RWMutex
	svcs   map[string]SvcInfo
	svcsAt time.Time
}

func New(client kubernetes.Interface) *Enricher {
	return &Enricher{
		client: client,
		pods:   make(map[string]PodInfo),
		svcs:   make(map[string]SvcInfo),
	}
}

func (e *Enricher) Pod(ctx context.Context, ns, podName string) PodInfo {
	e.refreshPods(ctx)

	e.muPods.RLock()
	info, ok := e.pods[ns+"/"+podName]
	e.muPods.RUnlock()

	if ok {
		return info
	}

	return PodInfo{
		Deployment: DeploymentFromPod(podName),
		Namespace:  ns,
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
			Deployment: dep,
			Node:       pod.Spec.NodeName,
			Namespace:  pod.Namespace,
			PodIP:      pod.Status.PodIP,
			Labels:     pod.Labels,
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
