package k8s

import (
	"testing"
	"time"
)

func TestLookupPIDResolvesIdentityWhenContainerIDMissing(t *testing.T) {
	pc := &PodCache{cache: map[string]PodInfo{}}
	pc.Remember("abcdef123456", 4242, PodInfo{
		PodName:   "worker",
		Namespace: "default",
		NodeName:  "node-a",
		PodUID:    "pod-uid",
		PodIP:     "10.0.0.42",
	})

	if _, ok := pc.LookupPID(9999); ok {
		t.Fatal("unknown pid must not resolve")
	}

	info, ok := pc.LookupPID(7777, 4242)
	if !ok {
		t.Fatal("expected parent pid to resolve pod identity")
	}

	var pod, namespace, node, uid, ip string
	pc.Apply(info, &pod, &namespace, &node, &uid, &ip)
	if uid != "pod-uid" || pod != "worker" || ip != "10.0.0.42" {
		t.Fatalf("unexpected pid enrichment: pod=%q uid=%q ip=%q", pod, uid, ip)
	}
}

func TestRememberedContainerSurvivesCacheRefresh(t *testing.T) {
	pc := &PodCache{cache: map[string]PodInfo{}}
	pc.Remember("abcdef123456", 0, PodInfo{PodName: "worker", Namespace: "default", PodUID: "pod-uid"})

	pc.mu.Lock()
	pc.cache = map[string]PodInfo{}
	pc.mu.Unlock()

	if _, ok := pc.Lookup("abcdef123456789"); !ok {
		t.Fatal("learned container identity must survive a full cache refresh")
	}
}

func TestPruneDropsExpiredLearnedEntries(t *testing.T) {
	pc := &PodCache{cache: map[string]PodInfo{}}
	pc.Remember("abcdef123456", 4242, PodInfo{PodName: "worker", Namespace: "default", PodUID: "pod-uid"})

	pc.mu.Lock()
	for k, v := range pc.learned {
		pc.learned[k] = learnedInfo{info: v.info, at: time.Now().Add(-2 * learnedTTL)}
	}
	for k, v := range pc.pidCache {
		pc.pidCache[k] = learnedInfo{info: v.info, at: time.Now().Add(-2 * pidTTL)}
	}
	pc.mu.Unlock()

	pc.prune()

	if _, ok := pc.Lookup("abcdef123456"); ok {
		t.Fatal("expired learned container entry must be pruned")
	}
	if _, ok := pc.LookupPID(4242); ok {
		t.Fatal("expired pid entry must be pruned")
	}
}

func TestEnrichPreservesPodIdentityAndIP(t *testing.T) {
	pc := &PodCache{cache: map[string]PodInfo{
		"container123": {
			PodName:   "same-name",
			Namespace: "default",
			NodeName:  "node-a",
			PodUID:    "pod-uid",
			PodIP:     "10.0.0.42",
		},
	}}

	var pod, namespace, node, uid, ip string
	if !pc.Enrich("container123456789", &pod, &namespace, &node, &uid, &ip) {
		t.Fatal("expected container identity to be found")
	}
	if pod != "same-name" || namespace != "default" || node != "node-a" || uid != "pod-uid" || ip != "10.0.0.42" {
		t.Fatalf("unexpected enrichment: pod=%q namespace=%q node=%q uid=%q ip=%q", pod, namespace, node, uid, ip)
	}
}

func TestEnrichFallsBackToPodIdentityWhenContainerRotated(t *testing.T) {
	pc := &PodCache{cache: map[string]PodInfo{
		"current-container": {
			PodName:   "worker",
			Namespace: "default",
			NodeName:  "node-a",
			PodUID:    "pod-uid",
			PodIP:     "10.0.0.42",
		},
	}}

	pod, namespace, node, uid, ip := "worker", "default", "", "", ""
	if !pc.Enrich("old-container-id", &pod, &namespace, &node, &uid, &ip) {
		t.Fatal("expected pod identity fallback")
	}
	if node != "node-a" || uid != "pod-uid" || ip != "10.0.0.42" {
		t.Fatalf("unexpected fallback enrichment: node=%q uid=%q ip=%q", node, uid, ip)
	}
}
