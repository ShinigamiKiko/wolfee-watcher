package k8s

import "testing"

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
