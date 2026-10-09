package podindex

import (
	"fmt"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func pod(name, ns, uid, ip, phase string, created time.Time, finished *time.Time, extra string) string {
	term := ""
	if finished != nil {
		term = fmt.Sprintf(`,"containerStatuses":[{"state":{"terminated":{"finishedAt":%q}}}]`, finished.Format(time.RFC3339))
	}
	return fmt.Sprintf(`{"metadata":{"name":%q,"namespace":%q,"uid":%q,"creationTimestamp":%q%s},
	  "spec":{"serviceAccountName":%q,"nodeName":"n1","containers":[{"image":"img:1"}]},
	  "status":{"phase":%q,"podIP":%q%s}}`,
		name, ns, uid, created.Format(time.RFC3339), extra, name+"-sa", phase, ip, term)
}

func snap(pods ...string) []byte {
	out := `{"pods":[`
	for i, p := range pods {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return []byte(out + "]}")
}

func TestLookupResolvesRunningPod(t *testing.T) {
	x := New(30 * time.Minute)
	web := pod("web-7f9c6d5b8-kq2pz", "shop", "u2", "10.244.0.41", "Running", t0, nil,
		`,"ownerReferences":[{"kind":"ReplicaSet","name":"web-7f9c6d5b8"}]`)
	host := `{"metadata":{"name":"agent","namespace":"infra","uid":"u3"},"spec":{"hostNetwork":true},"status":{"phase":"Running","podIP":"192.168.1.10"}}`
	if err := x.Update("k8s-test", snap(web, host), t0); err != nil {
		t.Fatal(err)
	}
	c, ok := x.Lookup("k8s-test", "10.244.0.41", t0.Add(time.Minute))
	if !ok || c.Pod != "web-7f9c6d5b8-kq2pz" || c.Workload != "web" || c.ServiceAccount != "web-7f9c6d5b8-kq2pz-sa" {
		t.Fatalf("lookup = %+v %v", c, ok)
	}
	if _, ok := x.Lookup("k8s-test", "192.168.1.10", t0); ok {
		t.Fatal("host network pod must not be indexed")
	}
	if _, ok := x.Lookup("other", "10.244.0.41", t0); ok {
		t.Fatal("lookup must be scoped by cluster")
	}
}

func TestReusedIPPrefersCurrentPod(t *testing.T) {
	x := New(30 * time.Minute)
	oldDone := t0.Add(-150 * time.Minute)
	old := pod("reporting-worker-2", "ww-hp-test", "old", "10.244.0.181", "Succeeded", t0.Add(-151*time.Minute), &oldDone, "")
	cur := pod("analytics-api", "ww-hp-test", "new", "10.244.0.181", "Running", t0.Add(-10*time.Second), nil, "")
	for _, order := range [][]string{{old, cur}, {cur, old}} {
		if err := x.Update("k8s-test", snap(order...), t0); err != nil {
			t.Fatal(err)
		}
		c, ok := x.Lookup("k8s-test", "10.244.0.181", t0)
		if !ok || c.Pod != "analytics-api" {
			t.Fatalf("reused IP resolved to %+v %v", c, ok)
		}
	}
}

func TestFinishedPodIsNotBlamedForLaterEvents(t *testing.T) {
	x := New(30 * time.Minute)
	done := t0.Add(-time.Hour)
	old := pod("reporting-worker-2", "ww-hp-test", "old", "10.244.0.181", "Succeeded", t0.Add(-2*time.Hour), &done, "")
	if err := x.Update("k8s-test", snap(old), t0); err != nil {
		t.Fatal(err)
	}
	if _, ok := x.Lookup("k8s-test", "10.244.0.181", t0); ok {
		t.Fatal("a pod that finished an hour ago must not match a new event on its old IP")
	}
	if c, ok := x.Lookup("k8s-test", "10.244.0.181", done.Add(-time.Minute)); !ok || c.Pod != "reporting-worker-2" {
		t.Fatalf("an event while the pod was alive must resolve, got %+v %v", c, ok)
	}
}

func TestGonePodIsKeptForEarlierEventsOnly(t *testing.T) {
	x := New(30 * time.Minute)
	p := pod("analytics-api", "ww-hp-test", "u1", "10.244.0.40", "Running", t0.Add(-time.Minute), nil, "")
	if err := x.Update("k8s-test", snap(p), t0); err != nil {
		t.Fatal(err)
	}
	gone := t0.Add(time.Minute)
	if err := x.Update("k8s-test", snap(), gone); err != nil {
		t.Fatal(err)
	}
	if c, ok := x.Lookup("k8s-test", "10.244.0.40", t0.Add(30*time.Second)); !ok || c.Pod != "analytics-api" {
		t.Fatalf("event before the pod disappeared must resolve, got %+v %v", c, ok)
	}
	if _, ok := x.Lookup("k8s-test", "10.244.0.40", gone.Add(time.Minute)); ok {
		t.Fatal("event after the pod disappeared must not resolve to it")
	}
	if err := x.Update("k8s-test", snap(), t0.Add(32*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, ok := x.Lookup("k8s-test", "10.244.0.40", t0.Add(30*time.Second)); ok {
		t.Fatal("entry must expire after the keep window")
	}
}
