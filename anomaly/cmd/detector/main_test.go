package main

import "testing"

func TestConsumerLockIDIsPerCluster(t *testing.T) {
	a := clusterConsumerLockID("k8s-test")
	b := clusterConsumerLockID("k8s-82")
	if a == b {
		t.Fatalf("clusters share consumer lock %d", a)
	}
	if a == defaultConsumerLockID || a == 0 {
		t.Fatalf("unexpected lock %d", a)
	}
	if clusterConsumerLockID("k8s-test") != a {
		t.Fatal("lock id is not stable")
	}
}

func TestConsumerLockIDEnvOverride(t *testing.T) {
	t.Setenv("CLUSTER_ID", "k8s-test")
	t.Setenv("ANOMALY_CONSUMER_LOCK_ID", "42")
	if got := consumerLockID(); got != 42 {
		t.Fatalf("override ignored: %d", got)
	}
	t.Setenv("ANOMALY_CONSUMER_LOCK_ID", "")
	if got := consumerLockID(); got == defaultConsumerLockID {
		t.Fatal("cluster-scoped lock not used")
	}
}
