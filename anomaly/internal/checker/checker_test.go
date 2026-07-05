package checker

import (
	"context"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func denyEgress(ns, name string, sel map[string]string) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: sel},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		},
	}
}

func TestCheck_PerNamespaceCache(t *testing.T) {
	client := fake.NewSimpleClientset(denyEgress("a", "deny-all", nil))
	chk := New(client)
	ctx := context.Background()

	if r, _ := chk.Check(ctx, "a", map[string]string{"x": "y"}, "8.8.8.8", 443); r != Blocked {
		t.Fatalf("ns a deny-all: want Blocked, got %v", r)
	}
	if r, _ := chk.Check(ctx, "b", map[string]string{"x": "y"}, "8.8.8.8", 443); r != Allowed {
		t.Fatalf("ns b has no policy but got %v — policies leaked across namespaces", r)
	}
}

func TestCheck_PodSelectorMatching(t *testing.T) {
	client := fake.NewSimpleClientset(denyEgress("c", "deny-web-egress", map[string]string{"app": "web"}))
	chk := New(client)
	ctx := context.Background()

	if r, _ := chk.Check(ctx, "c", map[string]string{"app": "web"}, "8.8.8.8", 443); r != Blocked {
		t.Fatalf("selected pod (app=web): want Blocked, got %v", r)
	}
	if r, _ := chk.Check(ctx, "c", map[string]string{"app": "db"}, "8.8.8.8", 443); r != Allowed {
		t.Fatalf("non-selected pod (app=db): want Allowed, got %v — podSelector ignored", r)
	}
}
