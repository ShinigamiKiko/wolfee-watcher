package checker

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

type Result int

const (
	Allowed Result = iota
	Blocked
)

func (r Result) String() string {
	if r == Blocked {
		return "blocked"
	}
	return "allowed"
}

type nsPolicies struct {
	policies  []networkingv1.NetworkPolicy
	refreshed time.Time
}

type Checker struct {
	client kubernetes.Interface
	mu     sync.RWMutex
	byNS   map[string]nsPolicies
	ttl    time.Duration
}

func New(client kubernetes.Interface) *Checker {
	return &Checker{client: client, byNS: make(map[string]nsPolicies), ttl: 30 * time.Second}
}

func (c *Checker) Check(ctx context.Context, srcNS string, podLabels map[string]string, dstIP string, dstPort int) (Result, error) {
	policies, err := c.getPolicies(ctx, srcNS)
	if err != nil {
		return Allowed, fmt.Errorf("get policies: %w", err)
	}

	set := labels.Set(podLabels)
	var applicable []networkingv1.NetworkPolicy
	for _, p := range policies {
		sel, err := metav1.LabelSelectorAsSelector(&p.Spec.PodSelector)
		if err != nil {
			continue
		}

		if sel.Matches(set) {
			applicable = append(applicable, p)
		}
	}

	if len(applicable) == 0 {
		return Allowed, nil
	}

	for _, p := range applicable {

		hasEgress := false
		for _, pt := range p.Spec.PolicyTypes {
			if pt == networkingv1.PolicyTypeEgress {
				hasEgress = true
				break
			}
		}
		if !hasEgress {
			continue
		}
		for _, rule := range p.Spec.Egress {
			if egressRuleMatches(rule, dstIP, dstPort) {
				return Allowed, nil
			}
		}
	}

	return Blocked, nil
}

func egressRuleMatches(rule networkingv1.NetworkPolicyEgressRule, dstIP string, dstPort int) bool {

	ipMatch := len(rule.To) == 0
	for _, peer := range rule.To {
		if peer.IPBlock != nil {
			_, cidr, err := net.ParseCIDR(peer.IPBlock.CIDR)
			if err == nil && cidr.Contains(net.ParseIP(dstIP)) {
				ipMatch = true
				break
			}
		}
		if peer.NamespaceSelector != nil || peer.PodSelector != nil {

			ipMatch = true
			break
		}
	}

	if !ipMatch {
		return false
	}

	if len(rule.Ports) == 0 {
		return true
	}
	for _, p := range rule.Ports {
		if p.Port == nil {
			return true
		}
		if int(p.Port.IntVal) == dstPort {
			return true
		}
	}
	return false
}

func (c *Checker) getPolicies(ctx context.Context, ns string) ([]networkingv1.NetworkPolicy, error) {
	c.mu.RLock()
	if e, ok := c.byNS[ns]; ok && time.Since(e.refreshed) < c.ttl {
		p := e.policies
		c.mu.RUnlock()
		return p, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.byNS[ns]; ok && time.Since(e.refreshed) < c.ttl {
		return e.policies, nil
	}

	list, err := c.client.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Printf("[checker] failed to list NetworkPolicies in %s: %v", ns, err)
		if e, ok := c.byNS[ns]; ok {
			return e.policies, nil
		}
		return nil, nil
	}

	c.byNS[ns] = nsPolicies{policies: list.Items, refreshed: time.Now()}
	log.Printf("[checker] refreshed %d NetworkPolicies in ns=%s", len(list.Items), ns)
	return list.Items, nil
}
