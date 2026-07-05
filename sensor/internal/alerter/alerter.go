package alerter

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	alertspkg "github.com/wolfee-watcher/pkg/alerts"

	"github.com/wolfee-watcher/sensor/internal/collector"
)

const (
	ruleRefreshInterval = 30 * time.Second
	evalInterval        = 60 * time.Second
	dedupTTL            = 10 * time.Minute
	dedupMaxEntries     = 20_000
	sourceTag           = "sensor"
)

var systemNS = map[string]bool{
	"kube-system":      true,
	"kube-public":      true,
	"kube-node-lease":  true,
	"calico-system":    true,
	"calico-apiserver": true,
	"cilium":           true,
	"cert-manager":     true,
}

type SnapshotProvider interface {
	GetSnapshot() *collector.Snapshot
}

type deployRule struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Enabled      bool     `json:"enabled"`
	AlertOnly    bool     `json:"alertOnly"`
	DetType      string   `json:"detType"`
	Sev          string   `json:"sev"`
	Namespace    string   `json:"namespace"`
	DeployChecks []string `json:"deployChecks"`
}

type Alerter struct {
	fetcher *alertspkg.RuleFetcher
	snap    SnapshotProvider
	fwd     *alertspkg.Forwarder

	mu    sync.RWMutex
	rules []deployRule

	dedupMu sync.Mutex
	dedup   map[string]time.Time
}

func New(ctx context.Context, snap SnapshotProvider) *Alerter {
	a := &Alerter{
		fetcher: alertspkg.NewRuleFetcher("Deploy"),
		snap:    snap,
		fwd:     alertspkg.NewForwarder(),
		dedup:   make(map[string]time.Time),
	}
	if a.fetcher == nil || snap == nil {
		log.Printf("[alerter] KVISIOR_URL not set — alert rules unavailable, alerting disabled")
		return a
	}
	if err := a.refresh(ctx); err != nil {
		log.Printf("[alerter] initial rule load failed: %v", err)
	} else {
		log.Printf("[alerter] loaded %d alertOnly deploy rule(s)", a.RuleCount())
	}
	go a.refreshLoop(ctx)
	go a.evalLoop(ctx)
	go a.dedupSweepLoop(ctx)
	return a
}

func (a *Alerter) RuleCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.rules)
}

func (a *Alerter) Close() {
	a.fwd.Close()
}

func (a *Alerter) evalLoop(ctx context.Context) {
	t := time.NewTicker(evalInterval)
	defer t.Stop()
	a.runOnce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.runOnce()
		}
	}
}

func (a *Alerter) markFresh(fp string) bool {
	a.dedupMu.Lock()
	defer a.dedupMu.Unlock()
	now := time.Now()
	if last, ok := a.dedup[fp]; ok && now.Sub(last) < dedupTTL {
		return false
	}
	a.dedup[fp] = now
	return true
}

func (a *Alerter) refreshLoop(ctx context.Context) {
	t := time.NewTicker(ruleRefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := a.refresh(ctx); err != nil {
				log.Printf("[alerter] rule refresh failed: %v", err)
			}
		}
	}
}

func (a *Alerter) refresh(ctx context.Context) error {
	loadCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	policies, err := a.fetcher.Fetch(loadCtx)
	if err != nil {
		return err
	}
	var fresh []deployRule
	for _, raw := range policies {
		var r deployRule
		if err := json.Unmarshal(raw, &r); err != nil {
			continue
		}
		fresh = append(fresh, r)
	}
	a.mu.Lock()
	prevCount := len(a.rules)
	a.rules = fresh
	a.mu.Unlock()
	if prevCount != len(fresh) {
		log.Printf("[alerter] rule set changed: %d → %d alertOnly deploy rule(s)", prevCount, len(fresh))
	}
	return nil
}

func (a *Alerter) dedupSweepLoop(ctx context.Context) {
	t := time.NewTicker(dedupTTL)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.sweep()
		}
	}
}

func (a *Alerter) sweep() {
	a.dedupMu.Lock()
	defer a.dedupMu.Unlock()
	cutoff := time.Now().Add(-dedupTTL)
	for fp, ts := range a.dedup {
		if ts.Before(cutoff) {
			delete(a.dedup, fp)
		}
	}
	if len(a.dedup) > dedupMaxEntries {
		a.dedup = make(map[string]time.Time)
	}
}
