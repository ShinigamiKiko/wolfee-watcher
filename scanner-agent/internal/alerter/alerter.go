package alerter

import (
	"context"
	"encoding/json"
	"log"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	alertspkg "github.com/wolfee-watcher/pkg/alerts"

	internal "github.com/wolfee-watcher/scanner-agent/internal"
)

const (
	ruleRefreshInterval = 30 * time.Second
	evalInterval        = 60 * time.Second
	dedupTTL            = 10 * time.Minute
	dedupMaxEntries     = 20_000
	sourceTag           = "scanner-agent"
)

type Snapshot interface {
	ListClusterImages(ctx context.Context) ([]internal.ClusterImage, error)
	ListHistoriesSnapshot() []internal.ImageHistory
}

type buildRule struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Enabled           bool   `json:"enabled"`
	AlertOnly         bool   `json:"alertOnly"`
	DetType           string `json:"detType"`
	Sev               string `json:"sev"`
	Namespace         string `json:"namespace"`
	BuildInstruction  string `json:"buildInstruction"`
	TrustedRegistries string `json:"trustedRegistries"`
}

type Alerter struct {
	fetcher  *alertspkg.RuleFetcher
	snapshot Snapshot
	fwd      *alertspkg.Forwarder

	mu    sync.RWMutex
	rules []buildRule

	dedupMu sync.Mutex
	dedup   map[string]time.Time
}

func New(ctx context.Context, snap Snapshot) *Alerter {
	a := &Alerter{
		fetcher:  alertspkg.NewRuleFetcher("Build"),
		snapshot: snap,
		fwd:      alertspkg.NewForwarder(),
		dedup:    make(map[string]time.Time),
	}
	if a.fetcher == nil || snap == nil {
		log.Printf("[alerter] KVISIOR_URL not set — alert rules unavailable, alerting disabled")
		return a
	}
	if err := a.refresh(ctx); err != nil {
		log.Printf("[alerter] initial rule load failed: %v", err)
	} else {
		log.Printf("[alerter] loaded %d alertOnly build rule(s)", a.RuleCount())
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

	a.runOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.runOnce(ctx)
		}
	}
}

func (a *Alerter) runOnce(ctx context.Context) {
	a.mu.RLock()
	rules := a.rules
	a.mu.RUnlock()
	if len(rules) == 0 {
		return
	}

	listCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	images, err := a.snapshot.ListClusterImages(listCtx)
	cancel()
	if err != nil {
		log.Printf("[alerter] list images: %v", err)
		return
	}
	histories := a.snapshot.ListHistoriesSnapshot()
	histByRef := make(map[string]internal.ImageHistory, len(histories))
	for _, h := range histories {
		histByRef[h.Image] = h
	}

	for _, r := range rules {
		evalRule(a, r, images, histByRef)
	}
}

func evalRule(a *Alerter, r buildRule, images []internal.ClusterImage, histByRef map[string]internal.ImageHistory) {
	nsFilter := strings.TrimSpace(r.Namespace)

	if tr := strings.TrimSpace(r.TrustedRegistries); tr != "" {
		var trusted []string
		for _, t := range strings.Split(tr, ",") {
			if v := strings.TrimSpace(strings.ToLower(t)); v != "" {
				trusted = append(trusted, v)
			}
		}
		for _, img := range images {
			if img.Ref == "" {
				continue
			}
			if nsFilter != "" && !sliceContains(img.Namespaces, nsFilter) {
				continue
			}
			low := strings.ToLower(img.Ref)
			isTrusted := false
			for _, t := range trusted {
				if strings.HasPrefix(low, t) {
					isTrusted = true
					break
				}
			}
			if !isTrusted {
				detail := "Image not from trusted registry. Trusted: " + strings.Join(trusted, ", ")
				a.emit(r, img.Ref, nsFilter, detail, "trusted-registry")
			}
		}
	}

	if pat := strings.TrimSpace(r.BuildInstruction); pat != "" {
		rx, err := regexp.Compile("(?i)" + pat)
		if err != nil {
			rx = regexp.MustCompile("(?i)" + regexp.QuoteMeta(pat))
		}
		for _, img := range images {
			if img.Ref == "" {
				continue
			}
			if strings.HasPrefix(img.Ref, "localhost/") || strings.HasPrefix(img.Ref, "localhost:") {
				continue
			}
			if nsFilter != "" && !sliceContains(img.Namespaces, nsFilter) {
				continue
			}
			hist, ok := histByRef[img.Ref]
			if !ok {
				continue
			}
			status := strings.ToLower(string(hist.Status))
			if status == "pending" || status == "fetching" {
				continue
			}
			if status == "unavailable" {
				a.emit(r, img.Ref, nsFilter,
					"History unavailable: "+stringOr(hist.Error, "registry unreachable"),
					"history-unavailable")
				continue
			}
			for _, l := range hist.Layers {
				if rx.MatchString(l.CreatedBy) {
					a.emit(r, img.Ref, nsFilter,
						"Layer matches: "+cleanLayer(l.CreatedBy),
						"layer-match")
					break
				}
			}
		}
	}
}

func cleanLayer(s string) string {
	s = strings.TrimPrefix(s, "/bin/sh -c #(nop) ")
	s = strings.TrimPrefix(s, "/bin/sh -c ")
	return strings.TrimSpace(s)
}

func stringOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func sliceContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func (a *Alerter) emit(r buildRule, image, namespace, detail, checkKind string) {
	fp := strings.Join([]string{"bld", r.ID, image, checkKind, detail}, "|")
	if !a.markFresh(fp) {
		return
	}
	name := r.Name
	if name == "" {
		name = r.ID
	}
	ns := namespace
	if ns == "" {
		ns = "—"
	}
	log.Printf("[Warn] build detected %s in %s/%s detail=%q", name, ns, image, detail)
	payload, err := json.Marshal(map[string]any{
		"image":     image,
		"namespace": namespace,
		"check":     checkKind,
	})
	if err != nil {

		log.Printf("[alerter] marshal alert data: %v", err)
		payload = nil
	}

	a.fwd.Send(alertspkg.AlertLog{
		DetType:     "Build",
		Source:      sourceTag,
		RuleID:      r.ID,
		RuleName:    name,
		Severity:    r.Sev,
		Namespace:   namespace,
		Target:      image,
		Detail:      detail,
		Persist:     true,
		Fingerprint: fp,
		Data:        payload,
	})
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
	var fresh []buildRule
	for _, raw := range policies {
		var r buildRule
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
		log.Printf("[alerter] rule set changed: %d → %d alertOnly build rule(s)", prevCount, len(fresh))
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
		a.evictOldest(len(a.dedup) - dedupMaxEntries)
	}
}

func (a *Alerter) evictOldest(n int) {
	type fpTime struct {
		fp string
		ts time.Time
	}
	entries := make([]fpTime, 0, len(a.dedup))
	for fp, ts := range a.dedup {
		entries = append(entries, fpTime{fp, ts})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ts.Before(entries[j].ts)
	})
	for i := 0; i < n && i < len(entries); i++ {
		delete(a.dedup, entries[i].fp)
	}
}
