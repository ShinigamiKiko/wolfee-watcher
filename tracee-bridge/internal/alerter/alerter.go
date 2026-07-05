package alerter

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	alertspkg "github.com/wolfee-watcher/pkg/alerts"
	"github.com/wolfee-watcher/tracee-bridge/internal/mapper"
	"github.com/wolfee-watcher/tracee-bridge/internal/matcher"
)

const ruleRefreshInterval = 30 * time.Second

const dedupTTL = 10 * time.Minute

const dedupMaxEntries = 20_000

const sourceTag = "tracee-bridge"

type Alerter struct {
	pool *pgxpool.Pool
	fwd  *alertspkg.Forwarder

	mu    sync.RWMutex
	rules []matcher.Rule

	dedupMu sync.Mutex
	dedup   map[string]time.Time
}

func New(ctx context.Context, pool *pgxpool.Pool) *Alerter {
	a := &Alerter{
		pool:  pool,
		fwd:   alertspkg.NewForwarder(),
		dedup: make(map[string]time.Time),
	}

	a.fwd.OnDeliveryFailed(a.persistBatch)
	if pool == nil {
		return a
	}
	if err := a.refresh(ctx); err != nil {
		log.Printf("[alerter] initial rule load failed: %v", err)
	} else {
		log.Printf("[alerter] loaded %d alertOnly rule(s)", a.RuleCount())
	}
	go a.refreshLoop(ctx)
	go a.dedupSweepLoop(ctx)
	return a
}

func (a *Alerter) RuleCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.rules)
}

func (a *Alerter) Evaluate(ev *mapper.UIEvent) {
	a.mu.RLock()
	rules := a.rules
	a.mu.RUnlock()
	if len(rules) == 0 || ev == nil {
		return
	}
	me := matcher.Event{
		Syscall:   ev.Syscall,
		Category:  ev.Category,
		Namespace: ev.Namespace,
		Pod:       ev.Pod,
		Process:   ev.Process,
		Execpath:  ev.Execpath,
		Cmdline:   ev.Cmdline,
		Args:      ev.Args,
	}
	for _, r := range rules {
		if !matcher.Matches(me, r) {
			continue
		}
		fp := strings.Join([]string{"rt", r.ID, ev.Namespace, ev.Pod, ev.Syscall}, "|")
		if !a.markFresh(fp) {
			continue
		}
		name := r.ID
		if r.DetType == "Binary" && r.ProcessFilter != "" {
			name = "Binary: " + r.ProcessFilter
		} else if r.Syscall != "" && r.Syscall != "*" {
			prefix := "Syscall"
			switch r.DetType {
			case "LSM", "Tracepoint":
				prefix = r.DetType
			}
			name = prefix + ": " + r.Syscall
		}
		ns := ev.Namespace
		if ns == "" {
			ns = "—"
		}
		pod := ev.Pod
		if pod == "" {
			pod = "—"
		}
		detType := r.DetType
		if detType == "" {
			detType = "Syscall"
		}

		payload, _ := json.Marshal(ev)
		al := alertspkg.AlertLog{
			DetType:     detType,
			Source:      sourceTag,
			RuleID:      r.ID,
			RuleName:    name,
			Severity:    ev.Severity,
			Namespace:   ns,
			Target:      pod,
			Syscall:     ev.Syscall,
			Detail:      ev.Cmdline,
			Persist:     true,
			Fingerprint: fp,
			Data:        payload,
		}
		a.fwd.Send(al)
	}
}

func (a *Alerter) persistBatch(batch []alertspkg.AlertLog) {
	for i := range batch {
		a.persist(batch[i])
	}
}

func (a *Alerter) persist(al alertspkg.AlertLog) {
	if a.pool == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := a.pool.Exec(ctx, `
		INSERT INTO alerts
		  (source, det_type, rule_id, rule_name, severity, namespace, target, syscall, detail, fingerprint, data)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		al.Source, al.DetType, al.RuleID, al.RuleName, al.Severity, al.Namespace,
		al.Target, al.Syscall, al.Detail, al.Fingerprint, al.Data,
	)
	if err != nil {
		log.Printf("[alerter] fallback persist error: %v", err)
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
	rows, err := a.pool.Query(loadCtx, `
		SELECT data FROM runtime_policies
		WHERE alert_only = TRUE
		  AND enabled    = TRUE
		  AND (det_type IS NULL OR det_type IN ('', 'Runtime', 'Syscall', 'Binary', 'LSM', 'Tracepoint'))`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var fresh []matcher.Rule
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		var r matcher.Rule
		if err := json.Unmarshal(raw, &r); err != nil {
			continue
		}
		fresh = append(fresh, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	prevCount := len(a.rules)
	a.rules = fresh
	a.mu.Unlock()
	if prevCount != len(fresh) {
		log.Printf("[alerter] rule set changed: %d → %d alertOnly rule(s)", prevCount, len(fresh))
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
