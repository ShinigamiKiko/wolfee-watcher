package alerter

import (
	"context"
	"encoding/json"
	"log"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	alertspkg "github.com/wolfee-watcher/pkg/alerts"
	"github.com/wolfee-watcher/tracee-bridge/internal/mapper"
	"github.com/wolfee-watcher/tracee-bridge/internal/matcher"
)

const ruleRefreshInterval = 30 * time.Second

const ruleStaleWarnAfter = 5 * time.Minute

const dedupTTL = 10 * time.Minute

const dedupMaxEntries = 20_000

const sourceTag = "tracee-bridge"

type Alerter struct {
	pool *pgxpool.Pool
	fwd  *alertspkg.Forwarder

	mu    sync.RWMutex
	rules []matcher.Rule

	syscallMu      sync.RWMutex
	policySyscalls map[string]bool
	policyPassAll  bool

	lastRefreshOK atomic.Int64

	dedupMu sync.Mutex
	dedup   map[string]time.Time
}

func New(ctx context.Context, pool *pgxpool.Pool) *Alerter {
	a := &Alerter{
		pool:           pool,
		fwd:            alertspkg.NewForwarder(),
		dedup:          make(map[string]time.Time),
		policySyscalls: make(map[string]bool),
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

func (a *Alerter) Close() {
	if a == nil {
		return
	}
	a.fwd.Close()
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
		name := alertName(r)
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
			Timestamp:   ev.Ts,
			DetType:     detType,
			Source:      sourceTag,
			RuleID:      r.ID,
			RuleName:    name,
			Severity:    alertSeverity(r, ev),
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

func alertName(r matcher.Rule) string {
	if name := strings.TrimSpace(r.Name); name != "" {
		return name
	}
	if r.DetType == "Binary" && r.ProcessFilter != "" {
		return "Binary: " + r.ProcessFilter
	}
	if r.Syscall != "" && r.Syscall != "*" {
		prefix := "Syscall"
		switch r.DetType {
		case "LSM", "Tracepoint":
			prefix = r.DetType
		}
		return prefix + ": " + r.Syscall
	}
	return r.ID
}

func alertSeverity(r matcher.Rule, ev *mapper.UIEvent) string {
	if severity := strings.TrimSpace(r.Sev); severity != "" {
		return strings.ToUpper(severity)
	}
	if ev == nil {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(ev.Severity))
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
		  (ts, source, det_type, rule_id, rule_name, severity, namespace, target, syscall, detail, fingerprint, data)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		alertTimestamp(al.Timestamp), al.Source, al.DetType, al.RuleID, al.RuleName, al.Severity, al.Namespace,
		al.Target, al.Syscall, al.Detail, al.Fingerprint, al.Data,
	)
	if err != nil {
		log.Printf("[alerter] fallback persist error: %v", err)
	}
}

func alertTimestamp(ts time.Time) time.Time {
	if ts.IsZero() {
		return time.Now()
	}
	return ts
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
				a.reportStaleRules(err)
			}
		}
	}
}

func (a *Alerter) reportStaleRules(err error) {
	stale := a.StaleFor()
	if stale < ruleStaleWarnAfter {
		log.Printf("[alerter] rule refresh failed: %v", err)
		return
	}
	slog.Error("policy_snapshot_stale",
		"component", "tracee-bridge/alerter",
		"stale_for", stale.Truncate(time.Second).String(),
		"rules", a.RuleCount(),
		"error", err,
		"impact", "disabled_or_deleted_policies_still_alerting")
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

	syscalls, passAll, err := a.loadPolicySyscalls(ctx)
	if err != nil {
		return err
	}

	a.mu.Lock()
	prevCount := len(a.rules)
	a.rules = fresh
	a.mu.Unlock()

	a.syscallMu.Lock()
	prevSyscalls := len(a.policySyscalls)
	a.policySyscalls = syscalls
	a.policyPassAll = passAll
	a.syscallMu.Unlock()

	a.lastRefreshOK.Store(time.Now().UnixNano())
	if prevCount != len(fresh) {
		log.Printf("[alerter] rule set changed: %d → %d alertOnly rule(s)", prevCount, len(fresh))
	}
	if prevSyscalls != len(syscalls) {
		log.Printf("[alerter] policy syscall set changed: %d → %d syscall(s), pass_all=%v",
			prevSyscalls, len(syscalls), passAll)
	}
	return nil
}

func (a *Alerter) loadPolicySyscalls(ctx context.Context) (map[string]bool, bool, error) {
	loadCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := a.pool.Query(loadCtx, `
		SELECT DISTINCT COALESCE(data->>'syscall', '') FROM runtime_policies
		WHERE enabled = TRUE
		  AND (det_type IS NULL OR det_type IN ('', 'Runtime', 'Syscall', 'Binary', 'LSM', 'Tracepoint'))`)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	syscalls := make(map[string]bool)
	passAll := false
	for rows.Next() {
		var sc string
		if err := rows.Scan(&sc); err != nil {
			continue
		}
		sc = strings.TrimSpace(sc)
		switch sc {
		case "":
			continue
		case "*":
			passAll = true
		default:
			syscalls[sc] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	return syscalls, passAll, nil
}

func (a *Alerter) WantsSyscall(syscall string) bool {
	if a == nil {
		return false
	}
	a.syscallMu.RLock()
	defer a.syscallMu.RUnlock()
	return a.policyPassAll || a.policySyscalls[syscall]
}

func (a *Alerter) QueueStats() (buffered, capacity int, dropped, lost int64) {
	if a == nil {
		return 0, 0, 0, 0
	}
	return a.fwd.QueueStats()
}

func (a *Alerter) StaleFor() time.Duration {
	if a == nil {
		return 0
	}
	last := a.lastRefreshOK.Load()
	if last == 0 {
		return 0
	}
	return time.Since(time.Unix(0, last))
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
