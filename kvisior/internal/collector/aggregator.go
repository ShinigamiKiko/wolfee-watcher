package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/hub"
	"github.com/wolfee-watcher/kvisior/internal/rules"
	"github.com/wolfee-watcher/kvisior/internal/store"
)

type bk struct {
	client *http.Client
	base   string
}

func (b bk) get(ctx context.Context, path string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.base+path, nil)
	if err != nil {
		return err
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type Aggregator struct {
	hub          *hub.Hub
	anomaly      bk
	sensor       bk
	auditMatcher *rules.AuditMatcher
	store        *store.Store

	anomalyCursor string
	anomalyErrN   int
}

func New(
	h *hub.Hub,
	anomalyCl, sensorCl *http.Client,
	anomalyBase, sensorBase string,
	auditMatcher *rules.AuditMatcher,
	st *store.Store,
) *Aggregator {
	return &Aggregator{
		hub:          h,
		anomaly:      bk{anomalyCl, anomalyBase},
		sensor:       bk{sensorCl, sensorBase},
		auditMatcher: auditMatcher,
		store:        st,
	}
}

func (a *Aggregator) Run(ctx context.Context) {
	a.refreshAuditRules(ctx)
	a.pollAnomaly(ctx)
	a.pollSensor(ctx)

	pollTick := time.NewTicker(5 * time.Second)
	sensorTick := time.NewTicker(60 * time.Second)
	rulesTick := time.NewTicker(30 * time.Second)
	defer pollTick.Stop()
	defer sensorTick.Stop()
	defer rulesTick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-pollTick.C:
			a.pollAnomaly(ctx)
		case <-sensorTick.C:
			a.pollSensor(ctx)
		case <-rulesTick.C:
			a.refreshAuditRules(ctx)
		}
	}
}

func (a *Aggregator) refreshAuditRules(ctx context.Context) {
	if a.store == nil {
		return
	}
	rCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := a.store.LoadRules(rCtx)
	if err != nil {
		log.Printf("[collector/rules] load from PG: %v", err)
		return
	}

	var auditRules []rules.AuditRule
	var skipped, otherDet int

	for _, r := range rows {
		var base struct {
			DetType string `json:"detType"`
		}
		if json.Unmarshal(r.Data, &base) != nil {
			skipped++
			continue
		}
		if base.DetType == "Audit" {
			var ar rules.AuditRule
			if json.Unmarshal(r.Data, &ar) == nil {
				auditRules = append(auditRules, ar)
			} else {
				skipped++
			}
		} else {
			otherDet++
		}
	}

	a.auditMatcher.Replace(auditRules)
	log.Printf("[collector/rules] audit rules refreshed: audit=%d skipped=%d other=%d (total=%d)",
		len(auditRules), skipped, otherDet, len(rows))
}

func logPollErr(tag string, n *int, err error) {
	*n++
	if *n == 1 || *n%10 == 0 {
		log.Printf("[collector/%s] %v (consecutive errors: %d)", tag, err, *n)
	}
}

func (a *Aggregator) pollAnomaly(ctx context.Context) {
	var resp struct {
		Events []json.RawMessage `json:"events"`
	}
	if err := a.anomaly.get(ctx, fmt.Sprintf("/api/anomalies?since=%s&limit=50", a.anomalyCursor), &resp); err != nil {
		logPollErr("anomaly", &a.anomalyErrN, err)
		return
	}
	a.anomalyErrN = 0
	for _, raw := range resp.Events {
		a.hub.Publish(hub.Event{Type: "anomaly_event", Data: raw})
		var ev struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(raw, &ev) == nil && ev.ID != "" {
			a.anomalyCursor = ev.ID
		}
	}
}

func (a *Aggregator) pollSensor(ctx context.Context) {
	var snapshot json.RawMessage
	if err := a.sensor.get(ctx, "/api/snapshot", &snapshot); err != nil {
		log.Printf("[collector/sensor] fetch failed: %v", err)
		return
	}
	a.hub.Publish(hub.Event{Type: "sensor_snapshot", Data: snapshot})
	log.Printf("[collector/sensor] snapshot published: %d bytes, %s", len(snapshot), summarizeSnapshot(snapshot))
}

func summarizeSnapshot(raw json.RawMessage) string {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return "unparseable"
	}
	if len(top) == 0 {
		return "empty object"
	}
	var parts []string
	for _, k := range []string{"pods", "namespaces", "workloads", "nodes", "services", "edges"} {
		if v, ok := top[k]; ok {
			var arr []json.RawMessage
			if json.Unmarshal(v, &arr) == nil {
				parts = append(parts, fmt.Sprintf("%s=%d", k, len(arr)))
			}
		}
	}
	if len(parts) == 0 {
		keys := make([]string, 0, len(top))
		for k := range top {
			keys = append(keys, k)
		}
		return "keys=" + strings.Join(keys, ",")
	}
	return strings.Join(parts, " ")
}
