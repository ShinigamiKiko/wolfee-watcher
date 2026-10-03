package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/clusterctx"
	"github.com/wolfee-watcher/kvisior/internal/hub"
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

func (b bk) post(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.base+path, nil)
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
	return nil
}

type Aggregator struct {
	hub     *hub.Hub
	anomaly bk
	sensor  bk
	store   *store.Store

	anomalyCursor  string
	anomalyErrN    int
	pendingWatches map[string]struct{}
}

func New(
	h *hub.Hub,
	anomalyCl, sensorCl *http.Client,
	anomalyBase, sensorBase string,
	st *store.Store,
) *Aggregator {
	return &Aggregator{
		hub:            h,
		anomaly:        bk{anomalyCl, anomalyBase},
		sensor:         bk{sensorCl, sensorBase},
		store:          st,
		pendingWatches: make(map[string]struct{}),
	}
}

func (a *Aggregator) Run(ctx context.Context) {
	a.pollAnomaly(ctx)
	a.pollSensor(ctx)

	pollTick := time.NewTicker(5 * time.Second)
	sensorTick := time.NewTicker(60 * time.Second)
	defer pollTick.Stop()
	defer sensorTick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-pollTick.C:
			a.pollAnomaly(ctx)
		case <-sensorTick.C:
			a.pollSensor(ctx)
		}
	}
}

func logPollErr(tag string, n *int, err error) {
	*n++
	if *n == 1 || *n%10 == 0 {
		log.Printf("[collector/%s] %v (consecutive errors: %d)", tag, err, *n)
	}
}

func (a *Aggregator) pollAnomaly(ctx context.Context) {
	for key := range a.pendingWatches {
		parts := strings.SplitN(key, "/", 2)
		if len(parts) != 2 {
			delete(a.pendingWatches, key)
			continue
		}
		if a.startForensicWatch(ctx, parts[0], parts[1]) == nil {
			delete(a.pendingWatches, key)
		}
	}

	var resp struct {
		Events []json.RawMessage `json:"events"`
	}
	if err := a.anomaly.get(ctx, fmt.Sprintf("/api/anomalies?since=%s&limit=50", a.anomalyCursor), &resp); err != nil {
		logPollErr("anomaly", &a.anomalyErrN, err)
		return
	}
	a.anomalyErrN = 0
	for _, raw := range resp.Events {
		var ev struct {
			ID           string `json:"id"`
			Kind         string `json:"kind"`
			SrcNamespace string `json:"src_namespace"`
			SrcPod       string `json:"src_pod"`
		}
		if json.Unmarshal(raw, &ev) == nil && validWatchTarget(ev.Kind, ev.SrcNamespace, ev.SrcPod) {
			if err := a.startForensicWatch(ctx, ev.SrcNamespace, ev.SrcPod); err != nil {
				a.pendingWatches[ev.SrcNamespace+"/"+ev.SrcPod] = struct{}{}
			}
		}
		a.hub.Publish(hub.Event{Cluster: clusterctx.Local(), Type: "anomaly_event", Data: raw})
		if json.Unmarshal(raw, &ev) == nil && ev.ID != "" {
			a.anomalyCursor = ev.ID
		}
	}
}

func validWatchTarget(kind, ns, pod string) bool {
	return kind != "digest_change" && ns != "" && ns != "—" && pod != "" && !strings.Contains(pod, "/")
}

func (a *Aggregator) startForensicWatch(ctx context.Context, ns, pod string) error {
	watchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	path := "/api/forensic/watch/" + url.PathEscape(ns) + "/" + url.PathEscape(pod) + "?source=anomaly"
	if err := a.sensor.post(watchCtx, path); err != nil {
		log.Printf("[collector/anomaly] start forensic watch %s/%s: %v", ns, pod, err)
		return err
	}
	return nil
}

func (a *Aggregator) pollSensor(ctx context.Context) {
	var snapshot json.RawMessage
	if err := a.sensor.get(ctx, "/api/snapshot", &snapshot); err != nil {
		log.Printf("[collector/sensor] fetch failed: %v", err)
		return
	}
	a.hub.Publish(hub.Event{Cluster: clusterctx.Local(), Type: "sensor_snapshot", Data: snapshot})
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
