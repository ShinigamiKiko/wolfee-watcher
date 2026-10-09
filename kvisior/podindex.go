package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/clusterctx"
	"github.com/wolfee-watcher/kvisior/internal/hub"
	"github.com/wolfee-watcher/kvisior/internal/podindex"
)

const (
	podIndexKeep  = 30 * time.Minute
	podIndexEvery = 15 * time.Second
)

func runPodIndex(ctx context.Context, h *hub.Hub, idx *podindex.Index) {
	t := time.NewTicker(podIndexEvery)
	defer t.Stop()
	for {
		for _, ev := range h.Latest("sensor_snapshot") {
			cluster := ev.Cluster
			if cluster == "" {
				cluster = clusterctx.Local()
			}
			if err := idx.Update(cluster, ev.Data, time.Now()); err != nil {
				slog.Warn("pod_index_update_failed", "component", "kvisior/podindex", "cluster", cluster, "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
