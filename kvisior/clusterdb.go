package main

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/clusterctx"
	"github.com/wolfee-watcher/kvisior/internal/store"
)

const (
	clusterDatabasesEnv          = "KVISIOR_CLUSTER_DATABASES"
	clusterDatabaseSyncInterval  = 15 * time.Second
	clusterDatabaseApplyDeadline = 10 * time.Second
)

type clusterDatabases struct {
	st      *store.Store
	router  *store.Router
	path    string
	loadErr string
	syncErr map[string]string
}

func startClusterDatabases(ctx context.Context, st *store.Store) func() {
	path := strings.TrimSpace(os.Getenv(clusterDatabasesEnv))
	if path == "" || st == nil {
		return func() {}
	}
	if clusterctx.Mode() != "hub" {
		slog.Warn("cluster_databases_ignored", "component", "kvisior/cluster-db",
			"reason", "only the hub routes clusters to their own databases", "mode", clusterctx.Mode())
		return func() {}
	}
	c := &clusterDatabases{st: st, router: store.NewRouter(), path: path, syncErr: map[string]string{}}
	st.SetRouter(c.router)
	c.reload(ctx)
	go c.run(ctx)
	return c.router.Close
}

func (c *clusterDatabases) run(ctx context.Context) {
	c.sync(ctx)
	t := time.NewTicker(clusterDatabaseSyncInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.reload(ctx)
			c.sync(ctx)
		}
	}
}

func (c *clusterDatabases) reload(ctx context.Context) {
	dsns, err := store.LoadClusterDatabases(c.path)
	if errors.Is(err, fs.ErrNotExist) {
		dsns, err = map[string]string{}, nil
	}
	if err != nil {
		if msg := err.Error(); msg != c.loadErr {
			c.loadErr = msg
			slog.Error("cluster_databases_unreadable", "component", "kvisior/cluster-db",
				"path", c.path, "error", err, "action", "keeping the current routes")
		}
		return
	}
	c.loadErr = ""
	actx, cancel := context.WithTimeout(ctx, clusterDatabaseApplyDeadline)
	added, removed, err := c.router.Apply(actx, dsns)
	cancel()
	for _, id := range added {
		slog.Info("cluster_database_routed", "component", "kvisior/cluster-db", "cluster", id)
	}
	for _, id := range removed {
		delete(c.syncErr, id)
		slog.Info("cluster_database_unrouted", "component", "kvisior/cluster-db", "cluster", id,
			"now", "hub database")
	}
	if err != nil {
		slog.Error("cluster_database_open_failed", "component", "kvisior/cluster-db", "error", err)
	}
}

func (c *clusterDatabases) sync(ctx context.Context) {
	for _, res := range c.st.SyncRoutedClusters(ctx) {
		msg := ""
		if res.Err != nil {
			msg = res.Err.Error()
		}
		if msg != c.syncErr[res.Cluster] {
			if msg == "" {
				slog.Info("cluster_database_reachable", "component", "kvisior/cluster-db", "cluster", res.Cluster)
			} else {
				slog.Error("cluster_database_sync_failed", "component", "kvisior/cluster-db",
					"cluster", res.Cluster, "error", res.Err)
			}
			c.syncErr[res.Cluster] = msg
		}
		if len(res.Copied) > 0 {
			slog.Info("cluster_database_config_replicated", "component", "kvisior/cluster-db",
				"cluster", res.Cluster, "tables", res.Copied)
		}
	}
}
