package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/wolfee-watcher/kvisior/internal/clusterctx"
	"github.com/wolfee-watcher/kvisior/internal/store"
	"github.com/wolfee-watcher/pkg/auditrules"
)

const maxAuditLogNodes = 64

var auditLogNodeRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

func validAuditLogPath(p string) error { return store.ValidAuditLogPath(p) }

type auditLogSourceView struct {
	Managed                   bool                     `json:"managed"`
	Settings                  store.AuditLogSettings   `json:"settings"`
	Plan                      store.AuditLogPlan       `json:"plan"`
	Nodes                     []store.AuditLogNode     `json:"nodes"`
	Queues                    []store.AuditSpoolStatus `json:"queues"`
	TrustedProxies            string                   `json:"trustedProxies"`
	ForwardedHeadersSanitized bool                     `json:"forwardedHeadersSanitized"`
}

func loadAuditLogSource(r *http.Request, scope *store.Scoped) (auditLogSourceView, error) {
	settings, managed, err := scope.AuditLogSettings(r.Context())
	if err != nil {
		return auditLogSourceView{}, err
	}
	nodes, err := scope.ListAuditLogNodes(r.Context())
	if err != nil {
		return auditLogSourceView{}, err
	}
	proxies, err := scope.AuditTrustedProxies(r.Context())
	if err != nil {
		return auditLogSourceView{}, err
	}
	queues, err := scope.ListAuditSpools(r.Context())
	if err != nil {
		return auditLogSourceView{}, err
	}
	return auditLogSourceView{
		Managed: managed, Settings: settings, Nodes: nodes, Queues: queues, TrustedProxies: proxies.Proxies,
		ForwardedHeadersSanitized: proxies.HeadersSanitized,
		Plan:                      store.PlanAuditLog(settings, managed, nodes),
	}, nil
}

func auditTrustedProxiesHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var body struct {
			Proxies                   string `json:"proxies"`
			ForwardedHeadersSanitized bool   `json:"forwardedHeadersSanitized"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&body) != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid json")
			return
		}
		networks, err := auditrules.ParseProxies(strings.ReplaceAll(body.Proxies, "\n", ","))
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		items := make([]string, 0, len(networks))
		for _, network := range networks {
			if ones, bits := network.Mask.Size(); ones == bits {
				items = append(items, network.IP.String())
			} else {
				items = append(items, network.String())
			}
		}
		scope := st.Cluster(clusterctx.ForRead(r))
		settings := store.AuditProxySettings{
			Proxies: strings.Join(items, ", "), HeadersSanitized: body.ForwardedHeadersSanitized,
		}
		if err := scope.SaveAuditTrustedProxies(r.Context(), settings, r.Header.Get("X-Acting-User")); err != nil {
			slog.Error("audit_trusted_proxies_save_failed", "component", "kvisior/audit-api", "error", err)
			writeAPIError(w, http.StatusInternalServerError, "write failed")
			return
		}
		view, err := loadAuditLogSource(r, scope)
		if err != nil {
			slog.Error("audit_log_source_query_failed", "component", "kvisior/audit-api", "error", err)
			writeAPIError(w, http.StatusInternalServerError, "query failed")
			return
		}
		writeJSON(w, http.StatusOK, view)
	}
}

func auditLogSourceHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope := st.Cluster(clusterctx.ForRead(r))
		switch r.Method {
		case http.MethodGet:
		case http.MethodPut:
			var body struct {
				Enabled   bool              `json:"enabled"`
				Path      string            `json:"path"`
				NodePaths map[string]string `json:"nodePaths"`
			}
			if json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body) != nil {
				writeAPIError(w, http.StatusBadRequest, "invalid json")
				return
			}
			next := store.AuditLogSettings{
				Enabled: body.Enabled, Path: strings.TrimSpace(body.Path),
				NodePaths: map[string]string{}, UpdatedBy: r.Header.Get("X-Acting-User"),
			}
			if next.Path != "" {
				if err := validAuditLogPath(next.Path); err != nil {
					writeAPIError(w, http.StatusBadRequest, err.Error())
					return
				}
			}
			if len(body.NodePaths) > maxAuditLogNodes {
				writeAPIError(w, http.StatusBadRequest, "too many per-node paths")
				return
			}
			for node, p := range body.NodePaths {
				node, p = strings.TrimSpace(node), strings.TrimSpace(p)
				if p == "" {
					continue
				}
				if !auditLogNodeRe.MatchString(node) {
					writeAPIError(w, http.StatusBadRequest, fmt.Sprintf("invalid node name %q", node))
					return
				}
				if err := validAuditLogPath(p); err != nil {
					writeAPIError(w, http.StatusBadRequest, fmt.Sprintf("node %s: %v", node, err))
					return
				}
				next.NodePaths[node] = p
			}
			if err := scope.SaveAuditLogSettings(r.Context(), next); err != nil {
				slog.Error("audit_log_settings_save_failed", "component", "kvisior/audit-api", "error", err)
				writeAPIError(w, http.StatusInternalServerError, "write failed")
				return
			}
		default:
			writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		view, err := loadAuditLogSource(r, scope)
		if err != nil {
			slog.Error("audit_log_source_query_failed", "component", "kvisior/audit-api", "error", err)
			writeAPIError(w, http.StatusInternalServerError, "query failed")
			return
		}
		writeJSON(w, http.StatusOK, view)
	}
}

func auditLogConfigPull(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if st == nil {
			writeAPIError(w, http.StatusServiceUnavailable, "postgresql not configured")
			return
		}
		view, err := loadAuditLogSource(r, st.Cluster(clusterctx.ForPush(r)))
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "query failed")
			return
		}
		writeJSON(w, http.StatusOK, view.Plan)
	}
}

func auditLogNodesPush(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if st == nil {
			writeAPIError(w, http.StatusServiceUnavailable, "postgresql not configured")
			return
		}
		var body struct {
			Nodes      []store.AuditLogNode `json:"nodes"`
			Rev        string               `json:"rev"`
			ApplyError string               `json:"applyError"`
			Applied    bool                 `json:"applied"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body) != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid json")
			return
		}
		cluster := clusterctx.ForPush(r)
		st.EnsureClusterCached(cluster)
		scope := st.Cluster(cluster)
		nodes := make([]store.AuditLogNode, 0, len(body.Nodes))
		for _, n := range body.Nodes {
			if !auditLogNodeRe.MatchString(n.Node) || len(nodes) >= maxAuditLogNodes {
				continue
			}
			if n.DetectedPath != "" && validAuditLogPath(n.DetectedPath) != nil {
				n.DetectedPath = ""
			}
			nodes = append(nodes, n)
		}
		if err := scope.ReplaceDetectedAuditLogNodes(r.Context(), nodes); err != nil {
			slog.Error("audit_log_nodes_write_failed", "component", "kvisior/audit-api", "error", err)
			writeAPIError(w, http.StatusInternalServerError, "write failed")
			return
		}
		if body.Applied || body.ApplyError != "" {
			if err := scope.MarkAuditLogApplied(r.Context(), body.Rev, body.ApplyError); err != nil {
				writeAPIError(w, http.StatusInternalServerError, "write failed")
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func auditLogStatusPush(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if st == nil {
			writeAPIError(w, http.StatusServiceUnavailable, "postgresql not configured")
			return
		}
		var body struct {
			Node         string     `json:"node"`
			Path         string     `json:"path"`
			State        string     `json:"state"`
			Error        string     `json:"error"`
			LastRecordAt *time.Time `json:"lastRecordAt"`
			Lines        int64      `json:"lines"`
			Sent         int64      `json:"sent"`
			Rejected     int64      `json:"rejected"`
			BacklogBytes int64      `json:"backlogBytes"`
			BacklogFiles int        `json:"backlogFiles"`
			LagSeconds   int64      `json:"lagSeconds"`
			Headroom     *int       `json:"headroom"`
			ProbeDone    string     `json:"probeDone"`
			ProbeOK      bool       `json:"probeOk"`
			ProbeDetail  string     `json:"probeDetail"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&body) != nil || !auditLogNodeRe.MatchString(body.Node) {
			writeAPIError(w, http.StatusBadRequest, "invalid status")
			return
		}
		body.Error, body.ProbeDetail = clip(body.Error, 300), clip(body.ProbeDetail, 300)
		body.Path, body.State = clip(body.Path, 512), clip(body.State, 32)
		cluster := clusterctx.ForPush(r)
		st.EnsureClusterCached(cluster)
		probe, err := st.Cluster(cluster).UpsertAuditLogTail(r.Context(), store.AuditLogNode{
			Node: body.Node, TailPath: body.Path, TailState: body.State, TailError: body.Error,
			LastRecordAt: body.LastRecordAt, Lines: body.Lines, Sent: body.Sent, Rejected: body.Rejected,
			BacklogBytes: max(body.BacklogBytes, 0), BacklogFiles: max(body.BacklogFiles, 0),
			LagSeconds: max(body.LagSeconds, 0), Headroom: body.Headroom,
			ProbeDone: clip(body.ProbeDone, 64), ProbeOK: body.ProbeOK, ProbeDetail: body.ProbeDetail,
		})
		if err != nil {
			slog.Error("audit_log_status_write_failed", "component", "kvisior/audit-api", "error", err)
			writeAPIError(w, http.StatusInternalServerError, "write failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"probe": probe})
	}
}

func clip(s string, n int) string {
	s = strings.ToValidUTF8(strings.ReplaceAll(s, "\x00", "�"), "�")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func auditLogTestHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var body struct {
			Node string `json:"node"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&body) != nil || !auditLogNodeRe.MatchString(body.Node) {
			writeAPIError(w, http.StatusBadRequest, "invalid node")
			return
		}
		id := newAuditRuleID()
		err := st.Cluster(clusterctx.ForRead(r)).RequestAuditLogProbe(r.Context(), body.Node, id)
		if errors.Is(err, store.ErrAuditLogReaderOffline) {
			writeAPIError(w, http.StatusConflict, "the reader is not running on this node; turn reading on and save first")
			return
		}
		if err != nil {
			slog.Error("audit_log_probe_request_failed", "component", "kvisior/audit-api", "error", err)
			writeAPIError(w, http.StatusInternalServerError, "write failed")
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"probeId": id})
	}
}
