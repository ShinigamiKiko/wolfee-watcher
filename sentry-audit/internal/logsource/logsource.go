package logsource

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	DaemonSetName = "sentry-audit-logtail"
	ContainerName = "logtail"

	OffLabel      = "wolfee-watcher.io/audit-log-off"
	RevAnnotation = "wolfee-watcher.io/audit-log-rev"
	EnvPath       = "AUDIT_LOG_PATH"
	EnvNodePaths  = "AUDIT_LOG_NODE_PATHS"

	volumePrefix  = "audit-log"
	apiServerNS   = "kube-system"
	auditPathFlag = "--audit-log-path"
	interval      = 30 * time.Second
)

var controlPlaneLabels = []string{
	"node-role.kubernetes.io/control-plane",
	"node-role.kubernetes.io/master",
}

type Node struct {
	Node         string `json:"node"`
	APIServer    bool   `json:"apiServer"`
	AuditEnabled bool   `json:"auditEnabled"`
	DetectedPath string `json:"detectedPath"`
}

type Plan struct {
	Managed   bool              `json:"managed"`
	Enabled   bool              `json:"enabled"`
	Path      string            `json:"path"`
	NodePaths map[string]string `json:"nodePaths"`
	Rev       string            `json:"rev"`
}

type Caller interface {
	Call(ctx context.Context, method, path string, in, out any) error
}

func flagValue(args []string, flag string) (string, bool) {
	for i, arg := range args {
		if v, ok := strings.CutPrefix(arg, flag+"="); ok {
			return v, true
		}
		if arg == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

func hostPathFor(pod *corev1.Pod, c *corev1.Container, inside string) string {
	best, host := "", ""
	for _, m := range c.VolumeMounts {
		mount := path.Clean(m.MountPath)
		if inside != mount && !strings.HasPrefix(inside, strings.TrimSuffix(mount, "/")+"/") {
			continue
		}
		if len(mount) <= len(best) {
			continue
		}
		for _, v := range pod.Spec.Volumes {
			if v.Name == m.Name && v.HostPath != nil {
				best = mount
				host = path.Join(v.HostPath.Path, m.SubPath, strings.TrimPrefix(inside, mount))
			}
		}
	}
	return host
}

func apiServerAudit(pod *corev1.Pod) (bool, string) {
	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		args := append(append([]string{}, c.Command...), c.Args...)
		value, ok := flagValue(args, auditPathFlag)
		if !ok {
			continue
		}
		if value == "" || value == "-" || !path.IsAbs(value) {
			return true, ""
		}
		return true, hostPathFor(pod, c, path.Clean(value))
	}
	return false, ""
}

func Detect(ctx context.Context, client kubernetes.Interface) ([]Node, error) {
	byNode := map[string]*Node{}
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	for _, n := range nodes.Items {
		for _, label := range controlPlaneLabels {
			if _, ok := n.Labels[label]; ok {
				byNode[n.Name] = &Node{Node: n.Name}
			}
		}
	}
	pods, err := client.CoreV1().Pods(apiServerNS).List(ctx, metav1.ListOptions{LabelSelector: "component=kube-apiserver"})
	if err != nil {
		return nil, fmt.Errorf("list kube-apiserver pods: %w", err)
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Spec.NodeName == "" {
			continue
		}
		n := byNode[pod.Spec.NodeName]
		if n == nil {
			n = &Node{Node: pod.Spec.NodeName}
			byNode[pod.Spec.NodeName] = n
		}
		n.APIServer = true
		n.AuditEnabled, n.DetectedPath = apiServerAudit(pod)
	}
	out := make([]Node, 0, len(byNode))
	for _, n := range byNode {
		out = append(out, *n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out, nil
}

func planDirs(plan Plan) []string {
	seen := map[string]bool{}
	var dirs []string
	add := func(p string) {
		if p == "" {
			return
		}
		if d := path.Dir(p); !seen[d] {
			seen[d] = true
			dirs = append(dirs, d)
		}
	}
	add(plan.Path)
	for _, p := range plan.NodePaths {
		add(p)
	}
	sort.Strings(dirs)
	return dirs
}

func nodePathsEnv(plan Plan) string {
	names := make([]string, 0, len(plan.NodePaths))
	for node := range plan.NodePaths {
		names = append(names, node)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, node := range names {
		parts = append(parts, node+"="+plan.NodePaths[node])
	}
	return strings.Join(parts, ",")
}

func setEnv(c *corev1.Container, name, value string) {
	for i := range c.Env {
		if c.Env[i].Name == name {
			c.Env[i].Value, c.Env[i].ValueFrom = value, nil
			return
		}
	}
	c.Env = append(c.Env, corev1.EnvVar{Name: name, Value: value})
}

func Apply(ctx context.Context, client kubernetes.Interface, namespace string, plan Plan) (bool, error) {
	if !plan.Managed {
		return false, nil
	}
	api := client.AppsV1().DaemonSets(namespace)
	ds, err := api.Get(ctx, DaemonSetName, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("get daemonset %s: %w", DaemonSetName, err)
	}
	tpl := &ds.Spec.Template
	if tpl.Annotations[RevAnnotation] == plan.Rev {
		return false, nil
	}
	var container *corev1.Container
	for i := range tpl.Spec.Containers {
		if tpl.Spec.Containers[i].Name == ContainerName {
			container = &tpl.Spec.Containers[i]
		}
	}
	if container == nil {
		return false, fmt.Errorf("daemonset %s has no container %q", DaemonSetName, ContainerName)
	}
	dirs := planDirs(plan)

	volumes := tpl.Spec.Volumes[:0:0]
	for _, v := range tpl.Spec.Volumes {
		if !strings.HasPrefix(v.Name, volumePrefix) {
			volumes = append(volumes, v)
		}
	}
	mounts := container.VolumeMounts[:0:0]
	for _, m := range container.VolumeMounts {
		if !strings.HasPrefix(m.Name, volumePrefix) {
			mounts = append(mounts, m)
		}
	}
	hostType := corev1.HostPathDirectoryOrCreate
	for i, dir := range dirs {
		name := fmt.Sprintf("%s-%d", volumePrefix, i)
		volumes = append(volumes, corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{Path: dir, Type: &hostType},
		}})
		mounts = append(mounts, corev1.VolumeMount{Name: name, MountPath: dir, ReadOnly: true})
	}
	tpl.Spec.Volumes, container.VolumeMounts = volumes, mounts
	setEnv(container, EnvPath, plan.Path)
	setEnv(container, EnvNodePaths, nodePathsEnv(plan))

	if plan.Enabled && len(dirs) > 0 {
		delete(tpl.Spec.NodeSelector, OffLabel)
	} else {
		if tpl.Spec.NodeSelector == nil {
			tpl.Spec.NodeSelector = map[string]string{}
		}
		tpl.Spec.NodeSelector[OffLabel] = "true"
	}
	if tpl.Annotations == nil {
		tpl.Annotations = map[string]string{}
	}
	tpl.Annotations[RevAnnotation] = plan.Rev
	if _, err := api.Update(ctx, ds, metav1.UpdateOptions{}); err != nil {
		return false, fmt.Errorf("update daemonset %s: %w", DaemonSetName, err)
	}
	return true, nil
}

func reconcile(ctx context.Context, client kubernetes.Interface, namespace string, kv Caller) error {
	var plan Plan
	if err := kv.Call(ctx, http.MethodGet, "/internal/pull/audit-log-config", nil, &plan); err != nil {
		return fmt.Errorf("pull audit log config: %w", err)
	}
	report := struct {
		Nodes      []Node `json:"nodes"`
		Rev        string `json:"rev"`
		Applied    bool   `json:"applied"`
		ApplyError string `json:"applyError"`
	}{Rev: plan.Rev}
	nodes, err := Detect(ctx, client)
	if err != nil {
		return err
	}
	report.Nodes = nodes
	changed, applyErr := Apply(ctx, client, namespace, plan)
	switch {
	case applyErr != nil:
		report.ApplyError = applyErr.Error()
	case plan.Managed:
		report.Applied = true
	}
	if changed {
		slog.Info("audit_log_reader_updated",
			"component", "sentry-audit/logsource",
			"enabled", plan.Enabled, "path", plan.Path, "node_paths", len(plan.NodePaths), "rev", plan.Rev)
	}
	if err := kv.Call(ctx, http.MethodPost, "/internal/push/audit-log-nodes", report, nil); err != nil {
		return fmt.Errorf("report audit log nodes: %w", err)
	}
	return applyErr
}

func Run(ctx context.Context, client kubernetes.Interface, namespace string, kv Caller) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	last := ""
	for {
		err := reconcile(ctx, client, namespace, kv)
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		if msg != last && ctx.Err() == nil {
			if err != nil {
				slog.Warn("audit_log_reconcile_failed", "component", "sentry-audit/logsource", "error", err)
			} else {
				slog.Info("audit_log_reconcile_ok", "component", "sentry-audit/logsource")
			}
			last = msg
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
