package posture

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

const maxPatternLength = 256

var systemNamespaces = map[string]bool{
	"kube-system": true, "kube-public": true, "kube-node-lease": true, "calico-system": true,
	"calico-apiserver": true, "cilium": true, "cert-manager": true,
}

type Policy struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Sev               string   `json:"sev"`
	Action            string   `json:"action"`
	Namespace         string   `json:"namespace"`
	DetType           string   `json:"detType"`
	Enabled           *bool    `json:"enabled"`
	TrustedRegistries string   `json:"trustedRegistries"`
	BuildInstruction  string   `json:"buildInstruction"`
	DeployChecks      []string `json:"deployChecks"`
}

func (p Policy) active() bool { return p.Enabled == nil || *p.Enabled }

func (p Policy) sevOr(def string) string {
	if p.Sev != "" {
		return p.Sev
	}
	return def
}

type Finding struct {
	VType       string `json:"-"`
	Fingerprint string `json:"_fp"`
	PolicyID    string `json:"_policyId"`
	Policy      string `json:"policy"`
	Sev         string `json:"sev"`
	Action      string `json:"action,omitempty"`
	Detail      string `json:"detail"`

	Image       string `json:"image,omitempty"`
	Instruction string `json:"instruction,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	BuildCheck  string `json:"_check,omitempty"`
	Pending     bool   `json:"_pending,omitempty"`

	Workload string `json:"workload,omitempty"`
	Kind     string `json:"kind,omitempty"`
	NS       string `json:"ns,omitempty"`
	Check    string `json:"check,omitempty"`
}

func (f Finding) Subject() string {
	if f.VType == "build" {
		return f.Image
	}
	return f.Workload
}

func (f Finding) Scope() string {
	if f.VType == "build" {
		return f.Namespace
	}
	return f.NS
}

type meta struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Annotations map[string]string `json:"annotations"`
}

type capabilities struct {
	Drop []string `json:"drop"`
}

type seccomp struct {
	Type string `json:"type"`
}

type securityContext struct {
	Privileged               *bool         `json:"privileged"`
	AllowPrivilegeEscalation *bool         `json:"allowPrivilegeEscalation"`
	RunAsUser                *int64        `json:"runAsUser"`
	RunAsNonRoot             *bool         `json:"runAsNonRoot"`
	ReadOnlyRootFilesystem   *bool         `json:"readOnlyRootFilesystem"`
	Capabilities             *capabilities `json:"capabilities"`
	SeccompProfile           *seccomp      `json:"seccompProfile"`
}

type podSecurityContext struct {
	SupplementalGroups []int64  `json:"supplementalGroups"`
	FSGroup            *int64   `json:"fsGroup"`
	SeccompProfile     *seccomp `json:"seccompProfile"`
}

type nameRef struct {
	Name string `json:"name"`
}

type container struct {
	Name            string           `json:"name"`
	Image           string           `json:"image"`
	SecurityContext *securityContext `json:"securityContext"`
	Ports           []struct {
		ContainerPort int32 `json:"containerPort"`
		HostPort      int32 `json:"hostPort"`
	} `json:"ports"`
	VolumeMounts []struct {
		Name     string `json:"name"`
		ReadOnly bool   `json:"readOnly"`
	} `json:"volumeMounts"`
	Resources struct {
		Limits   map[string]any `json:"limits"`
		Requests map[string]any `json:"requests"`
	} `json:"resources"`
	Env []struct {
		ValueFrom *struct {
			SecretKeyRef *nameRef `json:"secretKeyRef"`
		} `json:"valueFrom"`
	} `json:"env"`
	EnvFrom []struct {
		SecretRef *nameRef `json:"secretRef"`
	} `json:"envFrom"`
}

type podSpec struct {
	Containers                   []container         `json:"containers"`
	InitContainers               []container         `json:"initContainers"`
	HostPID                      bool                `json:"hostPID"`
	HostIPC                      bool                `json:"hostIPC"`
	HostNetwork                  bool                `json:"hostNetwork"`
	SecurityContext              *podSecurityContext `json:"securityContext"`
	ServiceAccountName           string              `json:"serviceAccountName"`
	AutomountServiceAccountToken *bool               `json:"automountServiceAccountToken"`
	Volumes                      []struct {
		Name     string `json:"name"`
		HostPath *struct {
			Path string `json:"path"`
		} `json:"hostPath"`
	} `json:"volumes"`
}

type workload struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Template struct {
			Spec podSpec `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
	kind string
}

type pod struct {
	Metadata meta    `json:"metadata"`
	Spec     podSpec `json:"spec"`
}

type ingressRule struct {
	From []json.RawMessage `json:"from"`
}

type egressRule struct {
	To []json.RawMessage `json:"to"`
}

type networkPolicy struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Ingress []ingressRule `json:"ingress"`
		Egress  []egressRule  `json:"egress"`
	} `json:"spec"`
}

type service struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Type string `json:"type"`
	} `json:"spec"`
}

type Snapshot struct {
	Deployments     []workload      `json:"deployments"`
	StatefulSets    []workload      `json:"stateful_sets"`
	DaemonSets      []workload      `json:"daemon_sets"`
	Pods            []pod           `json:"pods"`
	NetworkPolicies []networkPolicy `json:"network_policies"`
	Namespaces      []struct {
		Metadata meta `json:"metadata"`
	} `json:"namespaces"`
	Services []service `json:"services"`
}

func ParseSnapshot(raw []byte) (*Snapshot, error) {
	var s Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *Snapshot) workloads() []workload {
	out := make([]workload, 0, len(s.Deployments)+len(s.StatefulSets)+len(s.DaemonSets))
	for _, set := range []struct {
		items []workload
		kind  string
	}{{s.Deployments, "Deployment"}, {s.StatefulSets, "StatefulSet"}, {s.DaemonSets, "DaemonSet"}} {
		for _, w := range set.items {
			w.kind = set.kind
			out = append(out, w)
		}
	}
	return out
}

type Layer struct {
	CreatedBy string `json:"created_by"`
}

type History struct {
	Image  string  `json:"image"`
	Status string  `json:"status"`
	Error  string  `json:"error"`
	Layers []Layer `json:"layers"`
}

type Evaluator struct {
	Cluster string
	Now     time.Time
}

func (e Evaluator) day() string { return e.Now.UTC().Format("20060102") }

func (e Evaluator) build(f Finding) Finding {
	f.VType = "build"
	f.Fingerprint = fmt.Sprintf("bld::%s::%s::%s::%s::%s", e.Cluster, f.PolicyID, f.Image, f.BuildCheck, e.day())
	return f
}

func (e Evaluator) deploy(f Finding) Finding {
	f.VType = "deploy"
	f.Fingerprint = fmt.Sprintf("dep::%s::%s::%s::%s::%s::%s", e.Cluster, f.PolicyID, f.Workload, f.NS, f.Check, e.day())
	return f
}

type image struct {
	ref        string
	namespaces map[string]bool
}

func clusterImages(s *Snapshot, histories []History) []image {
	byRef := map[string]*image{}
	var order []string
	add := func(ref, ns string) {
		if ref == "" {
			return
		}
		img, ok := byRef[ref]
		if !ok {
			img = &image{ref: ref, namespaces: map[string]bool{}}
			byRef[ref] = img
			order = append(order, ref)
		}
		if ns != "" {
			img.namespaces[ns] = true
		}
	}
	if s != nil {
		for _, p := range s.Pods {
			for _, c := range append(slices.Clone(p.Spec.Containers), p.Spec.InitContainers...) {
				add(c.Image, p.Metadata.Namespace)
			}
		}
		if len(order) == 0 {
			for _, w := range s.workloads() {
				spec := w.Spec.Template.Spec
				for _, c := range append(slices.Clone(spec.Containers), spec.InitContainers...) {
					add(c.Image, w.Metadata.Namespace)
				}
			}
		}
	}
	if len(order) == 0 {
		for _, h := range histories {
			add(h.Image, "")
		}
	}
	out := make([]image, 0, len(order))
	for _, ref := range order {
		out = append(out, *byRef[ref])
	}
	return out
}

var (
	nopPrefix = regexp.MustCompile(`^/bin/sh -c #\(nop\)\s+`)
	runPrefix = regexp.MustCompile(`^/bin/sh -c\s+`)
)

func (e Evaluator) Build(policies []Policy, s *Snapshot, histories []History) []Finding {
	byRef := map[string]History{}
	for _, h := range histories {
		byRef[h.Image] = h
	}
	images := clusterImages(s, histories)
	var out []Finding
	for _, p := range policies {
		if !p.active() || p.DetType != "Build" {
			continue
		}
		nsFilter := strings.TrimSpace(p.Namespace)
		inScope := func(img image) bool {
			return nsFilter == "" || len(img.namespaces) == 0 || img.namespaces[nsFilter]
		}
		if trusted := splitList(p.TrustedRegistries); len(trusted) > 0 {
			for _, img := range images {
				if !inScope(img) {
					continue
				}
				ref := strings.ToLower(img.ref)
				if !slices.ContainsFunc(trusted, func(t string) bool { return strings.HasPrefix(ref, t) }) {
					out = append(out, e.build(Finding{
						PolicyID: p.ID, Policy: p.Name, Sev: p.sevOr("HIGH"), Action: p.Action, Image: img.ref,
						Detail:      "Image not from trusted registry. Trusted: " + strings.Join(trusted, ", "),
						Instruction: p.TrustedRegistries, Namespace: nsFilter, BuildCheck: "registry",
					}))
				}
			}
		}
		pattern := strings.TrimSpace(p.BuildInstruction)
		if pattern == "" || len(pattern) > maxPatternLength {
			continue
		}
		needle := strings.ToLower(pattern)
		for _, img := range images {
			if !inScope(img) || strings.HasPrefix(img.ref, "localhost/") || strings.HasPrefix(img.ref, "localhost:") {
				continue
			}
			h, ok := byRef[img.ref]
			if !ok || h.Status == "pending" || h.Status == "fetching" {
				continue
			}
			if h.Status == "unavailable" {
				reason := h.Error
				if reason == "" {
					reason = "registry unreachable"
				}
				out = append(out, e.build(Finding{
					PolicyID: p.ID, Policy: p.Name, Sev: p.sevOr("MEDIUM"), Action: "alert", Image: img.ref,
					Detail: "History unavailable: " + reason, Instruction: p.BuildInstruction, Namespace: nsFilter,
					BuildCheck: "history", Pending: true,
				}))
				continue
			}
			for _, l := range h.Layers {
				if !strings.Contains(strings.ToLower(l.CreatedBy), needle) {
					continue
				}
				shown := runPrefix.ReplaceAllString(nopPrefix.ReplaceAllString(l.CreatedBy, ""), "RUN ")
				out = append(out, e.build(Finding{
					PolicyID: p.ID, Policy: p.Name, Sev: p.sevOr("MEDIUM"), Action: p.Action, Image: img.ref,
					Detail: "Layer matches: " + strings.TrimSpace(shown), Instruction: p.BuildInstruction,
					Namespace: nsFilter, BuildCheck: "layer",
				}))
				break
			}
		}
	}
	return out
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.ToLower(strings.TrimSpace(part)); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func (e Evaluator) Deploy(policies []Policy, s *Snapshot) []Finding {
	if s == nil {
		return nil
	}
	workloads := s.workloads()
	var out []Finding
	for _, p := range policies {
		if !p.active() || p.DetType != "Deploy" {
			continue
		}
		nsFilter := strings.TrimSpace(p.Namespace)
		for _, w := range workloads {
			ns := w.Metadata.Namespace
			if nsFilter != "" && ns != nsFilter {
				continue
			}
			for _, check := range p.DeployChecks {
				detail, ok := checkWorkload(check, w)
				if !ok {
					continue
				}
				out = append(out, e.deploy(Finding{
					PolicyID: p.ID, Policy: p.Name, Sev: p.sevOr("HIGH"), Action: p.Action, Detail: detail,
					Workload: w.Metadata.Name, Kind: w.kind, NS: ns, Check: check,
				}))
			}
		}
		out = append(out, e.clusterChecks(p, s, nsFilter)...)
	}
	return out
}

func (e Evaluator) clusterChecks(p Policy, s *Snapshot, nsFilter string) []Finding {
	var out []Finding
	skip := func(ns string) bool { return systemNamespaces[ns] || (nsFilter != "" && ns != nsFilter) }
	emit := func(check, sevDef, name, kind, ns, detail string) {
		out = append(out, e.deploy(Finding{
			PolicyID: p.ID, Policy: p.Name, Sev: p.sevOr(sevDef), Action: p.Action, Detail: detail,
			Workload: name, Kind: kind, NS: ns, Check: check,
		}))
	}
	if slices.Contains(p.DeployChecks, "ns-no-netpol-rt") {
		covered := map[string]bool{}
		for _, np := range s.NetworkPolicies {
			covered[np.Metadata.Namespace] = true
		}
		for _, ns := range s.Namespaces {
			name := ns.Metadata.Name
			if skip(name) || covered[name] {
				continue
			}
			emit("ns-no-netpol-rt", "MEDIUM", name, "Namespace", name, fmt.Sprintf("Namespace %q has no NetworkPolicy", name))
		}
	}
	if slices.Contains(p.DeployChecks, "allow-all-ingress-rt") {
		for _, np := range s.NetworkPolicies {
			ns := np.Metadata.Namespace
			if skip(ns) {
				continue
			}
			if slices.ContainsFunc(np.Spec.Ingress, func(r ingressRule) bool { return len(r.From) == 0 }) {
				emit("allow-all-ingress-rt", "HIGH", np.Metadata.Name, "NetworkPolicy", ns, fmt.Sprintf("NetworkPolicy %q allows all ingress", np.Metadata.Name))
			}
		}
	}
	if slices.Contains(p.DeployChecks, "allow-all-egress-rt") {
		for _, np := range s.NetworkPolicies {
			ns := np.Metadata.Namespace
			if skip(ns) {
				continue
			}
			if slices.ContainsFunc(np.Spec.Egress, func(r egressRule) bool { return len(r.To) == 0 }) {
				emit("allow-all-egress-rt", "MEDIUM", np.Metadata.Name, "NetworkPolicy", ns, fmt.Sprintf("NetworkPolicy %q allows all egress", np.Metadata.Name))
			}
		}
	}
	if slices.Contains(p.DeployChecks, "nodeport-exposed-rt") {
		for _, svc := range s.Services {
			ns := svc.Metadata.Namespace
			if skip(ns) || svc.Spec.Type != "NodePort" {
				continue
			}
			emit("nodeport-exposed-rt", "MEDIUM", svc.Metadata.Name, "Service", ns, fmt.Sprintf("Service %q is type NodePort", svc.Metadata.Name))
		}
	}
	return out
}

func isTrue(b *bool) bool  { return b != nil && *b }
func isFalse(b *bool) bool { return b != nil && !*b }

func sc(c container) securityContext {
	if c.SecurityContext == nil {
		return securityContext{}
	}
	return *c.SecurityContext
}

func drops(c container) []string {
	if s := sc(c); s.Capabilities != nil {
		return s.Capabilities.Drop
	}
	return nil
}

func quantity(m map[string]any, key string) bool {
	v, ok := m[key]
	if !ok || v == nil {
		return false
	}
	switch t := v.(type) {
	case string:
		return t != ""
	case float64:
		return t != 0
	}
	return true
}

func latestTag(img string) bool {
	if img == "" || strings.Contains(img, "@") {
		return img == ""
	}
	last := img[strings.LastIndex(img, "/")+1:]
	i := strings.LastIndex(last, ":")
	return i < 0 || last[i+1:] == "latest"
}

func checkWorkload(check string, w workload) (string, bool) {
	spec := w.Spec.Template.Spec
	containers := append(slices.Clone(spec.Containers), spec.InitContainers...)
	find := func(pred func(container) bool) (container, bool) {
		for _, c := range containers {
			if pred(c) {
				return c, true
			}
		}
		return container{}, false
	}
	writableHostPath := func() (string, string, bool) {
		for _, v := range spec.Volumes {
			if v.HostPath == nil {
				continue
			}
			for _, c := range containers {
				for _, m := range c.VolumeMounts {
					if m.Name == v.Name && !m.ReadOnly {
						return v.Name, v.HostPath.Path, true
					}
				}
			}
		}
		return "", "", false
	}
	switch check {
	case "no-privileged", "privileged-pod-rt":
		if c, ok := find(func(c container) bool { return isTrue(sc(c).Privileged) }); ok {
			return fmt.Sprintf("Container %q has privileged: true", c.Name), true
		}
	case "no-host-pid", "host-pid-pod-rt":
		if spec.HostPID {
			return "spec.hostPID is true", true
		}
	case "no-host-ipc":
		if spec.HostIPC {
			return "spec.hostIPC is true", true
		}
	case "no-host-net", "host-network-pod-rt":
		if spec.HostNetwork {
			return "spec.hostNetwork is true", true
		}
	case "no-priv-esc":
		if c, ok := find(func(c container) bool { return !isFalse(sc(c).AllowPrivilegeEscalation) }); ok {
			return fmt.Sprintf("Container %q — allowPrivilegeEscalation not false", c.Name), true
		}
	case "no-root":
		if c, ok := find(func(c container) bool {
			s := sc(c)
			return (s.RunAsUser != nil && *s.RunAsUser == 0) || isFalse(s.RunAsNonRoot)
		}); ok {
			return fmt.Sprintf("Container %q runs as root", c.Name), true
		}
	case "no-root-group":
		if p := spec.SecurityContext; p != nil && (slices.Contains(p.SupplementalGroups, 0) || (p.FSGroup != nil && *p.FSGroup == 0)) {
			return "supplementalGroups or fsGroup includes GID 0", true
		}
	case "drop-net-raw":
		if c, ok := find(func(c container) bool {
			d := drops(c)
			return !slices.Contains(d, "NET_RAW") && !slices.Contains(d, "ALL")
		}); ok {
			return fmt.Sprintf("Container %q does not drop NET_RAW", c.Name), true
		}
	case "drop-all-caps":
		if c, ok := find(func(c container) bool { return !slices.Contains(drops(c), "ALL") }); ok {
			return fmt.Sprintf("Container %q does not drop ALL capabilities", c.Name), true
		}
	case "no-seccomp-unconfined":
		podUnconfined := spec.SecurityContext != nil && spec.SecurityContext.SeccompProfile != nil && spec.SecurityContext.SeccompProfile.Type == "Unconfined"
		_, ok := find(func(c container) bool {
			s := sc(c)
			return s.SeccompProfile != nil && s.SeccompProfile.Type == "Unconfined"
		})
		if podUnconfined || ok {
			return "seccompProfile is Unconfined", true
		}
	case "no-apparmor-unconfined":
		keys := make([]string, 0, len(w.Metadata.Annotations))
		for k := range w.Metadata.Annotations {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			if strings.HasPrefix(k, "container.apparmor") && w.Metadata.Annotations[k] == "unconfined" {
				return fmt.Sprintf("AppArmor annotation %s=unconfined", k), true
			}
		}
	case "readonly-root":
		if c, ok := find(func(c container) bool { return !isTrue(sc(c).ReadOnlyRootFilesystem) }); ok {
			return fmt.Sprintf("Container %q has writable root filesystem", c.Name), true
		}
	case "no-host-path":
		for _, v := range spec.Volumes {
			if v.HostPath != nil {
				return fmt.Sprintf("Volume %q uses hostPath: %s", v.Name, v.HostPath.Path), true
			}
		}
	case "no-host-path-write":
		if name, _, ok := writableHostPath(); ok {
			return fmt.Sprintf("hostPath %q mounted writable", name), true
		}
	case "no-host-path-write-rt":
		if name, path, ok := writableHostPath(); ok {
			return fmt.Sprintf("hostPath %q mounted writable at %s", name, path), true
		}
	case "no-host-port":
		for _, c := range containers {
			for _, p := range c.Ports {
				if p.HostPort != 0 {
					return fmt.Sprintf("Port %d exposes hostPort %d", p.ContainerPort, p.HostPort), true
				}
			}
		}
	case "resource-limits":
		if c, ok := find(func(c container) bool {
			return !quantity(c.Resources.Limits, "cpu") || !quantity(c.Resources.Limits, "memory")
		}); ok {
			return fmt.Sprintf("Container %q missing CPU/memory limits", c.Name), true
		}
	case "resource-requests":
		if c, ok := find(func(c container) bool {
			return !quantity(c.Resources.Requests, "cpu") || !quantity(c.Resources.Requests, "memory")
		}); ok {
			return fmt.Sprintf("Container %q missing CPU/memory requests", c.Name), true
		}
	case "no-latest-tag":
		if c, ok := find(func(c container) bool { return latestTag(c.Image) }); ok {
			return fmt.Sprintf("Container %q uses :latest tag: %s", c.Name, c.Image), true
		}
	case "no-default-sa":
		if (spec.ServiceAccountName == "" || spec.ServiceAccountName == "default") && !isFalse(spec.AutomountServiceAccountToken) {
			return "Default ServiceAccount with automountServiceAccountToken enabled", true
		}
	case "secret-as-env-rt":
		for _, c := range containers {
			for _, e := range c.Env {
				if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
					return fmt.Sprintf("Container %q exposes secret %q as env var", c.Name, e.ValueFrom.SecretKeyRef.Name), true
				}
			}
			for _, ef := range c.EnvFrom {
				if ef.SecretRef != nil {
					return fmt.Sprintf("Container %q exposes all keys of secret %q via envFrom", c.Name, ef.SecretRef.Name), true
				}
			}
		}
	}
	return "", false
}
