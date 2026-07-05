package alerter

import (
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/wolfee-watcher/sensor/internal/collector"
)

type workloadRef struct {
	kind      string
	name      string
	namespace string
	spec      corev1.PodSpec
	anns      map[string]string
}

func (a *Alerter) runOnce() {
	a.mu.RLock()
	rules := a.rules
	a.mu.RUnlock()
	if len(rules) == 0 {
		return
	}
	snap := a.snap.GetSnapshot()
	if snap == nil {
		return
	}

	var workloads []workloadRef
	for _, d := range snap.Deployments {
		workloads = append(workloads, workloadRef{
			kind: "Deployment", name: d.Name, namespace: d.Namespace,
			spec: d.Spec.Template.Spec, anns: d.Spec.Template.Annotations,
		})
	}
	for _, s := range snap.StatefulSets {
		workloads = append(workloads, workloadRef{
			kind: "StatefulSet", name: s.Name, namespace: s.Namespace,
			spec: s.Spec.Template.Spec, anns: s.Spec.Template.Annotations,
		})
	}
	for _, d := range snap.DaemonSets {
		workloads = append(workloads, workloadRef{
			kind: "DaemonSet", name: d.Name, namespace: d.Namespace,
			spec: d.Spec.Template.Spec, anns: d.Spec.Template.Annotations,
		})
	}

	for _, r := range rules {
		nsFilter := strings.TrimSpace(r.Namespace)
		for _, w := range workloads {
			if nsFilter != "" && w.namespace != nsFilter {
				continue
			}
			for _, checkID := range r.DeployChecks {
				if detail, ok := evalWorkloadCheck(checkID, w); ok {
					a.emit(r, w.namespace, w.name+" ("+w.kind+")", checkID, detail)
				}
			}
		}
		evalClusterChecks(a, r, snap, nsFilter)
	}
}

func evalWorkloadCheck(id string, w workloadRef) (string, bool) {
	containers := append([]corev1.Container{}, w.spec.Containers...)
	containers = append(containers, w.spec.InitContainers...)

	switch id {
	case "no-privileged", "privileged-pod-rt":
		for _, c := range containers {
			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				return "Container \"" + c.Name + "\" has privileged: true", true
			}
		}
	case "no-host-pid", "host-pid-pod-rt":
		if w.spec.HostPID {
			return "spec.hostPID is true", true
		}
	case "no-host-ipc":
		if w.spec.HostIPC {
			return "spec.hostIPC is true", true
		}
	case "no-host-net", "host-network-pod-rt":
		if w.spec.HostNetwork {
			return "spec.hostNetwork is true", true
		}
	case "no-priv-esc":
		for _, c := range containers {
			ok := c.SecurityContext != nil && c.SecurityContext.AllowPrivilegeEscalation != nil && !*c.SecurityContext.AllowPrivilegeEscalation
			if !ok {
				return "Container \"" + c.Name + "\" — allowPrivilegeEscalation not false", true
			}
		}
	case "no-root":
		for _, c := range containers {
			if c.SecurityContext == nil {
				continue
			}
			if c.SecurityContext.RunAsUser != nil && *c.SecurityContext.RunAsUser == 0 {
				return "Container \"" + c.Name + "\" runs as root (runAsUser=0)", true
			}
			if c.SecurityContext.RunAsNonRoot != nil && !*c.SecurityContext.RunAsNonRoot {
				return "Container \"" + c.Name + "\" runs as root (runAsNonRoot=false)", true
			}
		}
	case "no-root-group":
		if w.spec.SecurityContext != nil {
			for _, g := range w.spec.SecurityContext.SupplementalGroups {
				if g == 0 {
					return "supplementalGroups includes GID 0", true
				}
			}
			if w.spec.SecurityContext.FSGroup != nil && *w.spec.SecurityContext.FSGroup == 0 {
				return "fsGroup is 0", true
			}
		}
	case "drop-net-raw":
		for _, c := range containers {
			drop := capabilityDropList(c)
			if !containsCap(drop, "NET_RAW") && !containsCap(drop, "ALL") {
				return "Container \"" + c.Name + "\" does not drop NET_RAW", true
			}
		}
	case "drop-all-caps":
		for _, c := range containers {
			if !containsCap(capabilityDropList(c), "ALL") {
				return "Container \"" + c.Name + "\" does not drop ALL capabilities", true
			}
		}
	case "no-seccomp-unconfined":
		if w.spec.SecurityContext != nil && w.spec.SecurityContext.SeccompProfile != nil &&
			w.spec.SecurityContext.SeccompProfile.Type == corev1.SeccompProfileTypeUnconfined {
			return "seccompProfile is Unconfined (pod-level)", true
		}
		for _, c := range containers {
			if c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil &&
				c.SecurityContext.SeccompProfile.Type == corev1.SeccompProfileTypeUnconfined {
				return "Container \"" + c.Name + "\" seccompProfile Unconfined", true
			}
		}
	case "no-apparmor-unconfined":
		for k, v := range w.anns {
			if strings.HasPrefix(k, "container.apparmor") && v == "unconfined" {
				return "AppArmor annotation " + k + "=unconfined", true
			}
		}
	case "readonly-root":
		for _, c := range containers {
			ok := c.SecurityContext != nil && c.SecurityContext.ReadOnlyRootFilesystem != nil && *c.SecurityContext.ReadOnlyRootFilesystem
			if !ok {
				return "Container \"" + c.Name + "\" has writable root filesystem", true
			}
		}
	case "no-host-path":
		for _, v := range w.spec.Volumes {
			if v.HostPath != nil {
				return "Volume \"" + v.Name + "\" uses hostPath: " + v.HostPath.Path, true
			}
		}
	case "no-host-path-write", "no-host-path-write-rt":
		for _, v := range w.spec.Volumes {
			if v.HostPath == nil {
				continue
			}
			for _, c := range containers {
				for _, m := range c.VolumeMounts {
					if m.Name == v.Name && !m.ReadOnly {
						return "hostPath \"" + v.Name + "\" mounted writable at " + v.HostPath.Path, true
					}
				}
			}
		}
	case "no-host-port":
		for _, c := range containers {
			for _, p := range c.Ports {
				if p.HostPort != 0 {
					return "Container port exposes hostPort " + itoa(int(p.HostPort)), true
				}
			}
		}
	case "resource-limits":
		for _, c := range containers {
			if c.Resources.Limits.Cpu().IsZero() || c.Resources.Limits.Memory().IsZero() {
				return "Container \"" + c.Name + "\" missing CPU/memory limits", true
			}
		}
	case "resource-requests":
		for _, c := range containers {
			if c.Resources.Requests.Cpu().IsZero() || c.Resources.Requests.Memory().IsZero() {
				return "Container \"" + c.Name + "\" missing CPU/memory requests", true
			}
		}
	case "no-latest-tag":

		for _, c := range containers {
			img := c.Image
			if !strings.Contains(img, ":") {
				return "Container \"" + c.Name + "\" uses :latest tag: " + img, true
			}
			tag := img[strings.LastIndex(img, ":")+1:]
			if tag == "latest" {
				return "Container \"" + c.Name + "\" uses :latest tag: " + img, true
			}
		}
	case "no-default-sa":
		sa := w.spec.ServiceAccountName
		auto := w.spec.AutomountServiceAccountToken
		if (sa == "" || sa == "default") && (auto == nil || *auto) {
			return "Default ServiceAccount with automountServiceAccountToken enabled", true
		}
	case "secret-as-env-rt":
		for _, c := range containers {
			for _, e := range c.Env {
				if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
					return "Container \"" + c.Name + "\" exposes secret \"" + e.ValueFrom.SecretKeyRef.Name + "\" as env var", true
				}
			}
			for _, ef := range c.EnvFrom {
				if ef.SecretRef != nil {
					return "Container \"" + c.Name + "\" exposes all keys of secret \"" + ef.SecretRef.Name + "\" via envFrom", true
				}
			}
		}
	}
	return "", false
}

func evalClusterChecks(a *Alerter, r deployRule, snap *collector.Snapshot, nsFilter string) {
	if !hasAny(r.DeployChecks, "ns-no-netpol-rt", "allow-all-ingress-rt", "allow-all-egress-rt", "nodeport-exposed-rt") {
		return
	}

	if hasAny(r.DeployChecks, "ns-no-netpol-rt") {
		covered := make(map[string]bool, len(snap.NetworkPolicies))
		for _, np := range snap.NetworkPolicies {
			covered[np.Namespace] = true
		}
		for _, ns := range snap.Namespaces {
			name := ns.Name
			if systemNS[name] {
				continue
			}
			if nsFilter != "" && name != nsFilter {
				continue
			}
			if !covered[name] {
				a.emit(r, name, name+" (Namespace)", "ns-no-netpol-rt",
					"Namespace \""+name+"\" has no NetworkPolicy")
			}
		}
	}

	if hasAny(r.DeployChecks, "allow-all-ingress-rt") {
		for _, np := range snap.NetworkPolicies {
			if systemNS[np.Namespace] {
				continue
			}
			if nsFilter != "" && np.Namespace != nsFilter {
				continue
			}
			for _, rule := range np.Spec.Ingress {
				if len(rule.From) == 0 {
					a.emit(r, np.Namespace, np.Name+" (NetworkPolicy)", "allow-all-ingress-rt",
						"NetworkPolicy \""+np.Name+"\" allows all ingress")
					break
				}
			}
		}
	}

	if hasAny(r.DeployChecks, "allow-all-egress-rt") {
		for _, np := range snap.NetworkPolicies {
			if systemNS[np.Namespace] {
				continue
			}
			if nsFilter != "" && np.Namespace != nsFilter {
				continue
			}
			for _, rule := range np.Spec.Egress {
				if len(rule.To) == 0 {
					a.emit(r, np.Namespace, np.Name+" (NetworkPolicy)", "allow-all-egress-rt",
						"NetworkPolicy \""+np.Name+"\" allows all egress")
					break
				}
			}
		}
	}

	if hasAny(r.DeployChecks, "nodeport-exposed-rt") {
		for _, svc := range snap.Services {
			if systemNS[svc.Namespace] {
				continue
			}
			if nsFilter != "" && svc.Namespace != nsFilter {
				continue
			}
			if svc.Spec.Type == corev1.ServiceTypeNodePort {
				a.emit(r, svc.Namespace, svc.Name+" (Service)", "nodeport-exposed-rt",
					"Service \""+svc.Name+"\" is type NodePort")
			}
		}
	}
}
