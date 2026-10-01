package auditrules

type Builtin struct {
	ID       string
	Group    string
	Name     string
	Kind     string
	Resource string
	Severity string
	Enabled  bool
}

var Catalog = []Builtin{
	{"exec-pod", "Pod Access", "Exec into pod", KindExec, "", SevHigh, true},
	{"attach-pod", "Pod Access", "Attach to pod", KindAttach, "", SevHigh, true},
	{"portforward-pod", "Pod Access", "Port-forward to pod", KindPortForward, "", SevHigh, true},

	{"pod-create", "Workloads", "Pod created", KindCreate, "pods", SevLow, false},
	{"pod-delete", "Workloads", "Pod deleted", KindDelete, "pods", SevLow, false},
	{"deploy-create", "Workloads", "Deployment created", KindCreate, "deployments", SevLow, false},
	{"deploy-update", "Workloads", "Deployment updated", KindUpdate, "deployments", SevLow, false},
	{"daemonset-create", "Workloads", "DaemonSet created", KindCreate, "daemonsets", SevMedium, true},
	{"daemonset-update", "Workloads", "DaemonSet updated", KindUpdate, "daemonsets", SevLow, false},
	{"job-create", "Workloads", "Job created", KindCreate, "jobs", SevLow, false},
	{"cronjob-create", "Workloads", "CronJob created", KindCreate, "cronjobs", SevMedium, false},

	{"secret-create", "Secrets", "Secret created", KindCreate, "secrets", SevMedium, false},
	{"secret-delete", "Secrets", "Secret deleted", KindDelete, "secrets", SevMedium, true},
	{"configmap-update", "Secrets", "ConfigMap updated", KindUpdate, "configmaps", SevLow, false},

	{"role-create", "RBAC", "Role created", KindCreate, "roles", SevMedium, true},
	{"clusterrole-create", "RBAC", "ClusterRole created", KindCreate, "clusterroles", SevHigh, true},
	{"rolebinding-create", "RBAC", "RoleBinding created", KindCreate, "rolebindings", SevMedium, true},
	{"rolebinding-delete", "RBAC", "RoleBinding deleted", KindDelete, "rolebindings", SevMedium, false},
	{"crb-create", "RBAC", "ClusterRoleBinding created", KindCreate, "clusterrolebindings", SevCritical, true},
	{"crb-delete", "RBAC", "ClusterRoleBinding deleted", KindDelete, "clusterrolebindings", SevMedium, true},

	{"mwh-create", "Admission", "MutatingWebhook created", KindCreate, "mutatingwebhookconfigurations", SevCritical, true},
	{"mwh-update", "Admission", "MutatingWebhook updated", KindUpdate, "mutatingwebhookconfigurations", SevHigh, true},
	{"mwh-delete", "Admission", "MutatingWebhook deleted", KindDelete, "mutatingwebhookconfigurations", SevHigh, true},
	{"vwh-create", "Admission", "ValidatingWebhook created", KindCreate, "validatingwebhookconfigurations", SevHigh, true},
	{"vwh-update", "Admission", "ValidatingWebhook updated", KindUpdate, "validatingwebhookconfigurations", SevHigh, true},
	{"vwh-delete", "Admission", "ValidatingWebhook deleted", KindDelete, "validatingwebhookconfigurations", SevHigh, true},

	{"ns-create", "Infrastructure", "Namespace created", KindCreate, "namespaces", SevLow, false},
	{"ns-delete", "Infrastructure", "Namespace deleted", KindDelete, "namespaces", SevHigh, true},
	{"node-create", "Infrastructure", "Node joined cluster", KindCreate, "nodes", SevMedium, true},
	{"sa-create", "Infrastructure", "ServiceAccount created", KindCreate, "serviceaccounts", SevMedium, true},
	{"sa-delete", "Infrastructure", "ServiceAccount deleted", KindDelete, "serviceaccounts", SevLow, false},
}

func (b Builtin) Rule() Rule {
	r := Rule{
		ID:       b.ID,
		Name:     b.Name,
		Group:    b.Group,
		Origin:   OriginBuiltin,
		Enabled:  b.Enabled,
		Severity: b.Severity,
		Spec:     Spec{Kinds: []string{b.Kind}},
	}
	if b.Resource != "" {
		r.Spec.Resources = []string{b.Resource}
	}
	r.Normalize()
	return r
}

func BuiltinRules() []Rule {
	out := make([]Rule, 0, len(Catalog))
	for _, b := range Catalog {
		out = append(out, b.Rule())
	}
	return out
}

func LookupBuiltin(id string) (Builtin, bool) {
	for _, b := range Catalog {
		if b.ID == id {
			return b, true
		}
	}
	return Builtin{}, false
}
