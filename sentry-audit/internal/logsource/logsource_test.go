package logsource

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func node(name string, controlPlane bool) *corev1.Node {
	n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{}}}
	if controlPlane {
		n.Labels["node-role.kubernetes.io/control-plane"] = ""
	}
	return n
}

func apiServer(nodeName string, args []string, mountPath, hostPath string) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "kube-apiserver-" + nodeName, Namespace: "kube-system",
			Labels: map[string]string{"component": "kube-apiserver"},
		},
		Spec: corev1.PodSpec{
			NodeName:   nodeName,
			Containers: []corev1.Container{{Name: "kube-apiserver", Command: append([]string{"kube-apiserver"}, args...)}},
		},
	}
	if mountPath != "" {
		pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "audit", MountPath: mountPath}}
		pod.Spec.Volumes = []corev1.Volume{{Name: "audit", VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{Path: hostPath},
		}}}
	}
	return pod
}

func TestDetect(t *testing.T) {
	client := fake.NewSimpleClientset(
		node("cp-1", true), node("cp-2", true), node("cp-3", true), node("worker-1", false),
		apiServer("cp-1", []string{"--audit-log-path=/var/log/kubernetes/audit/audit.log"}, "/var/log/kubernetes/audit", "/srv/k8s-audit"),
		apiServer("cp-2", []string{"--audit-log-path", "/logs/audit.log"}, "/logs/", "/var/log/kubernetes"),
		apiServer("cp-3", []string{"--secure-port=6443"}, "", ""),
	)
	got, err := Detect(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	want := []Node{
		{Node: "cp-1", APIServer: true, AuditEnabled: true, DetectedPath: "/srv/k8s-audit/audit.log"},
		{Node: "cp-2", APIServer: true, AuditEnabled: true, DetectedPath: "/var/log/kubernetes/audit.log"},
		{Node: "cp-3", APIServer: true},
	}
	if len(got) != len(want) {
		t.Fatalf("detected %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("node %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestDetectKeepsControlPlaneNodesWithoutAPIServerPod(t *testing.T) {
	got, err := Detect(context.Background(), fake.NewSimpleClientset(node("k3s-1", true), node("agent-1", false)))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != (Node{Node: "k3s-1"}) {
		t.Fatalf("detected %+v", got)
	}
}

func TestAuditLogWrittenToStdoutOrContainerFS(t *testing.T) {
	for _, pod := range []*corev1.Pod{
		apiServer("a", []string{"--audit-log-path=-"}, "", ""),
		apiServer("b", []string{"--audit-log-path=/tmp/audit.log"}, "/var/log", "/var/log"),
	} {
		if enabled, path := apiServerAudit(pod); !enabled || path != "" {
			t.Errorf("%s: enabled=%v path=%q, want an enabled audit log with no file on the node", pod.Name, enabled, path)
		}
	}
}

func reader() *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: DaemonSetName, Namespace: "ww"},
		Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			NodeSelector: map[string]string{OffLabel: "true"},
			Volumes: []corev1.Volume{
				{Name: "wolfee-ca-bundle"},
				{Name: "audit-log", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/old"}}},
				{Name: "tail-state"},
			},
			Containers: []corev1.Container{{
				Name: ContainerName,
				VolumeMounts: []corev1.VolumeMount{
					{Name: "wolfee-ca-bundle", MountPath: "/etc/wolfee-watcher/ca-bundle"},
					{Name: "audit-log", MountPath: "/old"},
					{Name: "tail-state", MountPath: "/var/lib/sentry-audit"},
				},
				Env: []corev1.EnvVar{{Name: EnvPath, Value: "/old/audit.log"}, {Name: "CLUSTER_ID", Value: "c"}},
			}},
		}}},
	}
}

func env(c corev1.Container, name string) string {
	for _, e := range c.Env {
		if e.Name == name {
			return e.Value
		}
	}
	return ""
}

func TestApply(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(reader())
	plan := Plan{
		Managed: true, Enabled: true, Path: "/var/log/kubernetes/audit.log",
		NodePaths: map[string]string{"cp-2": "/data/audit/audit.log", "cp-3": "/var/log/kubernetes/other.log"},
		Rev:       "r1",
	}
	changed, err := Apply(ctx, client, "ww", plan)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	ds, _ := client.AppsV1().DaemonSets("ww").Get(ctx, DaemonSetName, metav1.GetOptions{})
	spec := ds.Spec.Template.Spec
	if _, off := spec.NodeSelector[OffLabel]; off {
		t.Error("an enabled reader must not keep the off selector")
	}
	var names, dirs []string
	for _, v := range spec.Volumes {
		names = append(names, v.Name)
		if v.HostPath != nil {
			dirs = append(dirs, v.HostPath.Path)
		}
	}
	if len(names) != 4 || names[0] != "wolfee-ca-bundle" || names[1] != "tail-state" || names[2] != "audit-log-0" || names[3] != "audit-log-1" {
		t.Errorf("volumes %v", names)
	}
	if len(dirs) != 2 || dirs[0] != "/data/audit" || dirs[1] != "/var/log/kubernetes" {
		t.Errorf("host directories %v", dirs)
	}
	c := spec.Containers[0]
	if len(c.VolumeMounts) != 4 || !c.VolumeMounts[2].ReadOnly || c.VolumeMounts[2].MountPath != "/data/audit" {
		t.Errorf("mounts %+v", c.VolumeMounts)
	}
	if env(c, EnvPath) != plan.Path || env(c, EnvNodePaths) != "cp-2=/data/audit/audit.log,cp-3=/var/log/kubernetes/other.log" || env(c, "CLUSTER_ID") != "c" {
		t.Errorf("env %+v", c.Env)
	}
	if ds.Spec.Template.Annotations[RevAnnotation] != "r1" {
		t.Errorf("annotations %v", ds.Spec.Template.Annotations)
	}
	if changed, err = Apply(ctx, client, "ww", plan); err != nil || changed {
		t.Fatalf("an applied revision must not be written again: changed=%v err=%v", changed, err)
	}
	plan.Enabled, plan.Rev = false, "r2"
	if changed, err = Apply(ctx, client, "ww", plan); err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	ds, _ = client.AppsV1().DaemonSets("ww").Get(ctx, DaemonSetName, metav1.GetOptions{})
	if ds.Spec.Template.Spec.NodeSelector[OffLabel] != "true" {
		t.Error("a disabled reader must be parked by the off selector")
	}
}

func TestApplyLeavesAnUnmanagedReaderAlone(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(reader())
	changed, err := Apply(ctx, client, "ww", Plan{Managed: false, Enabled: true, Path: "/x/audit.log", Rev: "r"})
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	ds, _ := client.AppsV1().DaemonSets("ww").Get(ctx, DaemonSetName, metav1.GetOptions{})
	if ds.Spec.Template.Spec.Volumes[1].HostPath.Path != "/old" {
		t.Error("the chart-defined reader was modified without settings")
	}
}
