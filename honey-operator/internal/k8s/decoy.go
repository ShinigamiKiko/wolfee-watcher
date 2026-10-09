package k8s

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8slabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/wolfee-watcher/honey-operator/internal/decoy"
	"github.com/wolfee-watcher/honey-operator/internal/registry"
)

var ErrNameTaken = errors.New("name is already used in this namespace")

const (
	StateReady    = "ok"
	StateMissing  = "missing"
	StateReplaced = "replaced"
)

type DecoyStatus struct {
	State     string
	Phase     string
	ClusterIP string
	Pods      []corev1.Pod
}

func headlessName(name string) string { return name + "-hl" }

func NewID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (m *Manager) NameTaken(ctx context.Context, ns, name string, p decoy.Profile) (bool, error) {
	checks := []func() error{
		func() error {
			_, err := m.client.AppsV1().StatefulSets(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		},
		func() error {
			_, err := m.client.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		},
		func() error { _, err := m.client.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{}); return err },
		func() error {
			_, err := m.client.NetworkingV1().NetworkPolicies(ns).Get(ctx, name, metav1.GetOptions{})
			return err
		},
	}
	if p.Kind == decoy.KindStatefulSet {
		checks = append(checks, func() error {
			_, err := m.client.CoreV1().Services(ns).Get(ctx, headlessName(name), metav1.GetOptions{})
			return err
		})
	}
	for _, check := range checks {
		err := check()
		if err == nil {
			return true, nil
		}
		if !k8serrors.IsNotFound(err) {
			return false, err
		}
	}
	return false, nil
}

func (m *Manager) CreateDecoy(ctx context.Context, ns, name string, p decoy.Profile) (registry.Record, error) {
	rec := registry.Record{
		ID:         NewID(),
		Namespace:  ns,
		Name:       name,
		Kind:       p.Kind,
		Service:    p.Service,
		Port:       p.Port,
		TargetPort: p.TargetPort,
		Selector:   p.Selector(name),
		Image:      p.Image(),
		CreatedAt:  time.Now().UTC(),
	}
	if blockedNamespaces[ns] {
		return rec, fmt.Errorf("namespace %q is protected and cannot be used for honeypots", ns)
	}
	taken, err := m.NameTaken(ctx, ns, name, p)
	if err != nil {
		return rec, err
	}
	if taken {
		return rec, ErrNameTaken
	}

	var cleanup []func()
	rollback := func() {
		for i := len(cleanup) - 1; i >= 0; i-- {
			cleanup[i]()
		}
	}
	bg := context.Background()

	svc, err := m.client.CoreV1().Services(ns).Create(ctx, decoyService(ns, name, p), metav1.CreateOptions{})
	if err != nil {
		return rec, fmt.Errorf("service: %w", err)
	}
	cleanup = append(cleanup, func() { _ = m.deleteIfUID(bg, "service", ns, name, string(svc.UID)) })
	rec.ServiceUID = string(svc.UID)
	rec.ClusterIP = svc.Spec.ClusterIP

	if p.Kind == decoy.KindStatefulSet {
		hl, err := m.client.CoreV1().Services(ns).Create(ctx, decoyHeadless(ns, name, p), metav1.CreateOptions{})
		if err != nil {
			rollback()
			return rec, fmt.Errorf("headless service: %w", err)
		}
		cleanup = append(cleanup, func() { _ = m.deleteIfUID(bg, "service", ns, headlessName(name), string(hl.UID)) })
	}

	np, err := m.client.NetworkingV1().NetworkPolicies(ns).Create(ctx, decoyPolicy(ns, name, p), metav1.CreateOptions{})
	if err != nil {
		rollback()
		return rec, fmt.Errorf("network policy: %w", err)
	}
	cleanup = append(cleanup, func() { _ = m.deleteIfUID(bg, "networkpolicy", ns, name, string(np.UID)) })
	rec.PolicyUID = string(np.UID)

	switch p.Kind {
	case decoy.KindStatefulSet:
		sts, err := m.client.AppsV1().StatefulSets(ns).Create(ctx, decoyStatefulSet(ns, name, p), metav1.CreateOptions{})
		if err != nil {
			rollback()
			return rec, fmt.Errorf("statefulset: %w", err)
		}
		rec.WorkloadUID = string(sts.UID)
		cleanup = append(cleanup, func() { _ = m.deleteIfUID(bg, "statefulset", ns, name, string(sts.UID)) })
	default:
		dep, err := m.client.AppsV1().Deployments(ns).Create(ctx, decoyDeployment(ns, name, p), metav1.CreateOptions{})
		if err != nil {
			rollback()
			return rec, fmt.Errorf("deployment: %w", err)
		}
		rec.WorkloadUID = string(dep.UID)
		cleanup = append(cleanup, func() { _ = m.deleteIfUID(bg, "deployment", ns, name, string(dep.UID)) })
	}
	return rec, nil
}

func (m *Manager) RollbackDecoy(ctx context.Context, rec registry.Record) {
	_ = m.DeleteDecoy(ctx, rec)
}

func (m *Manager) DeleteDecoy(ctx context.Context, rec registry.Record) error {
	var errs []error
	kind := "deployment"
	if rec.Kind == decoy.KindStatefulSet {
		kind = "statefulset"
	}
	if err := m.deleteIfUID(ctx, kind, rec.Namespace, rec.Name, rec.WorkloadUID); err != nil {
		errs = append(errs, err)
	}
	if err := m.deleteIfUID(ctx, "service", rec.Namespace, rec.Name, rec.ServiceUID); err != nil {
		errs = append(errs, err)
	}
	if rec.Kind == decoy.KindStatefulSet {
		if err := m.deleteOwnedHeadless(ctx, rec); err != nil {
			errs = append(errs, err)
		}
	}
	if err := m.deleteIfUID(ctx, "networkpolicy", rec.Namespace, rec.Name, rec.PolicyUID); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (m *Manager) deleteOwnedHeadless(ctx context.Context, rec registry.Record) error {
	hl, err := m.client.CoreV1().Services(rec.Namespace).Get(ctx, headlessName(rec.Name), metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !labelsMatch(hl.Labels, rec.Selector) {
		return nil
	}
	return m.deleteIfUID(ctx, "service", rec.Namespace, hl.Name, string(hl.UID))
}

func (m *Manager) deleteIfUID(ctx context.Context, kind, ns, name, uid string) error {
	if uid == "" {
		return nil
	}
	pre := metav1.NewUIDPreconditions(uid)
	opts := metav1.DeleteOptions{Preconditions: pre}
	var err error
	switch kind {
	case "statefulset":
		err = m.client.AppsV1().StatefulSets(ns).Delete(ctx, name, opts)
	case "deployment":
		err = m.client.AppsV1().Deployments(ns).Delete(ctx, name, opts)
	case "service":
		err = m.client.CoreV1().Services(ns).Delete(ctx, name, opts)
	case "networkpolicy":
		err = m.client.NetworkingV1().NetworkPolicies(ns).Delete(ctx, name, opts)
	default:
		return fmt.Errorf("unknown kind %s", kind)
	}
	if k8serrors.IsNotFound(err) || k8serrors.IsConflict(err) {
		return nil
	}
	return err
}

func (m *Manager) InspectDecoy(ctx context.Context, rec registry.Record) DecoyStatus {
	st := DecoyStatus{State: StateReady, ClusterIP: rec.ClusterIP}
	var workloadUID types.UID
	switch rec.Kind {
	case decoy.KindStatefulSet:
		sts, err := m.client.AppsV1().StatefulSets(rec.Namespace).Get(ctx, rec.Name, metav1.GetOptions{})
		if err != nil {
			st.State = StateMissing
			return st
		}
		workloadUID = sts.UID
	default:
		dep, err := m.client.AppsV1().Deployments(rec.Namespace).Get(ctx, rec.Name, metav1.GetOptions{})
		if err != nil {
			st.State = StateMissing
			return st
		}
		workloadUID = dep.UID
	}
	if string(workloadUID) != rec.WorkloadUID {
		st.State = StateReplaced
		return st
	}
	if svc, err := m.client.CoreV1().Services(rec.Namespace).Get(ctx, rec.Name, metav1.GetOptions{}); err == nil && string(svc.UID) == rec.ServiceUID {
		st.ClusterIP = svc.Spec.ClusterIP
	}
	st.Pods = m.OwnedPods(ctx, rec)
	st.Phase = "Pending"
	for _, p := range st.Pods {
		if p.Status.Phase == corev1.PodRunning {
			st.Phase = string(corev1.PodRunning)
			break
		}
		st.Phase = string(p.Status.Phase)
	}
	return st
}

func (m *Manager) OwnedPods(ctx context.Context, rec registry.Record) []corev1.Pod {
	sel := k8slabels.SelectorFromSet(rec.Selector).String()
	list, err := m.client.CoreV1().Pods(rec.Namespace).List(ctx, metav1.ListOptions{LabelSelector: sel})
	if err != nil {
		return nil
	}
	rsOwner := map[string]string{}
	var out []corev1.Pod
	for _, pod := range list.Items {
		owner := metav1.GetControllerOf(&pod)
		if owner == nil {
			continue
		}
		switch {
		case rec.Kind == decoy.KindStatefulSet && owner.Kind == "StatefulSet":
			if string(owner.UID) == rec.WorkloadUID {
				out = append(out, pod)
			}
		case rec.Kind == decoy.KindDeployment && owner.Kind == "ReplicaSet":
			depUID, ok := rsOwner[string(owner.UID)]
			if !ok {
				rs, err := m.client.AppsV1().ReplicaSets(rec.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
				if err == nil {
					if dep := metav1.GetControllerOf(rs); dep != nil && dep.Kind == "Deployment" {
						depUID = string(dep.UID)
					}
				}
				rsOwner[string(owner.UID)] = depUID
			}
			if depUID == rec.WorkloadUID {
				out = append(out, pod)
			}
		}
	}
	return out
}

func (m *Manager) StreamLogs(ctx context.Context, ns, pod string, since *metav1.Time, tail int64) (io.ReadCloser, error) {
	opts := &corev1.PodLogOptions{Follow: true, Timestamps: false}
	if since != nil {
		opts.SinceTime = since
	} else if tail > 0 {
		opts.TailLines = &tail
	}
	return m.client.CoreV1().Pods(ns).GetLogs(pod, opts).Stream(ctx)
}

func (m *Manager) PodLogs(ctx context.Context, ns, pod string, tail int64) ([]byte, error) {
	opts := &corev1.PodLogOptions{}
	if tail > 0 {
		opts.TailLines = &tail
	}
	stream, err := m.client.CoreV1().Pods(ns).GetLogs(pod, opts).Stream(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	return io.ReadAll(io.LimitReader(stream, 8<<20))
}

func labelsMatch(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

func decoyService(ns, name string, p decoy.Profile) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: p.Labels(name)},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: p.Selector(name),
			Ports: []corev1.ServicePort{{
				Name: p.PortName, Port: p.Port, TargetPort: intstr.FromString(p.PortName), Protocol: p.Protocol,
			}},
		},
	}
}

func decoyHeadless(ns, name string, p decoy.Profile) *corev1.Service {
	svc := decoyService(ns, headlessName(name), p)
	svc.Spec.Selector = p.Selector(name)
	svc.Spec.ClusterIP = corev1.ClusterIPNone
	svc.Spec.PublishNotReadyAddresses = true
	return svc
}

func decoyPolicy(ns, name string, p decoy.Profile) *networkingv1.NetworkPolicy {
	port := intstr.FromInt32(p.TargetPort)
	proto := p.Protocol
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: p.Labels(name)},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: p.Selector(name)},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				Ports: []networkingv1.NetworkPolicyPort{{Port: &port, Protocol: &proto}},
			}},
			Egress: []networkingv1.NetworkPolicyEgressRule{},
		},
	}
}

func decoyPodSpec(name string, p decoy.Profile) corev1.PodTemplateSpec {
	mounts := []corev1.VolumeMount{
		{Name: "tmp", MountPath: "/tmp"},
		{Name: "logs", MountPath: "/var/log/" + p.Service},
	}
	volumes := []corev1.Volume{
		{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{Name: "logs", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
	}
	if p.DataPath != "" {
		mounts = append(mounts, corev1.VolumeMount{Name: "data", MountPath: p.DataPath})
		volumes = append(volumes, corev1.Volume{Name: "data", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
	}
	container := corev1.Container{
		Name:            p.AppName,
		Image:           p.Image(),
		ImagePullPolicy: decoy.PullPolicy(),
		Args:            p.Args,
		Env:             p.Env,
		Ports:           []corev1.ContainerPort{{Name: p.PortName, ContainerPort: p.TargetPort, Protocol: p.Protocol}},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("48Mi")},
			Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("160Mi")},
		},
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: boolPtr(false),
			RunAsNonRoot:             boolPtr(true),
			RunAsUser:                int64Ptr(65534),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		},
		VolumeMounts: mounts,
	}
	if p.Protocol == corev1.ProtocolTCP {
		container.ReadinessProbe = &corev1.Probe{
			ProbeHandler:        corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromString(p.PortName)}},
			InitialDelaySeconds: 5,
			PeriodSeconds:       10,
		}
	}
	return corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: p.Labels(name)},
		Spec: corev1.PodSpec{
			AutomountServiceAccountToken: boolPtr(false),
			EnableServiceLinks:           boolPtr(false),
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   boolPtr(true),
				RunAsUser:      int64Ptr(65534),
				RunAsGroup:     int64Ptr(65534),
				FSGroup:        int64Ptr(65534),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{container},
			Volumes:    volumes,
		},
	}
}

func decoyStatefulSet(ns, name string, p decoy.Profile) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: p.Labels(name)},
		Spec: appsv1.StatefulSetSpec{
			Replicas:    int32Ptr(1),
			ServiceName: headlessName(name),
			Selector:    &metav1.LabelSelector{MatchLabels: p.Selector(name)},
			Template:    decoyPodSpec(name, p),
		},
	}
}

func decoyDeployment(ns, name string, p decoy.Profile) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: p.Labels(name)},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(1),
			Selector: &metav1.LabelSelector{MatchLabels: p.Selector(name)},
			Template: decoyPodSpec(name, p),
		},
	}
}

func int32Ptr(i int32) *int32 { return &i }
