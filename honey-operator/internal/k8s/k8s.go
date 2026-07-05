package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

var SupportedServices = map[string]int32{
	"dns":      5353,
	"postgres": 5432,
	"redis":    6379,
	"elastic":  9200,
	"mysql":    3306,
	"ssh":      22,
	"ftp":      21,
	"http":     80,
	"https":    443,
	"smtp":     25,
	"imap":     143,
	"ldap":     389,
	"vnc":      5900,
	"rdp":      3389,
}

const (
	image          = "localhost/wolfee-watcher/honeypot:latest"
	labelComponent = "deception"
	labelManagedBy = "h-operator"
)

var blockedNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
}

type Manager struct {
	client kubernetes.Interface
}

func New(client kubernetes.Interface) *Manager {
	return &Manager{client: client}
}

func (m *Manager) CheckNamespace(ctx context.Context, ns string) error {
	_, err := m.client.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
	return err
}

func (m *Manager) Create(ctx context.Context, name, ns string, services []string) error {
	if blockedNamespaces[ns] {
		return fmt.Errorf("namespace %q is protected and cannot be used for honeypots", ns)
	}
	podName := "h-" + name

	for _, svc := range services {
		if _, ok := SupportedServices[svc]; !ok {
			return fmt.Errorf("unsupported service: %s", svc)
		}
	}

	if err := m.createConfigMap(ctx, podName, name, ns, services); err != nil {
		log.Printf("[k8s] createConfigMap error: %v", err)
		return fmt.Errorf("configmap: %w", err)
	}
	log.Printf("[k8s] configmap created for %s/%s", ns, podName)
	if err := m.createPod(ctx, podName, name, ns, services); err != nil {
		_ = m.deleteConfigMap(ctx, podName, ns)
		log.Printf("[k8s] createPod error: %v", err)
		return fmt.Errorf("pod: %w", err)
	}
	log.Printf("[k8s] pod created for %s/%s", ns, podName)
	if err := m.createService(ctx, podName, name, ns, services); err != nil {
		_ = m.deletePod(ctx, podName, ns)
		_ = m.deleteConfigMap(ctx, podName, ns)
		log.Printf("[k8s] createService error: %v", err)

		return fmt.Errorf("service: %w", err)
	}
	return nil
}

func (m *Manager) Delete(ctx context.Context, name, ns string) error {
	resName := "h-" + name
	var errs []error
	if err := m.deleteService(ctx, resName, ns); err != nil {
		errs = append(errs, err)
	}
	if err := m.deletePod(ctx, resName, ns); err != nil {
		errs = append(errs, err)
	}
	if err := m.deleteConfigMap(ctx, resName, ns); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("delete errors: %v", errs)
	}
	return nil
}

func (m *Manager) List(ctx context.Context, ns string) ([]corev1.Pod, error) {

	list, err := m.client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
		LabelSelector: "component=" + labelComponent + ",managed-by=" + labelManagedBy,
	})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (m *Manager) GetService(ctx context.Context, name, ns string) (*corev1.Service, error) {
	return m.client.CoreV1().Services(ns).Get(ctx, "h-"+name, metav1.GetOptions{})
}

func (m *Manager) Logs(ctx context.Context, name, ns string, tailLines int64) ([]byte, error) {
	opts := &corev1.PodLogOptions{}
	if tailLines > 0 {
		opts.TailLines = &tailLines
	}
	req := m.client.CoreV1().Pods(ns).GetLogs("h-"+name, opts)
	stream, err := req.Stream(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	buf := make([]byte, 0, 64*1024)
	tmp := make([]byte, 4096)
	for {
		n, err := stream.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}

func labels(podName, userNname string) map[string]string {
	return map[string]string{
		"app":           podName,
		"component":     labelComponent,
		"managed-by":    labelManagedBy,
		"honeypot-name": userNname,
	}
}

func buildConfig(services []string) (string, error) {
	type svcCfg struct {
		Port    int32    `json:"port"`
		IP      string   `json:"ip"`
		Options []string `json:"options"`
	}
	honeypots := make(map[string]svcCfg, len(services))
	for _, svc := range services {
		port := SupportedServices[svc]
		honeypots[svc] = svcCfg{Port: port, IP: "0.0.0.0", Options: []string{"capture_commands"}}
	}
	cfg := map[string]interface{}{
		"logs":              "file,terminal,json",
		"logs_location":     "/var/log/honeypots/",
		"syslog_address":    "",
		"syslog_facility":   0,
		"postgres":          "",
		"sqlite_file":       "",
		"db_options":        []string{},
		"sniffer_filter":    "",
		"sniffer_interface": "",
		"honeypots":         honeypots,
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	return string(b), err
}

func (m *Manager) createConfigMap(ctx context.Context, podName, userName, ns string, services []string) error {
	cfgJSON, err := buildConfig(services)
	if err != nil {
		return err
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName + "-config",
			Namespace: ns,
			Labels:    labels(podName, userName),
		},
		Data: map[string]string{
			"config.json": cfgJSON,
		},
	}
	_, err = m.client.CoreV1().ConfigMaps(ns).Create(ctx, cm, metav1.CreateOptions{})
	return err
}

func (m *Manager) createPod(ctx context.Context, podName, userName, ns string, services []string) error {
	svcList := ""
	for i, s := range services {
		if i > 0 {
			svcList += ","
		}
		svcList += s
	}

	var ports []corev1.ContainerPort
	for _, svc := range services {
		port := SupportedServices[svc]
		proto := corev1.ProtocolTCP
		if svc == "dns" {
			proto = corev1.ProtocolUDP
		}
		ports = append(ports, corev1.ContainerPort{
			Name:          svc,
			ContainerPort: port,
			Protocol:      proto,
		})
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: ns,
			Labels:    labels(podName, userName),
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyAlways,

			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: boolPtr(true),
				RunAsUser:    int64Ptr(65534),
				RunAsGroup:   int64Ptr(65534),
				SeccompProfile: &corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				},
			},
			Containers: []corev1.Container{
				{
					Name:            "honeypot",
					Image:           image,
					ImagePullPolicy: corev1.PullNever,
					Args: []string{
						"--setup", svcList,
						"--config", "/etc/honeypot/config.json",
						"--termination-strategy", "signal",
					},
					Ports: ports,

					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: boolPtr(false),
						RunAsNonRoot:             boolPtr(true),
						RunAsUser:                int64Ptr(65534),
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"ALL"},
							Add:  []corev1.Capability{"NET_BIND_SERVICE"},
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{Name: "config", MountPath: "/etc/honeypot", ReadOnly: true},
						{Name: "logs", MountPath: "/var/log/honeypots"},

						{Name: "tmp", MountPath: "/tmp"},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "config",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: podName + "-config"},
						},
					},
				},
				{
					Name:         "logs",
					VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
				},
				{
					Name:         "tmp",
					VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
				},
			},
		},
	}
	_, err := m.client.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{})
	return err
}

func (m *Manager) createService(ctx context.Context, podName, userName, ns string, services []string) error {
	var ports []corev1.ServicePort
	for _, svc := range services {
		port := SupportedServices[svc]
		proto := corev1.ProtocolTCP
		if svc == "dns" {
			proto = corev1.ProtocolUDP
		}
		ports = append(ports, corev1.ServicePort{
			Name:       svc,
			Port:       port,
			TargetPort: intstr.FromInt(int(port)),
			Protocol:   proto,
		})
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: ns,
			Labels:    labels(podName, userName),
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": podName},
			Type:     corev1.ServiceTypeClusterIP,
			Ports:    ports,
		},
	}
	_, err := m.client.CoreV1().Services(ns).Create(ctx, svc, metav1.CreateOptions{})
	return err
}

func (m *Manager) deleteConfigMap(ctx context.Context, name, ns string) error {
	return m.client.CoreV1().ConfigMaps(ns).Delete(ctx, name+"-config", metav1.DeleteOptions{})
}
func (m *Manager) deletePod(ctx context.Context, name, ns string) error {
	return m.client.CoreV1().Pods(ns).Delete(ctx, name, metav1.DeleteOptions{})
}
func (m *Manager) deleteService(ctx context.Context, name, ns string) error {
	return m.client.CoreV1().Services(ns).Delete(ctx, name, metav1.DeleteOptions{})
}

func boolPtr(b bool) *bool    { return &b }
func int64Ptr(i int64) *int64 { return &i }
