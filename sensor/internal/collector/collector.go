package collector

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	admregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type CRDMeta struct {
	Name      string   `json:"name"`
	Group     string   `json:"group"`
	Kind      string   `json:"kind"`
	Plural    string   `json:"plural"`
	Scope     string   `json:"scope"`
	Versions  []string `json:"versions"`
	CreatedAt string   `json:"created_at"`
}

type Snapshot struct {
	CollectedAt time.Time `json:"collected_at"`

	Nodes               []corev1.Node                             `json:"nodes"`
	Pods                []corev1.Pod                              `json:"pods"`
	Deployments         []appsv1.Deployment                       `json:"deployments"`
	StatefulSets        []appsv1.StatefulSet                      `json:"stateful_sets"`
	DaemonSets          []appsv1.DaemonSet                        `json:"daemon_sets"`
	Namespaces          []corev1.Namespace                        `json:"namespaces"`
	ServiceAccounts     []corev1.ServiceAccount                   `json:"service_accounts"`
	ClusterRoles        []rbacv1.ClusterRole                      `json:"cluster_roles"`
	ClusterRoleBindings []rbacv1.ClusterRoleBinding               `json:"cluster_role_bindings"`
	Roles               []rbacv1.Role                             `json:"roles"`
	RoleBindings        []rbacv1.RoleBinding                      `json:"role_bindings"`
	NetworkPolicies     []netv1.NetworkPolicy                     `json:"network_policies"`
	Services            []corev1.Service                          `json:"services"`
	Secrets             []SecretMeta                              `json:"secrets"`
	CRDs                []CRDMeta                                 `json:"crds"`
	MutatingWebhooks    []admregv1.MutatingWebhookConfiguration   `json:"mutating_webhooks"`
	ValidatingWebhooks  []admregv1.ValidatingWebhookConfiguration `json:"validating_webhooks"`
}

type SecretMeta struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Type      string            `json:"type"`
	Labels    map[string]string `json:"labels,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

const defaultPodListChunkSize = 500

func Collect(ctx context.Context, client kubernetes.Interface, cfg *rest.Config) (*Snapshot, error) {
	s := &Snapshot{CollectedAt: time.Now()}
	podChunkSize := int64(envInt("SENSOR_POD_LIST_CHUNK_SIZE", defaultPodListChunkSize))

	if list, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{}); err == nil {
		for i := range list.Items {
			stripMeta(&list.Items[i].ObjectMeta)
		}
		s.Nodes = list.Items
	} else {
		log.Printf("[collector] nodes: %v", err)
	}

	if pods, err := listPodsChunked(ctx, client, podChunkSize); err == nil {
		s.Pods = pods
	} else {

		log.Printf("[collector] pods: %v", err)
		return nil, fmt.Errorf("collect pods: %w", err)
	}

	if list, err := client.AppsV1().Deployments("").List(ctx, metav1.ListOptions{}); err == nil {
		for i := range list.Items {
			stripMeta(&list.Items[i].ObjectMeta)
		}
		s.Deployments = list.Items
	} else {
		log.Printf("[collector] deployments: %v", err)
	}

	if list, err := client.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{}); err == nil {
		for i := range list.Items {
			stripMeta(&list.Items[i].ObjectMeta)
		}
		s.StatefulSets = list.Items
	} else {
		log.Printf("[collector] statefulsets: %v", err)
	}

	if list, err := client.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{}); err == nil {
		for i := range list.Items {
			stripMeta(&list.Items[i].ObjectMeta)
		}
		s.DaemonSets = list.Items
	} else {
		log.Printf("[collector] daemonsets: %v", err)
	}

	if list, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{}); err == nil {
		s.Namespaces = list.Items
	} else {
		log.Printf("[collector] namespaces: %v", err)
	}

	if list, err := client.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{}); err == nil {
		s.ServiceAccounts = list.Items
	} else {
		log.Printf("[collector] serviceaccounts: %v", err)
	}

	if list, err := client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{}); err == nil {
		s.ClusterRoles = list.Items
	} else {
		log.Printf("[collector] clusterroles: %v", err)
	}

	if list, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{}); err == nil {
		s.ClusterRoleBindings = list.Items
	} else {
		log.Printf("[collector] clusterrolebindings: %v", err)
	}

	if list, err := client.RbacV1().Roles("").List(ctx, metav1.ListOptions{}); err == nil {
		s.Roles = list.Items
	} else {
		log.Printf("[collector] roles: %v", err)
	}

	if list, err := client.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{}); err == nil {
		s.RoleBindings = list.Items
	} else {
		log.Printf("[collector] rolebindings: %v", err)
	}

	if list, err := client.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{}); err == nil {
		s.NetworkPolicies = list.Items
	} else {
		log.Printf("[collector] networkpolicies: %v", err)
	}

	if list, err := client.CoreV1().Services("").List(ctx, metav1.ListOptions{}); err == nil {
		for i := range list.Items {
			stripMeta(&list.Items[i].ObjectMeta)
		}
		s.Services = list.Items
	} else {
		log.Printf("[collector] services: %v", err)
	}

	if list, err := client.CoreV1().Secrets("").List(ctx, metav1.ListOptions{}); err == nil {
		for _, sec := range list.Items {
			s.Secrets = append(s.Secrets, SecretMeta{
				Name:      sec.Name,
				Namespace: sec.Namespace,
				Type:      string(sec.Type),
				Labels:    sec.Labels,
				CreatedAt: sec.CreationTimestamp.Time,
			})
		}
	} else {
		log.Printf("[collector] secrets: %v", err)
	}

	if list, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{}); err == nil {
		s.MutatingWebhooks = list.Items
	} else {
		log.Printf("[collector] mutatingwebhooks: %v", err)
	}

	if list, err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{}); err == nil {
		s.ValidatingWebhooks = list.Items
	} else {
		log.Printf("[collector] validatingwebhooks: %v", err)
	}

	if cfg != nil {
		dynClient, dynErr := dynamic.NewForConfig(cfg)
		if dynErr != nil {
			log.Printf("[collector] crds: dynamic client init failed: %v", dynErr)
		} else {
			crdGVR := schema.GroupVersionResource{
				Group:    "apiextensions.k8s.io",
				Version:  "v1",
				Resource: "customresourcedefinitions",
			}
			list, listErr := dynClient.Resource(crdGVR).List(ctx, metav1.ListOptions{})
			if listErr != nil {
				log.Printf("[collector] crds: list failed (check RBAC): %v", listErr)
			} else {
				log.Printf("[collector] crds: found %d", len(list.Items))
				for _, item := range list.Items {
					spec, _ := item.Object["spec"].(map[string]interface{})
					meta, _ := item.Object["metadata"].(map[string]interface{})
					names, _ := spec["names"].(map[string]interface{})
					versionsRaw, _ := spec["versions"].([]interface{})
					var versions []string
					for _, v := range versionsRaw {
						if vm, ok := v.(map[string]interface{}); ok {
							if name, ok := vm["name"].(string); ok {
								versions = append(versions, name)
							}
						}
					}
					s.CRDs = append(s.CRDs, CRDMeta{
						Name:      getString(meta, "name"),
						Group:     getString(spec, "group"),
						Kind:      getString(names, "kind"),
						Plural:    getString(names, "plural"),
						Scope:     getString(spec, "scope"),
						Versions:  versions,
						CreatedAt: getString(meta, "creationTimestamp"),
					})
				}
			}
		}
	}

	log.Printf("[collector] snapshot: %d nodes, %d pods, %d deployments, %d sts, %d ds, %d crds",
		len(s.Nodes), len(s.Pods), len(s.Deployments), len(s.StatefulSets), len(s.DaemonSets), len(s.CRDs))

	return s, nil
}

func RunLoop(ctx context.Context, client kubernetes.Interface, cfg *rest.Config, interval time.Duration, store func(*Snapshot)) {
	timeoutSec := envInt("SENSOR_COLLECT_TIMEOUT_SEC", 45)
	snap, err := collectWithTimeout(ctx, client, cfg, time.Duration(timeoutSec)*time.Second)
	if err == nil {
		store(snap)
	} else {
		log.Printf("[collector] initial collect error: %v", err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if snap, err := collectWithTimeout(ctx, client, cfg, time.Duration(timeoutSec)*time.Second); err == nil {
				store(snap)
			} else {
				log.Printf("[collector] periodic collect error: %v", err)
			}
		}
	}
}

func collectWithTimeout(ctx context.Context, client kubernetes.Interface, cfg *rest.Config, timeout time.Duration) (*Snapshot, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return Collect(cctx, client, cfg)
}

func getString(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func listPodsChunked(ctx context.Context, client kubernetes.Interface, chunkSize int64) ([]corev1.Pod, error) {
	out := make([]corev1.Pod, 0, 1024)
	continueToken := ""

	for {
		list, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
			Limit:    chunkSize,
			Continue: continueToken,
		})
		if err != nil {
			return nil, err
		}

		for i := range list.Items {
			stripMeta(&list.Items[i].ObjectMeta)
			stripPodNoise(&list.Items[i])
		}
		out = append(out, list.Items...)

		if list.Continue == "" {
			break
		}
		continueToken = list.Continue
	}

	log.Printf("[collector] pods: fetched %d in chunks of %d", len(out), chunkSize)
	return out, nil
}

func stripMeta(m *metav1.ObjectMeta) {
	m.ManagedFields = nil
	if m.Annotations != nil {
		delete(m.Annotations, "kubectl.kubernetes.io/last-applied-configuration")
		if len(m.Annotations) == 0 {
			m.Annotations = nil
		}
	}
}

func stripPodNoise(p *corev1.Pod) {
	p.Status.Conditions = nil
	p.Status.ContainerStatuses = nil
	p.Status.InitContainerStatuses = nil
	p.Status.EphemeralContainerStatuses = nil
}
