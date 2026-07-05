package k8s

import (
	"context"
	"os"
	"path/filepath"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Client struct {
	cs *kubernetes.Clientset
}

func New() (*Client, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		home, _ := os.UserHomeDir()
		kc := filepath.Join(home, ".kube", "config")
		if ev := os.Getenv("KUBECONFIG"); ev != "" {
			kc = ev
		}
		cfg, err = clientcmd.BuildConfigFromFlags("", kc)
		if err != nil {
			return nil, err
		}
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{cs: cs}, nil
}

type ClusterInfo struct {
	Name       string `json:"name"`
	K8sVersion string `json:"k8sVersion"`
	NodeCount  int    `json:"nodeCount"`
}

func (c *Client) ClusterInfo(ctx context.Context) ClusterInfo {
	info := ClusterInfo{Name: "wolfee-watcher", K8sVersion: "—"}

	if ver, err := c.cs.Discovery().ServerVersion(); err == nil {
		info.K8sVersion = ver.GitVersion
	}

	if nodes, err := c.cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{}); err == nil {
		info.NodeCount = len(nodes.Items)
		for _, n := range nodes.Items {
			if cl := n.Labels["alpha.eksctl.io/cluster-name"]; cl != "" {
				info.Name = cl
				break
			}
			if cl := n.Labels["cluster.x-k8s.io/cluster-name"]; cl != "" {
				info.Name = cl
				break
			}
			if cl := n.Labels["topology.kubernetes.io/region"]; cl != "" {
				info.Name = "k8s-" + cl
				break
			}
		}
	}
	return info
}
