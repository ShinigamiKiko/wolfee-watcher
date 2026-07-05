package k8s

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metricsv1beta1 "k8s.io/metrics/pkg/apis/metrics/v1beta1"
)

type PodDetail struct {
	Name            string `json:"name"`
	Phase           string `json:"phase"`
	Ready           bool   `json:"ready"`
	Restarts        int32  `json:"restarts"`
	OOMKilled       bool   `json:"oom_killed"`
	CPUMilli        int64  `json:"cpu_milli"`
	MemBytes        int64  `json:"mem_bytes"`
	HasMetrics      bool   `json:"has_metrics"`
	CPURequestMilli int64  `json:"cpu_request_milli"`
	MemRequestBytes int64  `json:"mem_request_bytes"`
	Node            string `json:"node"`
	AgeSec          int64  `json:"age_sec"`
}

type PVCInfo struct {
	Name          string `json:"name"`
	StorageClass  string `json:"storage_class,omitempty"`
	CapacityBytes int64  `json:"capacity_bytes"`
	Phase         string `json:"phase"`
}

type ComponentMetrics struct {
	ID            string      `json:"id"`
	Label         string      `json:"label"`
	Kind          string      `json:"kind"`
	PodsReady     int32       `json:"pods_ready"`
	PodsTotal     int32       `json:"pods_total"`
	RestartsTotal int32       `json:"restarts_total"`
	CPUMilli      int64       `json:"cpu_milli"`
	MemBytes      int64       `json:"mem_bytes"`
	Error         string      `json:"error,omitempty"`
	Pods          []PodDetail `json:"pods"`
}

type NodeMetric struct {
	Name           string `json:"name"`
	CPUMilli       int64  `json:"cpu_milli"`
	MemBytes       int64  `json:"mem_bytes"`
	Ready          bool   `json:"ready"`
	MemoryPressure bool   `json:"memory_pressure"`
	DiskPressure   bool   `json:"disk_pressure"`
	PIDPressure    bool   `json:"pid_pressure"`
}

type K8sMetricsResult struct {
	Components []ComponentMetrics `json:"components"`
	Nodes      []NodeMetric       `json:"nodes"`
	PVCs       []PVCInfo          `json:"pvcs"`
	TS         int64              `json:"ts"`
}

type ComponentSpec struct {
	ID    string
	Label string
	Kind  string
	Name  string
}

func (pc *PodCache) K8sMetrics(ns string, comps []ComponentSpec) K8sMetricsResult {
	res := K8sMetricsResult{TS: time.Now().Unix()}
	if pc.cs == nil {
		return res
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type msEntry struct{ cpu, mem int64 }
	msMap := map[string]msEntry{}
	if pc.mc != nil {
		mCtx, mCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer mCancel()
		var podMetricsList *metricsv1beta1.PodMetricsList
		var err error
		if ns != "" {
			podMetricsList, err = pc.mc.MetricsV1beta1().PodMetricses(ns).List(mCtx, metav1.ListOptions{})
		} else {
			podMetricsList, err = pc.mc.MetricsV1beta1().PodMetricses("").List(mCtx, metav1.ListOptions{})
		}
		if err == nil {
			for _, pm := range podMetricsList.Items {
				var cpu, mem resource.Quantity
				for _, c := range pm.Containers {
					cpu.Add(c.Usage[corev1.ResourceCPU])
					mem.Add(c.Usage[corev1.ResourceMemory])
				}
				msMap[pm.Namespace+"/"+pm.Name] = msEntry{cpu: cpu.MilliValue(), mem: mem.Value()}
			}
		}
		nodeMetricsList, nerr := pc.mc.MetricsV1beta1().NodeMetricses().List(mCtx, metav1.ListOptions{})
		if nerr == nil {
			for _, nm := range nodeMetricsList.Items {
				cpu := nm.Usage[corev1.ResourceCPU]
				mem := nm.Usage[corev1.ResourceMemory]
				res.Nodes = append(res.Nodes, NodeMetric{
					Name:     nm.Name,
					CPUMilli: cpu.MilliValue(),
					MemBytes: mem.Value(),
				})
			}
		}
	}

	nodeIdx := map[string]int{}
	for i, n := range res.Nodes {
		nodeIdx[n.Name] = i
	}
	nodeAPIList, nErr := pc.cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if nErr == nil {
		for _, n := range nodeAPIList.Items {
			nm := NodeMetric{Name: n.Name}
			if idx, ok := nodeIdx[n.Name]; ok {
				nm = res.Nodes[idx]
			}
			for _, cond := range n.Status.Conditions {
				switch cond.Type {
				case corev1.NodeReady:
					nm.Ready = cond.Status == corev1.ConditionTrue
				case corev1.NodeMemoryPressure:
					nm.MemoryPressure = cond.Status == corev1.ConditionTrue
				case corev1.NodeDiskPressure:
					nm.DiskPressure = cond.Status == corev1.ConditionTrue
				case corev1.NodePIDPressure:
					nm.PIDPressure = cond.Status == corev1.ConditionTrue
				}
			}
			if idx, ok := nodeIdx[n.Name]; ok {
				res.Nodes[idx] = nm
			} else {
				res.Nodes = append(res.Nodes, nm)
				nodeIdx[n.Name] = len(res.Nodes) - 1
			}
		}
	}

	pvcList, pvcErr := pc.cs.CoreV1().PersistentVolumeClaims(ns).List(ctx, metav1.ListOptions{})
	if pvcErr == nil {
		for _, pvc := range pvcList.Items {
			info := PVCInfo{Name: pvc.Name, Phase: string(pvc.Status.Phase)}
			if pvc.Spec.StorageClassName != nil {
				info.StorageClass = *pvc.Spec.StorageClassName
			}
			if cap, ok := pvc.Status.Capacity[corev1.ResourceStorage]; ok {
				info.CapacityBytes = cap.Value()
			}
			res.PVCs = append(res.PVCs, info)
		}
	}

	now := time.Now()
	for _, spec := range comps {
		cm := ComponentMetrics{ID: spec.ID, Label: spec.Label, Kind: spec.Kind}
		selector, errSel := pc.podSelector(ctx, ns, spec.Name, spec.Kind)
		if errSel != nil {
			cm.Error = errSel.Error()
			res.Components = append(res.Components, cm)
			continue
		}
		podList, errList := pc.cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
		if errList != nil {
			cm.Error = errList.Error()
			res.Components = append(res.Components, cm)
			continue
		}
		for _, p := range podList.Items {
			ready := false
			for _, cond := range p.Status.Conditions {
				if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
					ready = true
				}
			}
			var restarts int32
			oomKilled := false
			for _, cs := range p.Status.ContainerStatuses {
				restarts += cs.RestartCount
				if cs.LastTerminationState.Terminated != nil && cs.LastTerminationState.Terminated.Reason == "OOMKilled" {
					oomKilled = true
				}
			}
			if !oomKilled {
				for _, cs := range p.Status.InitContainerStatuses {
					if cs.LastTerminationState.Terminated != nil && cs.LastTerminationState.Terminated.Reason == "OOMKilled" {
						oomKilled = true
					}
				}
			}
			var cpuReq, memReq resource.Quantity
			for _, c := range p.Spec.Containers {
				if r := c.Resources.Requests[corev1.ResourceCPU]; !r.IsZero() {
					cpuReq.Add(r)
				}
				if r := c.Resources.Requests[corev1.ResourceMemory]; !r.IsZero() {
					memReq.Add(r)
				}
			}
			ms, hasMs := msMap[p.Namespace+"/"+p.Name]
			age := int64(0)
			if !p.CreationTimestamp.IsZero() {
				age = int64(now.Sub(p.CreationTimestamp.Time).Seconds())
			}
			pd := PodDetail{
				Name:            p.Name,
				Phase:           string(p.Status.Phase),
				Ready:           ready,
				Restarts:        restarts,
				OOMKilled:       oomKilled,
				Node:            p.Spec.NodeName,
				AgeSec:          age,
				HasMetrics:      hasMs,
				CPURequestMilli: cpuReq.MilliValue(),
				MemRequestBytes: memReq.Value(),
			}
			if hasMs {
				pd.CPUMilli = ms.cpu
				pd.MemBytes = ms.mem
			}
			cm.Pods = append(cm.Pods, pd)
			cm.PodsTotal++
			if ready {
				cm.PodsReady++
			}
			cm.RestartsTotal += restarts
			cm.CPUMilli += pd.CPUMilli
			cm.MemBytes += pd.MemBytes
		}
		res.Components = append(res.Components, cm)
	}
	return res
}

func (pc *PodCache) podSelector(ctx context.Context, ns, name, kind string) (string, error) {
	switch kind {
	case "deployment":
		d, err := pc.cs.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return "", err
		}
		return metav1.FormatLabelSelector(d.Spec.Selector), nil
	case "daemonset":
		d, err := pc.cs.AppsV1().DaemonSets(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return "", err
		}
		return metav1.FormatLabelSelector(d.Spec.Selector), nil
	case "statefulset":
		s, err := pc.cs.AppsV1().StatefulSets(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return "", err
		}
		return metav1.FormatLabelSelector(s.Spec.Selector), nil
	default:
		return "", nil
	}
}
