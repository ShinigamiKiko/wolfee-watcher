package mapper

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

type TraceeEvent struct {
	Timestamp      int64  `json:"timestamp"`
	ProcessID      int    `json:"processId"`
	HostProcessID  int    `json:"hostProcessId"`
	UserID         int    `json:"userId"`
	ProcessName    string `json:"processName"`
	HostName       string `json:"hostName"`
	ContainerID    string `json:"containerId"`
	ContainerImage string `json:"containerImage"`
	ContainerName  string `json:"containerName"`

	Container *TraceeContainerContext `json:"container"`

	PodName      string `json:"podName"`
	PodNamespace string `json:"podNamespace"`
	PodUID       string `json:"podUID"`

	Kubernetes  *TraceeK8sContext `json:"kubernetes"`
	EventName   string            `json:"eventName"`
	ReturnValue int               `json:"returnValue"`
	Args        []TraceeArg       `json:"args"`
}

type TraceeContainerContext struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Image string `json:"image"`
}

type TraceeK8sContext struct {
	PodName      string `json:"podName"`
	PodNamespace string `json:"podNamespace"`
	PodUID       string `json:"podUID"`
}

type TraceeArg struct {
	Name  string      `json:"name"`
	Type  string      `json:"type"`
	Value interface{} `json:"value"`
}

type UIEvent struct {
	ID          int64                  `json:"id"`
	Ts          time.Time              `json:"ts"`
	Syscall     string                 `json:"syscall"`
	Namespace   string                 `json:"namespace"`
	Pod         string                 `json:"pod"`
	Node        string                 `json:"node"`
	Container   string                 `json:"container"`
	ContainerID string                 `json:"containerId"`
	Image       string                 `json:"image"`
	PID         int                    `json:"pid"`
	UID         int                    `json:"uid"`
	Process     string                 `json:"process"`
	Execpath    string                 `json:"execpath"`
	Cmdline     string                 `json:"cmdline"`
	Args        map[string]interface{} `json:"args,omitempty"`

	Severity string `json:"severity,omitempty"`
	Category string `json:"category,omitempty"`
}

var DroppedSysNs atomic.Int64

var systemNamespaces = map[string]bool{
	"kube-system":      true,
	"kube-public":      true,
	"kube-node-lease":  true,
	"calico-system":    true,
	"calico-apiserver": true,
	"cilium":           true,
	"cert-manager":     true,
	"monitoring":       true,
	"ingress-nginx":    true,
}

var globalID atomic.Int64

func Map(t *TraceeEvent) *UIEvent {

	podName := t.PodName
	podNS := t.PodNamespace
	if t.Kubernetes != nil {
		if t.Kubernetes.PodName != "" {
			podName = t.Kubernetes.PodName
		}
		if t.Kubernetes.PodNamespace != "" {
			podNS = t.Kubernetes.PodNamespace
		}
	}

	containerName := t.ContainerName
	containerID := t.ContainerID
	containerImage := t.ContainerImage
	if t.Container != nil {
		if t.Container.Name != "" {
			containerName = t.Container.Name
		}
		if t.Container.ID != "" {
			containerID = t.Container.ID
		}
		if t.Container.Image != "" {
			containerImage = t.Container.Image
		}
	}
	_ = containerID

	if podNS != "" && systemNamespaces[podNS] {
		DroppedSysNs.Add(1)
		return nil
	}

	args := argsMap(t.Args)
	process := t.ProcessName
	execpath := ""
	cmdline := ""

	switch t.EventName {
	case "execve", "execveat", "sched_process_exec":

		for _, name := range []string{"pathname", "cmdpath", "filepath"} {
			if p := anyStringArg(t.Args, name); p != "" {
				execpath = p
				process = basename(p)
				break
			}
		}
		if argv, ok := args["argv"].([]interface{}); ok {
			parts := make([]string, 0, len(argv))
			for _, a := range argv {
				if s, ok := a.(string); ok {
					parts = append(parts, s)
				}
			}
			cmdline = strings.Join(parts, " ")
		}

	case "openat", "open":
		if p := stringArg(t.Args, "pathname"); p != "" && !isNumeric(p) {
			execpath = p
			cmdline = p
		}

	case "socket":

		for _, a := range t.Args {
			if a.Name == "domain" {
				switch v := a.Value.(type) {
				case float64:
					cmdline = fmt.Sprintf("%d", int(v))
				case string:

					cmdline = afToNum(v)
				}
			}
		}

	case "connect":

		for _, a := range t.Args {
			if a.Name != "addr" {
				continue
			}
			addr, ok := a.Value.(map[string]interface{})
			if !ok {
				break
			}
			sa, _ := addr["sa_family"].(string)
			if sa != "AF_INET" && sa != "AF_INET6" {

				return nil
			}

			ip, _ := addr["sin_addr"].(string)
			if ip == "" {
				ip, _ = addr["sin6_addr"].(string)
			}
			if ip != "" {
				cmdline = ip
			}
		}

	case "mount", "security_sb_mount":

		src := stringArg(t.Args, "source")
		tgt := stringArg(t.Args, "target")
		fs := stringArg(t.Args, "filesystemtype")
		if tgt != "" {
			if src != "" && fs != "" {
				cmdline = fmt.Sprintf("%s→%s (%s)", src, tgt, fs)
			} else if src != "" {
				cmdline = fmt.Sprintf("%s→%s", src, tgt)
			} else {
				cmdline = tgt
			}
			execpath = tgt
		}

	case "umount2":
		if tgt := stringArg(t.Args, "target"); tgt != "" {
			cmdline = tgt
			execpath = tgt
		}
	}

	if cmdline == "" {
		var parts []string
		for _, a := range t.Args {
			if s, ok := a.Value.(string); ok && s != "" && !isNumeric(s) {
				parts = append(parts, s)
			}
		}
		if len(parts) > 0 {
			cmdline = strings.Join(parts, " ")
		}
	}

	return &UIEvent{
		ID:          globalID.Add(1),
		Ts:          time.Unix(0, t.Timestamp),
		Syscall:     t.EventName,
		Namespace:   podNS,
		Pod:         podName,
		Node:        t.HostName,
		Container:   containerName,
		ContainerID: containerID,
		Image:       containerImage,
		PID:         t.HostProcessID,
		UID:         t.UserID,
		Process:     process,
		Execpath:    execpath,
		Cmdline:     cmdline,
		Args:        args,
	}
}

func argsMap(args []TraceeArg) map[string]interface{} {
	m := make(map[string]interface{}, len(args))
	for _, a := range args {
		m[a.Name] = a.Value
	}
	return m
}

func stringArg(args []TraceeArg, name string) string {
	for _, a := range args {
		if a.Name == name && a.Type == "string" {
			if s, ok := a.Value.(string); ok {
				return s
			}
		}
	}
	return ""
}

func anyStringArg(args []TraceeArg, name string) string {
	for _, a := range args {
		if a.Name == name {
			switch v := a.Value.(type) {
			case string:
				return v
			case map[string]interface{}:

				ip, _ := v["sin_addr"].(string)
				if ip == "" {
					ip, _ = v["sin6_addr"].(string)
				}
				port := ""
				if p, ok := v["sin_port"].(float64); ok && p > 0 {
					port = fmt.Sprintf("%.0f", p)
				}
				if ip != "" && port != "" {
					return ip + ":" + port
				}
				if ip != "" {
					return ip
				}
			}
		}
	}
	return ""
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

func basename(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

func afToNum(af string) string {
	switch af {
	case "AF_UNSPEC":
		return "0"
	case "AF_UNIX":
		return "1"
	case "AF_INET":
		return "2"
	case "AF_INET6":
		return "10"
	case "AF_NETLINK":
		return "16"
	case "AF_PACKET":
		return "17"
	case "AF_BLUETOOTH":
		return "31"
	default:
		return af
	}
}
