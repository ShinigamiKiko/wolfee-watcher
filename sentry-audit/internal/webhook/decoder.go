package webhook

import (
	"encoding/json"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
)

type EventKind string

const (
	EventKindCreate      EventKind = "create"
	EventKindUpdate      EventKind = "update"
	EventKindDelete      EventKind = "delete"
	EventKindExec        EventKind = "exec"
	EventKindAttach      EventKind = "attach"
	EventKindPortForward EventKind = "portforward"
	EventKindUnknown     EventKind = "unknown"
)

type AuditEvent struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`

	User      string   `json:"user"`
	Groups    []string `json:"groups"`
	SourceIPs []string `json:"sourceIPs,omitempty"`

	Kind      EventKind `json:"kind"`
	Resource  string    `json:"resource"`
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`

	Container string   `json:"container,omitempty"`
	Commands  []string `json:"commands,omitempty"`
	Ports     []int32  `json:"ports,omitempty"`

	Allowed    bool  `json:"allowed"`
	StatusCode int32 `json:"statusCode,omitempty"`
}

func decodeKind(op admissionv1.Operation, resourceKind, subResource string) EventKind {
	if op == admissionv1.Connect {

		switch subResource {
		case "exec":
			return EventKindExec
		case "attach":
			return EventKindAttach
		case "portforward":
			return EventKindPortForward
		}

		switch resourceKind {
		case "PodExecOptions":
			return EventKindExec
		case "PodAttachOptions":
			return EventKindAttach
		case "PodPortForwardOptions":
			return EventKindPortForward
		}
		return EventKindUnknown
	}
	switch op {
	case admissionv1.Create:
		return EventKindCreate
	case admissionv1.Update:
		return EventKindUpdate
	case admissionv1.Delete:
		return EventKindDelete
	}
	return EventKindUnknown
}

func fromAdmissionRequest(req *admissionv1.AdmissionRequest) AuditEvent {
	ev := AuditEvent{
		ID:        string(req.UID),
		Timestamp: time.Now().UTC(),
		User:      req.UserInfo.Username,
		Groups:    req.UserInfo.Groups,
		Kind:      decodeKind(req.Operation, req.Kind.Kind, req.SubResource),
		Resource:  req.Resource.Resource,
		Namespace: req.Namespace,
		Name:      req.Name,
		Allowed:   true,
	}

	if ev.Kind == EventKindExec || ev.Kind == EventKindAttach {
		var opts corev1.PodExecOptions
		if len(req.Object.Raw) > 0 {
			if err := json.Unmarshal(req.Object.Raw, &opts); err == nil {
				ev.Container = opts.Container
				ev.Commands = opts.Command
			}
		}
	}

	if ev.Kind == EventKindPortForward {
		var opts corev1.PodPortForwardOptions
		if len(req.Object.Raw) > 0 {
			if err := json.Unmarshal(req.Object.Raw, &opts); err == nil {
				ev.Ports = opts.Ports
			}
		}
	}

	return ev
}
