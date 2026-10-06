package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"
)

const investigationDataLimit = 256 << 10

// ClusterLabel keeps the stable ID visible even when a display name is renamed.
func (a AlertLog) ClusterLabel() string {
	id := firstNonEmpty(a.ClusterID, "default")
	name := firstNonEmpty(a.ClusterName, id)
	if name == id {
		return id
	}
	return name + " (" + id + ")"
}

type InvestigationField struct {
	Label string
	Key   string
	Value string
}

type investigationSpec struct {
	label string
	key   string
	paths [][]string
}

var investigationSpecs = []investigationSpec{
	newInvestigationSpec("Pod", "kubernetes.pod.name", "src_pod", "pod", "podName"),
	newInvestigationSpec("Node", "host.name", "src_node", "node", "nodeName"),
	newInvestigationSpec("Container", "container.name", "src_container", "container", "containerName"),
	newInvestigationSpec("Process", "process.name", "src_process", "process", "processName"),
	newInvestigationSpec("Source IP", "source.ip", "src_ip", "sourceIP", "sourceIPs", "podIP", "sourceIp"),
	newInvestigationSpec("Source port", "source.port", "src_port", "sourcePort"),
	newInvestigationSpec("Destination IP", "destination.ip", "dst_ip", "dest_ip", "destinationIP", "args.addr.sin_addr", "args.addr.sin6_addr"),
	newInvestigationSpec("Destination port", "destination.port", "dst_port", "dest_port", "destinationPort", "args.addr.sin_port", "args.addr.sin6_port"),
	newInvestigationSpec("User", "user.name", "user.username", "user", "actor"),
	newInvestigationSpec("Process ID", "process.pid", "pid"),
	newInvestigationSpec("Container ID", "container.id", "containerId", "containerID"),
	newInvestigationSpec("Event ID", "event.id", "auditID", "auditId", "id"),
	newInvestigationSpec("Action", "event.action", "kind", "verb"),
	newInvestigationSpec("Resource", "resource.type", "resource", "objectRef.resource"),
}

func newInvestigationSpec(label, key string, paths ...string) investigationSpec {
	spec := investigationSpec{label: label, key: key}
	for _, path := range paths {
		spec.paths = append(spec.paths, strings.Split(path, "."))
	}
	return spec
}

// InvestigationFields deliberately reads only location and actor metadata.
// Request bodies, credentials and other raw payload fields are not exported.
func (a AlertLog) InvestigationFields() []InvestigationField {
	if len(a.Data) == 0 || len(a.Data) > investigationDataLimit {
		return nil
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(a.Data, &root) != nil || len(root) == 0 {
		return nil
	}
	objects := map[string]map[string]json.RawMessage{"": root}
	var fields []InvestigationField
	for _, spec := range investigationSpecs {
		for _, path := range spec.paths {
			if value := investigationValue(objects, path); value != "" {
				fields = append(fields, InvestigationField{Label: spec.label, Key: spec.key, Value: value})
				break
			}
		}
	}
	return fields
}

func investigationValue(objects map[string]map[string]json.RawMessage, path []string) string {
	object := objects[""]
	prefix := ""
	for _, part := range path[:len(path)-1] {
		if prefix == "" {
			prefix = part
		} else {
			prefix += "." + part
		}
		next, seen := objects[prefix]
		if !seen {
			if raw, ok := object[part]; ok && json.Unmarshal(raw, &next) != nil {
				next = nil
			}
			objects[prefix] = next
		}
		if next == nil {
			return ""
		}
		object = next
	}
	raw := bytes.TrimSpace(object[path[len(path)-1]])
	if len(raw) == 0 {
		return ""
	}
	switch raw[0] {
	case '"':
		return investigationString(raw)
	case '[':
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) != nil {
			return ""
		}
		for _, item := range items {
			if value := investigationString(bytes.TrimSpace(item)); value != "" {
				return value
			}
		}
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		var number json.Number
		if json.Unmarshal(raw, &number) == nil {
			return number.String()
		}
	}
	return ""
}

func investigationString(raw json.RawMessage) string {
	if len(raw) == 0 || raw[0] != '"' {
		return ""
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

// LogSecurityAlert is shared by the receiver, audit engine and DB fallbacks.
func LogSecurityAlert(ctx context.Context, component string, a AlertLog) {
	detType := strings.ToLower(firstNonEmpty(a.DetType, "alert"))
	severity := strings.ToUpper(strings.TrimSpace(a.Severity))
	id := firstNonEmpty(a.ClusterID, "default")
	attrs := []slog.Attr{
		slog.String("component", component),
		slog.String("event.kind", "alert"),
		slog.String("cluster.id", id),
		slog.String("cluster.name", firstNonEmpty(a.ClusterName, id)),
		slog.String("alert.type", detType),
		slog.String("alert.source", a.Source),
	}
	appendIf := func(key, value string) {
		if value != "" {
			attrs = append(attrs, slog.String(key, value))
		}
	}
	if a.ID > 0 {
		attrs = append(attrs, slog.Int64("alert.id", a.ID))
	}
	if !a.Timestamp.IsZero() {
		appendIf("event.created", a.Timestamp.UTC().Format(time.RFC3339Nano))
	}
	appendIf("rule.name", firstNonEmpty(a.RuleName, a.RuleID))
	appendIf("rule.id", a.RuleID)
	appendIf("alert.severity", severity)
	appendIf("namespace", a.Namespace)
	appendIf("target", a.Target)
	appendIf("syscall", a.Syscall)
	appendIf("detail", a.Detail)
	appendIf("alert.fingerprint", a.Fingerprint)
	for _, field := range a.InvestigationFields() {
		appendIf(field.Key, field.Value)
	}
	level := slog.LevelWarn
	switch severity {
	case "CRITICAL", "HIGH":
		level = slog.LevelError
	case "LOW", "INFO", "INFORMATIONAL":
		level = slog.LevelInfo
	}
	slog.LogAttrs(ctx, level, "security_alert", attrs...)
}
