package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ClusterLabel keeps the stable ID visible even when a display name is renamed.
func (a AlertLog) ClusterLabel() string {
	id := firstNonEmpty(a.ClusterID, "default")
	name := firstNonEmpty(a.ClusterName, id)
	if name == id {
		return id
	}
	return name + " (" + id + ")"
}

// ResolveClusterName falls back to the stable ID if registration or the DB is
// unavailable. The receiver and delivery worker determine identity, not Data.
func ResolveClusterName(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, id string) string {
	id = firstNonEmpty(id, "default")
	if db == nil {
		return id
	}
	var name string
	if err := db.QueryRow(ctx, "SELECT name FROM clusters WHERE id = $1", id).Scan(&name); err != nil {
		return id
	}
	return firstNonEmpty(name, id)
}

type InvestigationField struct {
	Label string
	Key   string
	Value string
}

// InvestigationFields deliberately reads only location and actor metadata.
// Request bodies, credentials and other raw payload fields are not exported.
func (a AlertLog) InvestigationFields() []InvestigationField {
	var data map[string]any
	decoder := json.NewDecoder(bytes.NewReader(a.Data))
	decoder.UseNumber()
	if decoder.Decode(&data) != nil {
		return nil
	}
	value := func(keys ...string) string {
		for _, key := range keys {
			var raw any = data
			for _, part := range strings.Split(key, ".") {
				object, ok := raw.(map[string]any)
				if !ok {
					raw = nil
					break
				}
				raw = object[part]
			}
			switch v := raw.(type) {
			case string:
				if v = strings.TrimSpace(v); v != "" {
					return v
				}
			case json.Number:
				return v.String()
			case []any:
				var items []string
				for _, item := range v {
					if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
						items = append(items, strings.TrimSpace(s))
					}
				}
				if len(items) > 0 {
					return items[0]
				}
			}
		}
		return ""
	}
	var fields []InvestigationField
	add := func(label, key string, keys ...string) {
		if v := value(keys...); v != "" {
			fields = append(fields, InvestigationField{Label: label, Key: key, Value: v})
		}
	}
	add("Pod", "kubernetes.pod.name", "src_pod", "pod", "podName")
	add("Node", "host.name", "src_node", "node", "nodeName")
	add("Container", "container.name", "src_container", "container", "containerName")
	add("Process", "process.name", "src_process", "process", "processName")
	add("Source IP", "source.ip", "src_ip", "sourceIP", "sourceIPs", "podIP", "sourceIp")
	add("Source port", "source.port", "src_port", "sourcePort")
	add("Destination IP", "destination.ip", "dst_ip", "dest_ip", "destinationIP", "args.addr.sin_addr", "args.addr.sin6_addr")
	add("Destination port", "destination.port", "dst_port", "dest_port", "destinationPort", "args.addr.sin_port", "args.addr.sin6_port")
	add("User", "user.name", "user.username", "user", "actor")
	add("Process ID", "process.pid", "pid")
	add("Container ID", "container.id", "containerId", "containerID")
	add("Event ID", "event.id", "auditID", "auditId", "id")
	add("Action", "event.action", "kind", "verb")
	add("Resource", "resource.type", "resource", "objectRef.resource")
	return fields
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
