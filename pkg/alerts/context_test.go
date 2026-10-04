package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type clusterNameTestRow struct {
	name string
	err  error
}

func (r clusterNameTestRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*dest[0].(*string) = r.name
	return nil
}

type clusterNameTestDB struct {
	row clusterNameTestRow
	id  string
}

func (db *clusterNameTestDB) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	db.id = args[0].(string)
	return db.row
}

func TestResolveClusterNameFallbacksAndRename(t *testing.T) {
	ctx := context.Background()
	if got := ResolveClusterName(ctx, nil, ""); got != "default" {
		t.Fatalf("unconfigured cluster = %q", got)
	}
	db := &clusterNameTestDB{row: clusterNameTestRow{name: " Production EU "}}
	if got := ResolveClusterName(ctx, db, " prod-eu "); got != "Production EU" || db.id != "prod-eu" {
		t.Fatalf("name = %q, queried ID = %q", got, db.id)
	}
	db.row.name = "Renamed EU"
	if got := ResolveClusterName(ctx, db, "prod-eu"); got != "Renamed EU" {
		t.Fatalf("renamed cluster = %q", got)
	}
	for _, row := range []clusterNameTestRow{
		{name: "   "},
		{err: pgx.ErrNoRows},
		{err: errors.New("database unavailable")},
	} {
		db.row = row
		if got := ResolveClusterName(ctx, db, "prod-eu"); got != "prod-eu" {
			t.Fatalf("fallback = %q", got)
		}
	}
}

func TestInvestigationFieldsReadKnownEventShapes(t *testing.T) {
	cases := []struct {
		name string
		data string
		want map[string]string
	}{
		{
			name: "runtime",
			data: `{"pod":"api-123","node":"worker-2","container":"api","containerId":"abc","process":"sh","pid":42,"args":{"addr":{"sin_addr":"203.0.113.20","sin_port":443}},"password":"do-not-export","requestObject":{"token":"do-not-export"}}`,
			want: map[string]string{
				"kubernetes.pod.name": "api-123", "host.name": "worker-2",
				"container.name": "api", "container.id": "abc", "process.name": "sh",
				"process.pid": "42", "destination.ip": "203.0.113.20", "destination.port": "443",
			},
		},
		{
			name: "anomaly",
			data: `{"src_pod":"api-123","src_node":"worker-2","src_process":"curl","src_ip":"10.0.0.8","dst_ip":"203.0.113.20","dst_port":8443}`,
			want: map[string]string{
				"kubernetes.pod.name": "api-123", "host.name": "worker-2",
				"process.name": "curl", "source.ip": "10.0.0.8",
				"destination.ip": "203.0.113.20", "destination.port": "8443",
			},
		},
		{
			name: "audit",
			data: `{"user":"system:serviceaccount:prod:api","sourceIPs":["198.51.100.9","10.0.0.1"],"auditID":"audit-123","kind":"exec","resource":"pods"}`,
			want: map[string]string{
				"user.name": "system:serviceaccount:prod:api", "source.ip": "198.51.100.9",
				"event.id": "audit-123", "event.action": "exec", "resource.type": "pods",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := map[string]string{}
			for _, field := range (AlertLog{Data: json.RawMessage(tc.data)}).InvestigationFields() {
				got[field.Key] = field.Value
				if strings.Contains(field.Value, "do-not-export") {
					t.Fatal("raw credentials were exported as context")
				}
			}
			for key, want := range tc.want {
				if got[key] != want {
					t.Errorf("%s = %q, want %q", key, got[key], want)
				}
			}
		})
	}
}

func TestInvestigationFieldsIgnoreInvalidData(t *testing.T) {
	for _, data := range []string{"", "{", "null", "[]", `{"pod":{},"node":true}`} {
		if got := (AlertLog{Data: json.RawMessage(data)}).InvestigationFields(); len(got) != 0 {
			t.Fatalf("context for %q = %#v", data, got)
		}
	}
}

func TestSecurityLogIncludesClusterAndInvestigationContext(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	ts := time.Date(2026, 10, 4, 12, 0, 0, 0, time.FixedZone("UTC+3", 3*60*60))
	LogSecurityAlert(context.Background(), "test/alert", AlertLog{
		ClusterID: "prod-eu", ClusterName: "Production EU", Timestamp: ts,
		RuleID: "shell", RuleName: "Shell spawned", Severity: " high ",
		Source: "tracee-bridge", DetType: "Runtime", Namespace: "prod", Target: "api-123",
		Data: json.RawMessage(`{"node":"worker-2","pod":"api-123","process":"sh","clusterId":"spoofed","password":"do-not-export"}`),
	})
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"msg": "security_alert", "level": "ERROR", "cluster.id": "prod-eu",
		"cluster.name": "Production EU", "event.created": "2026-10-04T09:00:00Z",
		"rule.id": "shell", "alert.severity": "HIGH", "namespace": "prod",
		"target": "api-123", "host.name": "worker-2", "process.name": "sh",
	} {
		if record[key] != want {
			t.Errorf("%s = %v, want %q", key, record[key], want)
		}
	}
	if strings.Contains(output.String(), "spoofed") || strings.Contains(output.String(), "do-not-export") {
		t.Fatal("untrusted identity or raw credentials leaked into the security log")
	}
}
