package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAlertLogUsesPushIdentityInsteadOfBody(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	for _, body := range []string{
		`{"clusterId":"spoofed","clusterName":"Wrong cluster","id":99,"severity":"HIGH","source":"tracee-bridge","namespace":"prod","target":"api-123"}`,
		`{"alerts":[{"clusterId":"spoofed","clusterName":"Wrong cluster","id":99,"severity":"HIGH","source":"tracee-bridge","namespace":"prod","target":"api-123"}]}`,
	} {
		var output bytes.Buffer
		slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
		req := httptest.NewRequest(http.MethodPost, "/internal/alert-log", strings.NewReader(body))
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{
			{Subject: pkix.Name{OrganizationalUnit: []string{"cluster:prod-eu"}}},
		}}
		rec := httptest.NewRecorder()
		handleAlertLog(nil, rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var logged map[string]any
		if err := json.Unmarshal(output.Bytes(), &logged); err != nil {
			t.Fatal(err)
		}
		if logged["cluster.id"] != "prod-eu" || logged["cluster.name"] != "prod-eu" {
			t.Fatalf("push identity = %#v", logged)
		}
		if _, exists := logged["alert.id"]; exists {
			t.Fatal("sender cannot claim a database alert ID")
		}
		if strings.Contains(output.String(), "spoofed") || strings.Contains(output.String(), "Wrong cluster") {
			t.Fatal("body overrode authenticated cluster identity")
		}
	}
}
