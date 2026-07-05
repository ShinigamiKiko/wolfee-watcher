package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/wolfee-watcher/pkg/mtls"
)

var services = []mtls.ServiceType{
	mtls.Sensor,
	mtls.TraceeBridge,
	mtls.AnomalyDetector,
	mtls.SentryAudit,
	mtls.ScannerAgent,
	mtls.AuditRunner,
	mtls.HoneyOperator,
	mtls.ForensicWatcher,
	mtls.Kvisior,
}

func main() {
	out := flag.String("out", "deploy/certs", "output directory for Secret YAML files")
	ns := flag.String("namespace", "wolfee-watcher", "Kubernetes namespace")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatalf("mkdir %s: %v", *out, err)
	}

	log.Println("generating CA...")
	caCert, caKey, err := mtls.GenerateCA()
	if err != nil {
		log.Fatalf("generate CA: %v", err)
	}

	caSecret := secretYAML("wolfee-watcher-ca-pub", *ns, map[string][]byte{
		"ca.crt": caCert,
	})
	writeFile(filepath.Join(*out, "00-ca-secret.yaml"), caSecret)
	log.Println("  wrote 00-ca-secret.yaml (CA cert only, for all services)")

	caKeySecret := secretYAML("wolfee-watcher-ca", *ns, map[string][]byte{
		"ca.crt": caCert,
		"ca.key": caKey,
	})
	writeFile(filepath.Join(*out, "00-ca-key-secret.yaml"), caKeySecret)
	log.Println("  wrote 00-ca-key-secret.yaml (CA cert+key, cert-server only — guard this!)")

	for i, svc := range services {
		log.Printf("issuing cert for %s...", svc)
		cert, key, err := mtls.IssueServiceCert(caCert, caKey, svc)
		if err != nil {
			log.Fatalf("issue cert for %s: %v", svc, err)
		}

		secretName := fmt.Sprintf("wolfee-watcher-mtls-%s", svc)
		secret := secretYAML(secretName, *ns, map[string][]byte{
			"ca.crt":  caCert,
			"tls.crt": cert,
			"tls.key": key,
		})
		fname := fmt.Sprintf("%02d-%s.yaml", i+1, svc)
		writeFile(filepath.Join(*out, fname), secret)
		log.Printf("  wrote %s", fname)
	}

	log.Println("\nDone! Add the following to each Deployment under spec.template.spec:")
	fmt.Println(deploySnippet(*ns))
}

func secretYAML(name, ns string, data map[string][]byte) []byte {

	_, hasCAKey := data["ca.key"]
	_, hasTLSCrt := data["tls.crt"]
	_, hasTLSKey := data["tls.key"]
	secretType := "Opaque"
	if hasTLSCrt && hasTLSKey && !hasCAKey {
		secretType = "kubernetes.io/tls"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: v1\nkind: Secret\nmetadata:\n  name: %s\n  namespace: %s\ntype: %s\ndata:\n", name, ns, secretType)
	for k, v := range data {
		fmt.Fprintf(&b, "  %s: %s\n", k, base64.StdEncoding.EncodeToString(v))
	}
	return []byte(b.String())
}

func writeFile(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Fatalf("write %s: %v", path, err)
	}
}

func deploySnippet(ns string) string {
	return `
# ── add to spec.template.spec ─────────────────────────────────────────────
volumes:
  - name: mtls-certs
    secret:
      secretName: wolfee-watcher-mtls-<SERVICE-NAME>   # e.g. wolfee-watcher-mtls-sensor

# ── add to each container ─────────────────────────────────────────────────
volumeMounts:
  - name: mtls-certs
    mountPath: /etc/wolfee-watcher/certs
    readOnly: true
env:
  - name: MTLS_CA_FILE
    value: /etc/wolfee-watcher/certs/ca.crt
  - name: MTLS_CERT_FILE
    value: /etc/wolfee-watcher/certs/tls.crt
  - name: MTLS_KEY_FILE
    value: /etc/wolfee-watcher/certs/tls.key
`
}
