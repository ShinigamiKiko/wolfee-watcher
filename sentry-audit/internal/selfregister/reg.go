package selfregister

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	webhookConfigName = "wolfee-watcher-sentry-audit"
	namespace         = "wolfee-watcher"
	serviceName       = "sentry-audit"
	secretName        = "sentry-audit-tls"
)

type CertBundle struct {
	TLSConfig *tls.Config
	CAPem     []byte
}

func GenerateCert(dnsNames []string) (*CertBundle, error) {

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sentry-audit-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	srvKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate server key: %w", err)
	}
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: serviceName},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create server cert: %w", err)
	}
	srvPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(srvKey)})

	tlsCert, err := tls.X509KeyPair(srvPEM, srvKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse TLS keypair: %w", err)
	}

	return &CertBundle{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{tlsCert}, MinVersion: tls.VersionTLS12},
		CAPem:     caPEM,
	}, nil
}

func StoreCertSecret(ctx context.Context, client kubernetes.Interface, cert *CertBundle, certPEM, keyPEM []byte) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": certPEM, "tls.key": keyPEM, "ca.crt": cert.CAPem},
	}
	_, err := client.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
	if k8serrors.IsAlreadyExists(err) {
		_, err = client.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
	}
	return err
}

func LoadOrCreateCert(ctx context.Context, client kubernetes.Interface, dnsNames []string) (*CertBundle, error) {
	var secret *corev1.Secret
	var err error

	for attempt := 1; attempt <= 10; attempt++ {
		secret, err = client.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
		if err == nil || k8serrors.IsNotFound(err) {
			break
		}
		log.Printf("[sentry-audit] K8s API not ready (attempt %d/10): %v — retrying in 3s", attempt, err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	if err != nil && !k8serrors.IsNotFound(err) {
		return nil, fmt.Errorf("get secret %q: %w", secretName, err)
	}

	if err == nil {

		certPEM := secret.Data["tls.crt"]
		keyPEM := secret.Data["tls.key"]
		caPEM := secret.Data["ca.crt"]
		if len(certPEM) == 0 || len(keyPEM) == 0 || len(caPEM) == 0 {
			return nil, fmt.Errorf("secret %q exists but is missing tls.crt / tls.key / ca.crt", secretName)
		}
		tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("parse cert from secret: %w", err)
		}
		log.Printf("[sentry-audit] loaded TLS cert from secret %q", secretName)
		return &CertBundle{
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{tlsCert}, MinVersion: tls.VersionTLS12},
			CAPem:     caPEM,
		}, nil
	}

	bundle, certPEM, keyPEM, err := generateCertPEM(dnsNames)
	if err != nil {
		return nil, err
	}

	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": certPEM, "tls.key": keyPEM, "ca.crt": bundle.CAPem},
	}
	if _, err := client.CoreV1().Secrets(namespace).Create(ctx, s, metav1.CreateOptions{}); err != nil {
		if k8serrors.IsAlreadyExists(err) {

			return LoadOrCreateCert(ctx, client, dnsNames)
		}
		return nil, fmt.Errorf("create TLS secret: %w", err)
	}
	log.Printf("[sentry-audit] generated new TLS cert and saved to secret %q", secretName)
	return bundle, nil
}

func generateCertPEM(dnsNames []string) (*CertBundle, []byte, []byte, error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate CA key: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sentry-audit-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create CA cert: %w", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	srvKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate server key: %w", err)
	}
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: serviceName},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create server cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(srvKey)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse TLS keypair: %w", err)
	}
	return &CertBundle{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{tlsCert}, MinVersion: tls.VersionTLS12},
		CAPem:     caPEM,
	}, certPEM, keyPEM, nil
}

func Register(ctx context.Context, client kubernetes.Interface, caBundle []byte) error {
	ignore := admissionv1.Ignore
	none := admissionv1.SideEffectClassNone
	svcRef := admissionv1.ServiceReference{
		Namespace: namespace,
		Name:      serviceName,
	}
	validatePath := "/validate"
	eventsPath := "/events"
	svcRef2 := svcRef
	svcRefValidate := svcRef
	svcRefValidate.Path = &validatePath
	svcRef2.Path = &eventsPath

	timeout := int32(12)

	cfg := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: webhookConfigName},
		Webhooks: []admissionv1.ValidatingWebhook{
			{

				Name:                    "policyeval.wolfee-watcher.io",
				AdmissionReviewVersions: []string{"v1"},
				SideEffects:             &none,
				FailurePolicy:           &ignore,
				TimeoutSeconds:          &timeout,
				ClientConfig: admissionv1.WebhookClientConfig{
					Service:  &svcRefValidate,
					CABundle: caBundle,
				},
				Rules: []admissionv1.RuleWithOperations{

					{
						Operations: []admissionv1.OperationType{admissionv1.OperationAll},
						Rule: admissionv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources: []string{
								"pods",
								"secrets",
								"configmaps",
								"namespaces",
								"nodes",
								"serviceaccounts",
							},
						},
					},

					{
						Operations: []admissionv1.OperationType{admissionv1.OperationAll},
						Rule: admissionv1.Rule{
							APIGroups:   []string{"apps"},
							APIVersions: []string{"v1"},
							Resources:   []string{"deployments", "daemonsets", "statefulsets"},
						},
					},

					{
						Operations: []admissionv1.OperationType{admissionv1.OperationAll},
						Rule: admissionv1.Rule{
							APIGroups:   []string{"batch"},
							APIVersions: []string{"v1"},
							Resources:   []string{"jobs", "cronjobs"},
						},
					},

					{
						Operations: []admissionv1.OperationType{admissionv1.OperationAll},
						Rule: admissionv1.Rule{
							APIGroups:   []string{"rbac.authorization.k8s.io"},
							APIVersions: []string{"v1"},
							Resources: []string{
								"roles",
								"clusterroles",
								"rolebindings",
								"clusterrolebindings",
							},
						},
					},

					{
						Operations: []admissionv1.OperationType{admissionv1.OperationAll},
						Rule: admissionv1.Rule{
							APIGroups:   []string{"admissionregistration.k8s.io"},
							APIVersions: []string{"v1"},
							Resources: []string{
								"mutatingwebhookconfigurations",
								"validatingwebhookconfigurations",
							},
						},
					},
				},

				NamespaceSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "kubernetes.io/metadata.name",
							Operator: metav1.LabelSelectorOpNotIn,
							Values:   []string{"kube-system", "kube-public", "kube-node-lease"},
						},
					},
				},
			},
			{

				Name:                    "k8sevents.wolfee-watcher.io",
				AdmissionReviewVersions: []string{"v1"},
				SideEffects:             &none,
				FailurePolicy:           &ignore,
				TimeoutSeconds:          &timeout,
				ClientConfig: admissionv1.WebhookClientConfig{
					Service:  &svcRef2,
					CABundle: caBundle,
				},
				Rules: []admissionv1.RuleWithOperations{
					{
						Operations: []admissionv1.OperationType{admissionv1.Connect},
						Rule: admissionv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods/exec", "pods/attach", "pods/portforward", "pods/proxy"},
						},
					},
				},
			},
		},
	}

	_, err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Create(ctx, cfg, metav1.CreateOptions{})
	if k8serrors.IsAlreadyExists(err) {
		existing, getErr := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, webhookConfigName, metav1.GetOptions{})
		if getErr != nil {
			return fmt.Errorf("get existing webhook config: %w", getErr)
		}
		cfg.ResourceVersion = existing.ResourceVersion
		_, err = client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Update(ctx, cfg, metav1.UpdateOptions{})
	}
	if err != nil {
		return fmt.Errorf("upsert webhook config: %w", err)
	}
	log.Printf("[sentry-audit] ValidatingWebhookConfiguration %q registered", webhookConfigName)
	return nil
}
