package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

const (
	caCommonName = "Wolfee-Watcher Certificate Authority"
	caOrg        = "Wolfee-Watcher"
	caExpiry     = 10 * 365 * 24 * time.Hour
	certExpiry   = 2 * 365 * 24 * time.Hour
)

func GenerateCA() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("mtls: generate CA key: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   caCommonName,
			Organization: []string{caOrg},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(caExpiry),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("mtls: sign CA cert: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("mtls: marshal CA key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

func IssueServiceCert(caCertPEM, caKeyPEM []byte, svc ServiceType) (certPEM, keyPEM []byte, err error) {
	caCert, err := parseCert(caCertPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("mtls: parse CA cert: %w", err)
	}
	caKey, err := parseKey(caKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("mtls: parse CA key: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("mtls: generate service key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("mtls: generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{

			CommonName:         string(svc),
			Organization:       []string{caOrg},
			OrganizationalUnit: []string{string(svc)},
		},
		DNSNames: []string{
			string(svc),
			string(svc) + ".wolfee-watcher",
			string(svc) + ".wolfee-watcher.svc",
			string(svc) + ".wolfee-watcher.svc.cluster.local",
		},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(certExpiry),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("mtls: sign service cert: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("mtls: marshal service key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

func parseCert(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseKey(pemData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}
