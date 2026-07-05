package issuer

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

	"github.com/wolfee-watcher/pkg/mtls"
)

const (
	CertLifetime = 3 * time.Hour
	BeforeGrace  = 1 * time.Minute
)

type Issuer struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte
}

func New(caCertPEM, caKeyPEM []byte) (*Issuer, error) {

	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return nil, fmt.Errorf("issuer: failed to decode CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("issuer: parse CA cert: %w", err)
	}

	block, _ = pem.Decode(caKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("issuer: failed to decode CA key PEM")
	}
	caKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("issuer: parse CA key: %w", err)
	}

	return &Issuer{caCert: caCert, caKey: caKey, caPEM: caCertPEM}, nil
}

func (is *Issuer) Issue(svc mtls.ServiceType) (certPEM, keyPEM []byte, err error) {

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("issuer: generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("issuer: generate serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: string(svc)},
		DNSNames: []string{
			string(svc),
			string(svc) + ".wolfee-watcher",
			string(svc) + ".wolfee-watcher.svc",
			string(svc) + ".wolfee-watcher.svc.cluster.local",
		},
		NotBefore: now.Add(-BeforeGrace),
		NotAfter:  now.Add(CertLifetime),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, is.caCert, &key.PublicKey, is.caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("issuer: sign cert: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("issuer: marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

func (is *Issuer) CAPEM() []byte { return is.caPEM }
