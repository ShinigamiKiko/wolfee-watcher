package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
)

func ServerConfig(c *Certs) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(c.Cert, c.Key)
	if err != nil {
		return nil, fmt.Errorf("mtls: server key pair: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(c.CA) {
		return nil, fmt.Errorf("mtls: failed to parse CA cert")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},

		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
		MinVersion: tls.VersionTLS13,
	}, nil
}

func ClientConfig(c *Certs) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(c.Cert, c.Key)
	if err != nil {
		return nil, fmt.Errorf("mtls: client key pair: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(c.CA) {
		return nil, fmt.Errorf("mtls: failed to parse CA cert")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func NewSecureClient(c *Certs) (*http.Client, error) {
	tlsCfg, err := ClientConfig(c)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

func NewSecureClientFromHolder(h *CertHolder) (*http.Client, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(h.CA()) {
		return nil, fmt.Errorf("mtls: failed to parse CA from cert holder")
	}
	tlsCfg := &tls.Config{
		GetClientCertificate: h.GetClientCertificate,
		RootCAs:              pool,
		MinVersion:           tls.VersionTLS13,
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

func NewForensicClient(h *CertHolder) (*http.Client, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(h.CA()) {
		return nil, fmt.Errorf("mtls: failed to parse CA from cert holder")
	}
	tlsCfg := &tls.Config{
		GetClientCertificate: h.GetClientCertificate,

		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("mtls: forensic peer presented no certificate")
			}
			opts := x509.VerifyOptions{
				Roots:         pool,
				Intermediates: x509.NewCertPool(),
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			}
			for _, c := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(c)
			}
			leaf := cs.PeerCertificates[0]
			if _, err := leaf.Verify(opts); err != nil {
				return err
			}

			if leaf.Subject.CommonName != string(ForensicWatcher) {
				return fmt.Errorf("mtls: forensic peer identity %q != %q", leaf.Subject.CommonName, ForensicWatcher)
			}
			return nil
		},
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

func ServiceTypeFromRequest(r *http.Request) (ServiceType, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}
	cn := r.TLS.PeerCertificates[0].Subject.CommonName
	if cn == "" {
		return "", false
	}
	return ServiceType(cn), true
}
