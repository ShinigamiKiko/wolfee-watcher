package mtls

import (
	"fmt"
	"os"
)

const (
	EnvCAFile   = "MTLS_CA_FILE"
	EnvCertFile = "MTLS_CERT_FILE"
	EnvKeyFile  = "MTLS_KEY_FILE"
)

type Certs struct {
	CA   []byte
	Cert []byte
	Key  []byte
}

func Load() (*Certs, error) {
	ca, err := readEnvFile(EnvCAFile)
	if err != nil {
		return nil, err
	}
	cert, err := readEnvFile(EnvCertFile)
	if err != nil {
		return nil, err
	}
	key, err := readEnvFile(EnvKeyFile)
	if err != nil {
		return nil, err
	}
	return &Certs{CA: ca, Cert: cert, Key: key}, nil
}

func TryLoad() (*Certs, error) {
	if os.Getenv(EnvCAFile) == "" {
		return nil, nil
	}
	return Load()
}

func readEnvFile(envVar string) ([]byte, error) {
	path := os.Getenv(envVar)
	if path == "" {
		return nil, fmt.Errorf("mtls: %s is not set", envVar)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("mtls: reading %s (%s): %w", envVar, path, err)
	}
	return data, nil
}
