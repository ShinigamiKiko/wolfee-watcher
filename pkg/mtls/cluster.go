package mtls

import (
	"crypto/x509"
	"os"
	"regexp"
	"strings"
)

const (
	ClusterOUPrefix = "cluster:"
	EnvClusterID    = "CLUSTER_ID"
	DefaultCluster  = "default"
)

var clusterIDRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func ValidClusterID(id string) bool { return clusterIDRe.MatchString(id) }

func ClusterID() string {
	id := strings.TrimSpace(os.Getenv(EnvClusterID))
	if id == "" || !ValidClusterID(id) {
		return DefaultCluster
	}
	return id
}

func ClusterOU(id string) string { return ClusterOUPrefix + id }

func ClusterFromCert(cert *x509.Certificate) (string, bool) {
	if cert == nil {
		return "", false
	}
	for _, ou := range cert.Subject.OrganizationalUnit {
		if !strings.HasPrefix(ou, ClusterOUPrefix) {
			continue
		}
		id := strings.TrimSpace(strings.TrimPrefix(ou, ClusterOUPrefix))
		if ValidClusterID(id) {
			return id, true
		}
	}
	return "", false
}
