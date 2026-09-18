package mtls

import (
	"crypto/x509"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const (
	ClusterOUPrefix  = "cluster:"
	EnvClusterID     = "CLUSTER_ID"
	DefaultCluster   = "default"
	EnvNamespace     = "POD_NAMESPACE"
	DefaultNamespace = "wolfee-watcher"
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

func Namespace() string {
	if ns := strings.TrimSpace(os.Getenv(EnvNamespace)); ns != "" {
		return ns
	}
	return DefaultNamespace
}

func ServiceDNSNames(svc string) []string {
	ns := Namespace()
	return []string{
		svc,
		svc + "." + ns,
		svc + "." + ns + ".svc",
		svc + "." + ns + ".svc.cluster.local",
	}
}

func ServiceHost(svc string, port int) string {
	return svc + "." + Namespace() + ".svc.cluster.local:" + strconv.Itoa(port)
}
