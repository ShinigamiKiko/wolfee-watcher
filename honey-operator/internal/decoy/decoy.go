package decoy

import (
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

const (
	KindStatefulSet = "StatefulSet"
	KindDeployment  = "Deployment"
)

type Profile struct {
	Service     string
	Kind        string
	DefaultName string
	AppName     string
	Chart       string
	Version     string
	Component   string
	Repo        string
	Tag         string
	Args        []string
	Port        int32
	TargetPort  int32
	PortName    string
	Protocol    corev1.Protocol
	DataPath    string
	Env         []corev1.EnvVar
}

var catalog = []Profile{
	{
		Service: "postgres", Kind: KindStatefulSet, DefaultName: "postgres",
		AppName: "postgresql", Chart: "postgresql-15.5.38", Version: "16.4.0", Component: "primary",
		Repo: "postgres", Tag: "16.4", Args: []string{"postgres"},
		Port: 5432, TargetPort: 5432, PortName: "tcp-postgresql", Protocol: corev1.ProtocolTCP,
		DataPath: "/var/lib/postgresql/data",
		Env: []corev1.EnvVar{
			{Name: "POSTGRES_DB", Value: "app"},
			{Name: "POSTGRES_USER", Value: "app"},
			{Name: "PGDATA", Value: "/var/lib/postgresql/data/pgdata"},
		},
	},
	{
		Service: "mysql", Kind: KindStatefulSet, DefaultName: "mysql",
		AppName: "mysql", Chart: "mysql-11.1.17", Version: "8.0.39", Component: "primary",
		Repo: "mysql", Tag: "8.0.39", Args: []string{"mysqld"},
		Port: 3306, TargetPort: 3306, PortName: "mysql", Protocol: corev1.ProtocolTCP,
		DataPath: "/var/lib/mysql",
		Env:      []corev1.EnvVar{{Name: "MYSQL_DATABASE", Value: "app"}},
	},
	{
		Service: "redis", Kind: KindStatefulSet, DefaultName: "redis",
		AppName: "redis", Chart: "redis-20.1.4", Version: "7.2.5", Component: "master",
		Repo: "redis", Tag: "7.2.5", Args: []string{"redis-server"},
		Port: 6379, TargetPort: 6379, PortName: "tcp-redis", Protocol: corev1.ProtocolTCP,
		DataPath: "/data",
	},
	{
		Service: "elastic", Kind: KindStatefulSet, DefaultName: "elasticsearch",
		AppName: "elasticsearch", Chart: "elasticsearch-21.3.17", Version: "8.15.0", Component: "master",
		Repo: "elasticsearch", Tag: "8.15.0", Args: []string{"eswrapper"},
		Port: 9200, TargetPort: 9200, PortName: "tcp-rest-api", Protocol: corev1.ProtocolTCP,
		DataPath: "/usr/share/elasticsearch/data",
		Env: []corev1.EnvVar{
			{Name: "discovery.type", Value: "single-node"},
			{Name: "ES_JAVA_OPTS", Value: "-Xms512m -Xmx512m"},
		},
	},
	{
		Service: "dns", Kind: KindDeployment, DefaultName: "coredns-cache",
		AppName: "coredns", Chart: "coredns-1.36.0", Version: "1.11.3",
		Repo: "coredns", Tag: "1.11.3", Args: []string{"-conf", "/etc/coredns/Corefile"},
		Port: 53, TargetPort: 5353, PortName: "udp-53", Protocol: corev1.ProtocolUDP,
	},
	{
		Service: "ssh", Kind: KindDeployment, DefaultName: "bastion",
		AppName: "openssh-server", Chart: "openssh-server-0.4.2", Version: "9.7",
		Repo: "openssh-server", Tag: "9.7", Args: []string{"/usr/sbin/sshd", "-D", "-e"},
		Port: 22, TargetPort: 2222, PortName: "ssh", Protocol: corev1.ProtocolTCP,
	},
	{
		Service: "http", Kind: KindDeployment, DefaultName: "internal-api",
		AppName: "nginx", Chart: "nginx-18.1.11", Version: "1.27.1",
		Repo: "nginx", Tag: "1.27.1", Args: []string{"nginx", "-g", "daemon off;"},
		Port: 80, TargetPort: 8080, PortName: "http", Protocol: corev1.ProtocolTCP,
	},
	{
		Service: "ftp", Kind: KindDeployment, DefaultName: "ftp",
		AppName: "vsftpd", Chart: "vsftpd-1.2.0", Version: "3.0.5",
		Repo: "vsftpd", Tag: "3.0.5", Args: []string{"vsftpd"},
		Port: 21, TargetPort: 2121, PortName: "ftp", Protocol: corev1.ProtocolTCP,
	},
	{
		Service: "smtp", Kind: KindDeployment, DefaultName: "mail-relay",
		AppName: "postfix", Chart: "postfix-4.0.3", Version: "3.9.0",
		Repo: "postfix", Tag: "3.9.0", Args: []string{"postfix", "start-fg"},
		Port: 25, TargetPort: 2525, PortName: "smtp", Protocol: corev1.ProtocolTCP,
	},
}

func Lookup(service string) (Profile, bool) {
	for _, p := range catalog {
		if p.Service == service {
			return p, true
		}
	}
	return Profile{}, false
}

func All() []Profile {
	out := make([]Profile, len(catalog))
	copy(out, catalog)
	return out
}

func Registry() string {
	if r := strings.TrimRight(strings.TrimSpace(os.Getenv("DECOY_REGISTRY")), "/"); r != "" {
		return r
	}
	return "localhost/library"
}

func PullPolicy() corev1.PullPolicy {
	switch strings.TrimSpace(os.Getenv("DECOY_PULL_POLICY")) {
	case "Always":
		return corev1.PullAlways
	case "IfNotPresent":
		return corev1.PullIfNotPresent
	default:
		return corev1.PullNever
	}
}

func (p Profile) Image() string {
	return Registry() + "/" + p.Repo + ":" + p.Tag
}

func (p Profile) Selector(name string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":     p.AppName,
		"app.kubernetes.io/instance": name,
	}
}

func (p Profile) Labels(name string) map[string]string {
	l := p.Selector(name)
	l["app.kubernetes.io/version"] = p.Version
	l["app.kubernetes.io/managed-by"] = "Helm"
	l["helm.sh/chart"] = p.Chart
	if p.Component != "" {
		l["app.kubernetes.io/component"] = p.Component
	}
	return l
}
