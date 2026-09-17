package clusterctx

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/wolfee-watcher/kvisior/internal/store"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

const (
	ClusterOUPrefix = "cluster:"

	Header      = "X-Cluster-ID"
	QueryParam  = "cluster"
	EnvLocal    = "KVISIOR_CLUSTER_ID"
	EnvTrustHdr = "KVISIOR_TRUST_CLUSTER_HEADER"
)

type ctxKey struct{}

var (
	local     = store.DefaultCluster
	trustHdr  bool
	certFirst = true
)

func Init() {
	if v := strings.TrimSpace(os.Getenv(EnvLocal)); v != "" {
		if !store.ValidClusterID(v) {
			log.Fatalf("[clusterctx] %s=%q is not a valid cluster id "+
				"(lowercase alphanumeric and dashes, max 63 chars)", EnvLocal, v)
		}
		local = v
	}
	switch strings.ToLower(os.Getenv(EnvTrustHdr)) {
	case "1", "true", "yes":
		trustHdr = true
	}
	log.Printf("[clusterctx] local cluster id = %q (header trust=%v, cert identity=%v)",
		local, trustHdr, certFirst)
}

func Local() string { return local }

func FromPeerCert(r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}
	return clusterFromOUs(r.TLS.PeerCertificates[0].Subject.OrganizationalUnit)
}

func clusterFromOUs(ous []string) (string, bool) {
	for _, ou := range ous {
		if !strings.HasPrefix(ou, ClusterOUPrefix) {
			continue
		}
		id := strings.TrimSpace(strings.TrimPrefix(ou, ClusterOUPrefix))
		if store.ValidClusterID(id) {
			return id, true
		}
	}
	return "", false
}

func ForPush(r *http.Request) string {
	if id, ok := FromPeerCert(r); ok {
		return id
	}
	if trustHdr {
		if id := strings.TrimSpace(r.Header.Get(Header)); id != "" && store.ValidClusterID(id) {
			return id
		}
	}
	return local
}

func ForRead(r *http.Request) string {
	if id := strings.TrimSpace(r.Header.Get(Header)); id != "" && store.ValidClusterID(id) {
		return id
	}
	if id := strings.TrimSpace(r.URL.Query().Get(QueryParam)); id != "" && store.ValidClusterID(id) {
		return id
	}
	return local
}

func With(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

func From(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKey{}).(string); ok && v != "" {
		return v
	}
	return local
}

func ForGRPC(ctx context.Context) string {
	pr, ok := peer.FromContext(ctx)
	if !ok || pr.AuthInfo == nil {
		return local
	}
	tlsInfo, ok := pr.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return local
	}
	if id, ok := clusterFromOUs(tlsInfo.State.PeerCertificates[0].Subject.OrganizationalUnit); ok {
		return id
	}
	return local
}
