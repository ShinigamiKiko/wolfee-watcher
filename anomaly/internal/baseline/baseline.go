package baseline

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const DefaultObservationPeriod = 10 * 24 * time.Hour

type EntityType string

const (
	EntityDeployment     EntityType = "DEPLOYMENT"
	EntityExternalSource EntityType = "EXTERNAL_SOURCE"
	EntityInternet       EntityType = "INTERNET"
	EntityInternal       EntityType = "INTERNAL_ENTITIES"
)

var ValidPeerEntityTypes = map[EntityType]struct{}{
	EntityDeployment:     {},
	EntityExternalSource: {},
	EntityInternet:       {},
	EntityInternal:       {},
}

type Protocol string

const (
	TCP Protocol = "TCP"
	UDP Protocol = "UDP"
)

type Entity struct {
	ID         string
	Type       EntityType
	Name       string
	Discovered bool
}

func AnonymizeExternalDiscoveredEntity(e Entity) Entity {
	if e.Type == EntityExternalSource && e.Discovered {
		return InternetEntity()
	}
	return e
}

func InternetEntity() Entity {
	return Entity{ID: "internet", Type: EntityInternet, Name: "Internet"}
}

func ExternalEntity(ip string) Entity {
	cidr := bucketToCIDR(ip)
	return Entity{ID: cidr, Type: EntityExternalSource, Name: cidr}
}

func bucketToCIDR(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return fmt.Sprintf("%s/24", v4.Mask(net.CIDRMask(24, 32)))
	}
	return fmt.Sprintf("%s/48", parsed.Mask(net.CIDRMask(48, 128)))
}

type Peer struct {
	IsIngress bool
	Entity    Entity
	DstPort   uint32
	Protocol  Protocol
	CidrBlock string
}

type peerWire struct {
	I bool     `json:"i"`
	E Entity   `json:"e"`
	P uint32   `json:"p"`
	X Protocol `json:"x"`
	C string   `json:"c,omitempty"`
}

func (p Peer) MarshalText() ([]byte, error) {
	raw, err := json.Marshal(peerWire{p.IsIngress, p.Entity, p.DstPort, p.Protocol, p.CidrBlock})
	if err != nil {
		return nil, err
	}
	enc := base64.RawURLEncoding.EncodeToString(raw)
	return []byte(enc), nil
}

func (p *Peer) UnmarshalText(text []byte) error {
	raw, err := base64.RawURLEncoding.DecodeString(string(text))
	if err != nil {
		return fmt.Errorf("peer: base64 decode: %w", err)
	}
	var w peerWire
	if err := json.Unmarshal(raw, &w); err != nil {
		return fmt.Errorf("peer: json decode: %w", err)
	}
	p.IsIngress = w.I
	p.Entity = w.E
	p.DstPort = w.P
	p.Protocol = w.X
	p.CidrBlock = w.C
	return nil
}

type BaselineInfo struct {
	Namespace      string
	DeploymentName string
	DeploymentID   string

	ObservationPeriodEnd time.Time
	UserLocked           bool
	BaselinePeers        map[Peer]struct{}
	ForbiddenPeers       map[Peer]struct{}

	BaselineBinaries map[string]struct{}
}

type Store struct {
	mu                sync.Mutex
	baselines         map[string]*BaselineInfo
	pool              *pgxpool.Pool
	observationPeriod time.Duration
	baseCtx           context.Context

	dirtyMu sync.Mutex
	dirty   map[string]struct{}
	notify  chan struct{}
}

const (
	persistTimeout  = 5 * time.Second
	persistDebounce = 1 * time.Second
)

func New(ctx context.Context, pool *pgxpool.Pool, observationPeriod time.Duration) *Store {
	if observationPeriod == 0 {
		observationPeriod = DefaultObservationPeriod
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s := &Store{
		baselines:         make(map[string]*BaselineInfo),
		pool:              pool,
		observationPeriod: observationPeriod,
		baseCtx:           ctx,
		dirty:             make(map[string]struct{}),
		notify:            make(chan struct{}, 1),
	}
	if pool != nil {
		go s.persistLoop()
	}
	return s
}

func cidrOf(e Entity) string {
	if e.Type == EntityExternalSource {
		return e.Name
	}
	return ""
}
