package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wolfee-watcher/pkg/mtls"
)

const trapRefresh = 15 * time.Second

type trap struct {
	ID         string
	Namespace  string
	Name       string
	Service    string
	Kind       string
	Port       uint32
	TargetPort uint32
	ClusterIP  string
	Selector   map[string]string
}

type trapIndex struct {
	pool *pgxpool.Pool

	mu    sync.RWMutex
	list  []trap
	byIP  map[string]trap
	at    time.Time
	warns int
}

func newTrapIndex(pool *pgxpool.Pool) *trapIndex {
	return &trapIndex{pool: pool, byIP: map[string]trap{}}
}

func (t *trapIndex) load(ctx context.Context) []trap {
	t.mu.RLock()
	fresh := time.Since(t.at) < trapRefresh
	list := t.list
	t.mu.RUnlock()
	if fresh || t.pool == nil {
		return list
	}
	rows, err := t.pool.Query(ctx,
		`SELECT id, namespace, name, service, kind, port, target_port, cluster_ip, selector
		   FROM honeypots WHERE cluster_id = $1`, mtls.ClusterID())
	if err != nil {
		t.mu.Lock()
		t.at = time.Now()
		if t.warns < 3 {
			log.Printf("[honeypots] registry read failed: %v", err)
			t.warns++
		}
		t.mu.Unlock()
		return list
	}
	defer rows.Close()
	var out []trap
	for rows.Next() {
		var tr trap
		var port, target int32
		var sel []byte
		if err := rows.Scan(&tr.ID, &tr.Namespace, &tr.Name, &tr.Service, &tr.Kind, &port, &target, &tr.ClusterIP, &sel); err != nil {
			continue
		}
		tr.Port, tr.TargetPort = uint32(port), uint32(target)
		_ = json.Unmarshal(sel, &tr.Selector)
		out = append(out, tr)
	}
	t.mu.Lock()
	t.list = out
	t.at = time.Now()
	t.mu.Unlock()
	return out
}

func (c *Consumer) matchTrap(ctx context.Context, dstIP string, dstPort uint32) (trap, bool) {
	if c.traps == nil {
		return trap{}, false
	}
	list := c.traps.load(ctx)
	if len(list) == 0 {
		return trap{}, false
	}
	for _, tr := range list {
		if tr.ClusterIP != "" && tr.ClusterIP == dstIP {
			return tr, true
		}
	}
	for _, tr := range list {
		for _, ip := range c.enrich.PodIPsMatching(ctx, tr.Namespace, tr.Selector) {
			if ip == dstIP {
				return tr, true
			}
		}
	}
	return trap{}, false
}

func (c *Consumer) honeypotProbe(ev map[string]interface{}, base *AnomalyEvent, tr trap, dstIP string, dstPort uint32) *AnomalyEvent {
	a := clone(base)
	a.Kind = KindHoneypotProbe
	a.DstIP = dstIP
	a.DstPort = dstPort
	a.DstService = tr.Name
	a.DstNS = tr.Namespace
	a.Protocol = "TCP"
	a.HoneypotID = tr.ID
	a.HoneypotName = tr.Name
	a.HoneypotService = tr.Service
	a.HoneypotKind = tr.Kind
	a.SrcPID = anyString(ev["pid"])
	a.SrcUID = anyString(ev["uid"])
	a.SrcCmdline = strVal(ev, "cmdline")
	if a.SrcCmdline == "" {
		a.SrcCmdline = strVal(ev, "execpath")
	}
	a.Detail = fmt.Sprintf("connect to honeypot %s/%s (%s) from %s", tr.Namespace, tr.Name, tr.Service, base.SrcProcess)
	return a
}

func anyString(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return fmt.Sprintf("%d", int64(x))
	default:
		return fmt.Sprintf("%v", x)
	}
}
