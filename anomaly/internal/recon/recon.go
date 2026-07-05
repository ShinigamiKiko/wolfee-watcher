package recon

import (
	"fmt"
	"sync"
	"time"
)

const (
	ScanWindow      = 1 * time.Minute
	ScanThreshold   = 5
	cleanupInterval = 5 * time.Minute
)

var suspiciousPorts = map[uint32]string{
	22: "ssh", 23: "telnet", 512: "rexec", 513: "rlogin", 514: "rsh",
	1080: "socks-proxy", 1337: "c2-common", 4444: "metasploit-default",
	4445: "metasploit-alt", 5555: "android-adb", 6666: "irc-c2", 6667: "irc",
	7777: "c2-common", 8888: "c2-common", 9001: "tor", 9050: "tor-socks",
	9051: "tor-control", 31337: "elite-c2", 65535: "backdoor-common",
}

type AlertKind string

const (
	KindPortScan       AlertKind = "port_scan"
	KindSuspiciousPort AlertKind = "suspicious_port"
)

type Alert struct {
	Kind          AlertKind
	SrcDeployment string
	SrcNamespace  string
	DstIP         string
	Ports         []uint32
	Port          uint32
	PortLabel     string
	WindowStart   time.Time
	WindowEnd     time.Time
	Count         int
}

func (a Alert) String() string {
	switch a.Kind {
	case KindPortScan:
		return fmt.Sprintf("port_scan %s/%s → %s (%d ports in %s)", a.SrcNamespace, a.SrcDeployment, a.DstIP, a.Count, ScanWindow)
	case KindSuspiciousPort:
		return fmt.Sprintf("suspicious_port %s/%s → %s:%d (%s)", a.SrcNamespace, a.SrcDeployment, a.DstIP, a.Port, a.PortLabel)
	}
	return "unknown alert"
}

type portHit struct {
	port uint32
	ts   time.Time
}
type windowKey struct{ depKey, dstIP string }
type portWindow struct {
	hits      []portHit
	alerted   bool
	alertedAt time.Time
}

func (w *portWindow) uniquePortsInWindow(now time.Time) ([]uint32, map[uint32]struct{}) {
	cutoff := now.Add(-ScanWindow)
	seen := make(map[uint32]struct{})
	var ports []uint32
	fresh := w.hits[:0]
	for _, h := range w.hits {
		if h.ts.After(cutoff) {
			fresh = append(fresh, h)
			if _, ok := seen[h.port]; !ok {
				seen[h.port] = struct{}{}
				ports = append(ports, h.port)
			}
		}
	}
	w.hits = fresh
	return ports, seen
}

type Detector struct {
	mu          sync.Mutex
	windows     map[windowKey]*portWindow
	stopCleanup chan struct{}
}

func New() *Detector {
	d := &Detector{windows: make(map[windowKey]*portWindow), stopCleanup: make(chan struct{})}
	go d.runCleanup()
	return d
}

func (d *Detector) Stop() { close(d.stopCleanup) }

func (d *Detector) Observe(srcNS, srcDep, dstIP string, dstPort uint32, ts time.Time) []Alert {
	if ts.IsZero() {
		ts = time.Now()
	}
	var alerts []Alert

	if label, bad := suspiciousPorts[dstPort]; bad {
		alerts = append(alerts, Alert{Kind: KindSuspiciousPort, SrcDeployment: srcDep, SrcNamespace: srcNS,
			DstIP: dstIP, Port: dstPort, PortLabel: label, WindowStart: ts, WindowEnd: ts, Count: 1})
	}

	key := windowKey{depKey: srcNS + "/" + srcDep, dstIP: dstIP}
	d.mu.Lock()
	w := d.windows[key]
	if w == nil {
		w = &portWindow{}
		d.windows[key] = w
	}
	w.hits = append(w.hits, portHit{dstPort, ts})
	ports, _ := w.uniquePortsInWindow(ts)
	count := len(ports)
	if w.alerted && ts.Sub(w.alertedAt) > ScanWindow*2 {
		w.alerted = false
	}
	shouldAlert := count >= ScanThreshold && !w.alerted
	if shouldAlert {
		w.alerted = true
		w.alertedAt = ts
	}
	d.mu.Unlock()

	if shouldAlert {
		alerts = append(alerts, Alert{Kind: KindPortScan, SrcDeployment: srcDep, SrcNamespace: srcNS,
			DstIP: dstIP, Ports: ports, WindowStart: ts.Add(-ScanWindow), WindowEnd: ts, Count: count})
	}
	return alerts
}

func (d *Detector) Stats() (windows, hits int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, w := range d.windows {
		windows++
		hits += len(w.hits)
	}
	return
}

func (d *Detector) runCleanup() {
	t := time.NewTicker(cleanupInterval)
	defer t.Stop()
	for {
		select {
		case <-d.stopCleanup:
			return
		case now := <-t.C:
			d.cleanup(now)
		}
	}
}

func (d *Detector) cleanup(now time.Time) {
	cutoff := now.Add(-ScanWindow * 2)
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, w := range d.windows {
		fresh := w.hits[:0]
		for _, h := range w.hits {
			if h.ts.After(cutoff) {
				fresh = append(fresh, h)
			}
		}
		w.hits = fresh
		if len(w.hits) == 0 {
			delete(d.windows, k)
		}
	}
}
