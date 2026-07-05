package epss

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	internal "github.com/wolfee-watcher/scanner-agent/internal"
	"github.com/wolfee-watcher/scanner-agent/internal/bdu"
)

const (
	epssAPI   = "https://api.first.org/data/v1/epss"
	cisaURL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	nvdAPI    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	pocBase   = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"
	cacheTTL  = 24 * time.Hour
	batchSize = 100
)

type Enricher struct {
	client    *http.Client
	nvdAPIKey string

	mu        sync.RWMutex
	epssCache map[string]*epssEntry
	nvdCache  map[string]*nvdEntry
	pocCache  map[string][]internal.PoCEntry

	kevMu  sync.RWMutex
	kevSet map[string]struct{}
	kevTs  time.Time

	bdu *bdu.Enricher
}

type epssEntry struct {
	score      float64
	percentile float64
	fetched    time.Time
}

type nvdEntry struct {
	cvss3Score  float64
	cvss3Vector string
	cvss2Score  float64
	cvss2Vector string
	cvss4Score  float64
	cvss4Vector string
	description string
	fetched     time.Time
}

func New(ctx context.Context, nvdAPIKey string) *Enricher {
	conc := 3
	if nvdAPIKey != "" {
		conc = 10
		log.Printf("[enricher] NVD API key set — high-throughput mode (concurrency %d)", conc)
	} else {
		log.Printf("[enricher] No NVD API key — conservative mode (concurrency %d). Set NVD_API_KEY env var.", conc)
	}
	e := &Enricher{
		client:    &http.Client{Timeout: 15 * time.Second},
		nvdAPIKey: nvdAPIKey,
		epssCache: make(map[string]*epssEntry),
		nvdCache:  make(map[string]*nvdEntry),
		pocCache:  make(map[string][]internal.PoCEntry),
	}
	go func() {
		t := time.NewTicker(cacheTTL)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				e.pruneStale()
			}
		}
	}()
	return e
}

func (e *Enricher) pruneStale() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, ep := range e.epssCache {
		if isStale(ep.fetched) {
			delete(e.epssCache, id)
		}
	}
	for id, nvd := range e.nvdCache {
		if isStale(nvd.fetched) {
			delete(e.nvdCache, id)
		}
	}
	e.pocCache = make(map[string][]internal.PoCEntry)
}

func (e *Enricher) WithBDU(b *bdu.Enricher) *Enricher {
	e.bdu = b
	return e
}

func (e *Enricher) Enrich(ctx context.Context, cves []internal.CVE) []internal.CVE {
	if len(cves) == 0 {
		return cves
	}

	ids := make([]string, 0, len(cves))
	seen := map[string]bool{}
	for _, c := range cves {
		if c.ID != "" && !seen[c.ID] {
			ids = append(ids, c.ID)
			seen[c.ID] = true
		}
	}

	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); e.fetchEPSS(ctx, ids) }()
	go func() { defer wg.Done(); e.fetchNVD(ctx, ids) }()
	go func() { defer wg.Done(); e.fetchKEV(ctx) }()
	go func() { defer wg.Done(); e.fetchPoCs(ctx, ids) }()
	wg.Wait()

	e.mu.RLock()
	e.kevMu.RLock()
	defer e.mu.RUnlock()
	defer e.kevMu.RUnlock()

	for i := range cves {
		c := &cves[i]
		applyEnrichment(e, c)
	}
	return cves
}

func applyEnrichment(e *Enricher, c *internal.CVE) {
	id := c.ID

	if ep := e.epssCache[id]; ep != nil {
		c.EPSSScore = ep.score
		c.EPSSPercentile = ep.percentile
	}

	if nvd := e.nvdCache[id]; nvd != nil {
		if nvd.cvss3Score > 0 {
			c.CVSSv3Score = nvd.cvss3Score
			c.CVSSv3Vector = nvd.cvss3Vector
		}
		if nvd.cvss2Score > 0 {
			c.CVSSv2Score = nvd.cvss2Score
			c.CVSSv2Vector = nvd.cvss2Vector
		}
		if nvd.cvss4Score > 0 {
			c.CVSSv4Score = nvd.cvss4Score
			c.CVSSv4Vector = nvd.cvss4Vector
		}
		if nvd.description != "" && c.Description == "" {
			c.Description = nvd.description
		}
	}

	_, c.InKEV = e.kevSet[id]

	if e.bdu != nil {
		if bduID, bduSev, ok := e.bdu.Lookup(id); ok {
			c.BduID = bduID
			c.BduSeverity = bduSev

			if d, ok := e.bdu.LookupDetail(id); ok && d != nil {
				c.BduDetail = bduDetailToInternal(d)
			}
		}
	}

	if pocs, ok := e.pocCache[id]; ok {
		c.PoCs = pocs
	}

	c.HasFix = c.FixedIn != "" || c.FixState == "fixed"

	switch c.FixState {
	case "fixed":
		c.VEXStatus, c.VEXSource = "fixed", "Grype fix.state"
	case "wont-fix":
		c.VEXStatus, c.VEXSource = "wont_fix", "Grype fix.state"
	case "not-fixed":
		c.VEXStatus, c.VEXSource = "not_fixed", "Grype fix.state"
	default:

		if c.FixedIn != "" {
			c.VEXStatus, c.VEXSource = "fixed", "Grype fix.versions"
		} else {
			c.VEXStatus, c.VEXSource = "not_fixed", "Grype fix.state"
		}
	}

	cvssNorm := c.CVSSv3Score / 10.0
	if cvssNorm == 0 {
		cvssNorm = c.CVSSv2Score / 10.0
	}
	var raw float64
	if c.EPSSScore > 0 {
		raw = cvssNorm*0.6 + c.EPSSScore*0.4
	} else {
		raw = cvssNorm
	}
	c.RiskScore = int(raw * 100)
	switch {
	case c.RiskScore >= 80:
		c.RiskLabel = "CRITICAL"
	case c.RiskScore >= 50:
		c.RiskLabel = "HIGH"
	case c.RiskScore >= 25:
		c.RiskLabel = "MEDIUM"
	default:
		c.RiskLabel = "LOW"
	}

}

func bduDetailToInternal(d *bdu.Detail) *internal.BDUDetail {
	out := &internal.BDUDetail{
		Identifier:      d.Identifier,
		Name:            d.Name,
		Description:     d.Description,
		Severity:        d.Severity,
		CVSS3Vector:     d.CVSS3Vector,
		CVSS3Score:      d.CVSS3Score,
		Solution:        d.Solution,
		Sources:         d.Sources,
		FixStatus:       d.FixStatus,
		VulStatus:       d.VulStatus,
		ExploitStatus:   d.ExploitStatus,
		VulClass:        d.VulClass,
		VulElimination:  d.VulElimination,
		IdentifyDate:    d.IdentifyDate,
		PublicationDate: d.PublicationDate,
		LastUpdDate:     d.LastUpdDate,
		CVSS2Vector:     d.CVSS2Vector,
		CVSS2Score:      d.CVSS2Score,
		CVSS4Vector:     d.CVSS4Vector,
		CVSS4Score:      d.CVSS4Score,
		SLOperProcs:     d.SLOperProcs,
	}
	if len(d.CWEs) > 0 {
		out.CWEs = make([]internal.BDUCWE, len(d.CWEs))
		for i, c := range d.CWEs {
			out.CWEs[i] = internal.BDUCWE{ID: c.ID, Name: c.Name}
		}
	}
	if len(d.Software) > 0 {
		out.Software = make([]internal.BDUSoftware, len(d.Software))
		for i, s := range d.Software {
			out.Software[i] = internal.BDUSoftware{
				Vendor:   s.Vendor,
				Name:     s.Name,
				Version:  s.Version,
				Platform: s.Platform,
				Types:    s.Types,
			}
		}
	}
	if len(d.Environments) > 0 {
		out.Environments = make([]internal.BDUEnvironment, len(d.Environments))
		for i, e := range d.Environments {
			out.Environments[i] = internal.BDUEnvironment{
				Vendor:  e.Vendor,
				Name:    e.Name,
				Version: e.Version,
			}
		}
	}
	if len(d.OtherIDs) > 0 {
		out.OtherIDs = make([]internal.BDUOtherID, len(d.OtherIDs))
		for i, o := range d.OtherIDs {
			out.OtherIDs[i] = internal.BDUOtherID{Type: o.Type, Value: o.Value}
		}
	}
	return out
}
