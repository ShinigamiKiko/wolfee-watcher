package epss

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	internal "github.com/wolfee-watcher/scanner-agent/internal"
)

const maxFetchBody = 64 << 20

func (e *Enricher) fetchEPSS(ctx context.Context, ids []string) {
	e.mu.RLock()
	var toFetch []string
	for _, id := range ids {
		if ep := e.epssCache[id]; ep == nil || isStale(ep.fetched) {
			toFetch = append(toFetch, id)
		}
	}
	e.mu.RUnlock()
	if len(toFetch) == 0 {
		return
	}

	for i := 0; i < len(toFetch); i += batchSize {
		chunk := toFetch[i:min(i+batchSize, len(toFetch))]
		url := fmt.Sprintf("%s?cve=%s&limit=%d", epssAPI, strings.Join(chunk, ","), len(chunk))
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			log.Printf("[enricher] EPSS build request: %v", err)
			continue
		}
		resp, err := e.client.Do(req)
		if err != nil {
			log.Printf("[enricher] EPSS fetch error: %v", err)
			continue
		}

		var data struct {
			Data []struct {
				CVE        string `json:"cve"`
				EPSS       string `json:"epss"`
				Percentile string `json:"percentile"`
			} `json:"data"`
		}
		if resp.StatusCode != http.StatusOK {
			log.Printf("[enricher] EPSS HTTP %d for batch of %d", resp.StatusCode, len(chunk))
			resp.Body.Close()
			continue
		}
		decErr := json.NewDecoder(io.LimitReader(resp.Body, maxFetchBody)).Decode(&data)
		resp.Body.Close()
		if decErr != nil {
			log.Printf("[enricher] EPSS decode error: %v", decErr)
			continue
		}

		e.mu.Lock()
		for _, item := range data.Data {
			var score, pct float64
			fmt.Sscanf(item.EPSS, "%f", &score)
			fmt.Sscanf(item.Percentile, "%f", &pct)
			e.epssCache[item.CVE] = &epssEntry{score: score, percentile: pct, fetched: time.Now()}
		}
		e.mu.Unlock()
	}
}

func (e *Enricher) fetchNVD(ctx context.Context, ids []string) {
	e.mu.RLock()
	var toFetch []string
	for _, id := range ids {
		if nvd := e.nvdCache[id]; nvd == nil || isStale(nvd.fetched) {
			toFetch = append(toFetch, id)
		}
	}
	e.mu.RUnlock()
	if len(toFetch) == 0 {
		return
	}

	conc := 3
	if e.nvdAPIKey != "" {
		conc = 10
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup

	for _, id := range toFetch {
		if !strings.HasPrefix(id, "CVE-") {
			continue
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(cveID string) {
			defer wg.Done()
			defer func() { <-sem }()

			url := fmt.Sprintf("%s?cveId=%s", nvdAPI, cveID)
			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				log.Printf("[enricher] NVD build request: %v", err)
				return
			}
			req.Header.Set("Accept", "application/json")
			if e.nvdAPIKey != "" {
				req.Header.Set("apiKey", e.nvdAPIKey)
			}

			resp, err := e.client.Do(req)
			if err != nil || resp.StatusCode != 200 {
				if resp != nil {
					resp.Body.Close()
				}
				return
			}
			defer resp.Body.Close()

			var d struct {
				Vulnerabilities []struct {
					CVE struct {
						Descriptions []struct {
							Lang  string `json:"lang"`
							Value string `json:"value"`
						} `json:"descriptions"`
						Metrics struct {
							V40 []struct {
								CVSSData struct {
									BaseScore    float64 `json:"baseScore"`
									VectorString string  `json:"vectorString"`
								} `json:"cvssData"`
							} `json:"cvssMetricV40"`
							V31 []struct {
								CVSSData struct {
									BaseScore    float64 `json:"baseScore"`
									VectorString string  `json:"vectorString"`
								} `json:"cvssData"`
							} `json:"cvssMetricV31"`
							V30 []struct {
								CVSSData struct {
									BaseScore    float64 `json:"baseScore"`
									VectorString string  `json:"vectorString"`
								} `json:"cvssData"`
							} `json:"cvssMetricV30"`
							V2 []struct {
								CVSSData struct {
									BaseScore    float64 `json:"baseScore"`
									VectorString string  `json:"vectorString"`
								} `json:"cvssData"`
							} `json:"cvssMetricV2"`
						} `json:"metrics"`
					} `json:"cve"`
				} `json:"vulnerabilities"`
			}
			if err := json.NewDecoder(io.LimitReader(resp.Body, maxFetchBody)).Decode(&d); err != nil || len(d.Vulnerabilities) == 0 {
				return
			}

			vuln := d.Vulnerabilities[0].CVE
			entry := &nvdEntry{fetched: time.Now()}

			for _, desc := range vuln.Descriptions {
				if desc.Lang == "en" {
					entry.description = desc.Value
					break
				}
			}
			if len(vuln.Metrics.V31) > 0 {
				entry.cvss3Score = vuln.Metrics.V31[0].CVSSData.BaseScore
				entry.cvss3Vector = vuln.Metrics.V31[0].CVSSData.VectorString
			} else if len(vuln.Metrics.V30) > 0 {
				entry.cvss3Score = vuln.Metrics.V30[0].CVSSData.BaseScore
				entry.cvss3Vector = vuln.Metrics.V30[0].CVSSData.VectorString
			}
			if len(vuln.Metrics.V2) > 0 {
				entry.cvss2Score = vuln.Metrics.V2[0].CVSSData.BaseScore
				entry.cvss2Vector = vuln.Metrics.V2[0].CVSSData.VectorString
			}
			if len(vuln.Metrics.V40) > 0 {
				entry.cvss4Score = vuln.Metrics.V40[0].CVSSData.BaseScore
				entry.cvss4Vector = vuln.Metrics.V40[0].CVSSData.VectorString
			}

			e.mu.Lock()
			e.nvdCache[cveID] = entry
			e.mu.Unlock()
		}(id)
	}
	wg.Wait()
}

func (e *Enricher) fetchKEV(ctx context.Context) {
	e.kevMu.RLock()
	fresh := len(e.kevSet) > 0 && time.Since(e.kevTs) < time.Hour
	e.kevMu.RUnlock()
	if fresh {
		return
	}

	req, err := http.NewRequestWithContext(ctx, "GET", cisaURL, nil)
	if err != nil {
		log.Printf("[enricher] CISA KEV build request: %v", err)
		return
	}
	resp, err := e.client.Do(req)
	if err != nil {
		log.Printf("[enricher] CISA KEV error: %v", err)
		return
	}
	defer resp.Body.Close()

	var d struct {
		Vulnerabilities []struct {
			CVEID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxFetchBody)).Decode(&d); err != nil {
		return
	}

	kev := make(map[string]struct{}, len(d.Vulnerabilities))
	for _, v := range d.Vulnerabilities {
		kev[v.CVEID] = struct{}{}
	}
	e.kevMu.Lock()
	e.kevSet = kev
	e.kevTs = time.Now()
	e.kevMu.Unlock()
	log.Printf("[enricher] CISA KEV loaded: %d entries", len(kev))
}

func (e *Enricher) fetchPoCs(ctx context.Context, ids []string) {
	e.mu.RLock()
	var toFetch []string
	for _, id := range ids {
		if _, ok := e.pocCache[id]; !ok {
			toFetch = append(toFetch, id)
		}
	}
	e.mu.RUnlock()
	if len(toFetch) == 0 {
		return
	}

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, id := range toFetch {
		if !strings.HasPrefix(id, "CVE-") {
			continue
		}
		parts := strings.SplitN(id, "-", 3)
		if len(parts) < 3 {
			continue
		}
		year := parts[1]
		sem <- struct{}{}
		wg.Add(1)
		go func(cveID, yr string) {
			defer wg.Done()
			defer func() { <-sem }()

			url := fmt.Sprintf("%s/%s/%s.json", pocBase, yr, cveID)
			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				e.mu.Lock()
				e.pocCache[cveID] = []internal.PoCEntry{}
				e.mu.Unlock()
				return
			}
			resp, err := e.client.Do(req)
			if err != nil || resp.StatusCode == 404 {
				if resp != nil {
					resp.Body.Close()
				}
				e.mu.Lock()
				e.pocCache[cveID] = []internal.PoCEntry{}
				e.mu.Unlock()
				return
			}
			defer resp.Body.Close()

			var raw []struct {
				FullName        string `json:"full_name"`
				HTMLURL         string `json:"html_url"`
				StargazersCount int    `json:"stargazers_count"`
			}
			if err := json.NewDecoder(io.LimitReader(resp.Body, maxFetchBody)).Decode(&raw); err != nil {
				return
			}

			pocs := make([]internal.PoCEntry, 0, len(raw))
			for _, p := range raw {
				pocs = append(pocs, internal.PoCEntry{Name: p.FullName, URL: p.HTMLURL, Stars: p.StargazersCount})
			}
			sortByStarsDesc(pocs)
			if len(pocs) > 5 {
				pocs = pocs[:5]
			}

			e.mu.Lock()
			e.pocCache[cveID] = pocs
			e.mu.Unlock()
		}(id, year)
	}
	wg.Wait()
}

func sortByStarsDesc(pocs []internal.PoCEntry) {
	for i := 0; i < len(pocs)-1; i++ {
		for j := i + 1; j < len(pocs); j++ {
			if pocs[j].Stars > pocs[i].Stars {
				pocs[i], pocs[j] = pocs[j], pocs[i]
			}
		}
	}
}

func isStale(t time.Time) bool {
	return time.Since(t) > cacheTTL
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
