package enricher

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/wolfee-watcher/audit-runner/internal/parser"
)

const (
	httpTimeout = 15 * time.Second
	maxWorkers  = 4

	avdBase = "https://avd.aquasec.com/misconfig/kubernetes/%s/"
)

func EnrichReport(report *parser.HunterReport) {
	if report == nil || len(report.Vulnerabilities) == 0 {
		return
	}

	type job struct {
		idx int
		vid string
		url string
	}

	var jobs []job
	for i, v := range report.Vulnerabilities {
		if v.ID == "" {
			continue
		}

		url := fmt.Sprintf(avdBase, strings.ToLower(v.ID))
		jobs = append(jobs, job{i, v.ID, url})
	}

	if len(jobs) == 0 {
		return
	}

	sem := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup

	for _, j := range jobs {
		j := j
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			d, err := fetchAVD(j.url)
			if err != nil {
				log.Printf("[enricher] %s: %v", j.vid, err)
				return
			}
			if d.Remediation != "" {
				report.Vulnerabilities[j.idx].AVDRemediation = d.Remediation
			}
			if d.Description != "" {
				report.Vulnerabilities[j.idx].AVDDescription = d.Description
			}
			log.Printf("[enricher] %s: desc=%d chars, remediation=%d chars",
				j.vid, len(d.Description), len(d.Remediation))
		}()
	}
	wg.Wait()
}

type avdData struct {
	Description string
	Remediation string
}

var (
	reTag    = regexp.MustCompile(`<[^>]+>`)
	reSpaces = regexp.MustCompile(`\s{2,}`)
)

func fetchAVD(url string) (avdData, error) {
	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return avdData{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return avdData{}, fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return avdData{}, err
	}
	return parseAVD(string(body)), nil
}

func parseAVD(html string) avdData {
	var d avdData

	reH3 := regexp.MustCompile(`(?i)<h3[^>]*>(.*?)</h3>`)
	h3s := reH3.FindAllStringSubmatchIndex(html, -1)

	for i, m := range h3s {
		heading := cleanText(html[m[2]:m[3]])
		lh := strings.ToLower(heading)

		var target *string
		switch {
		case strings.Contains(lh, "recommended") || strings.Contains(lh, "remediat") ||
			strings.Contains(lh, "solution") || strings.Contains(lh, "fix"):
			target = &d.Remediation
		case strings.Contains(lh, "description") || strings.Contains(lh, "overview"):
			target = &d.Description
		default:

			if i == 0 && d.Description == "" {
				target = &d.Description
			}
		}
		if target == nil || *target != "" {
			continue
		}

		start := m[1]
		end := len(html)
		if i+1 < len(h3s) {
			end = h3s[i+1][0]
		}
		if end-start > 2000 {
			end = start + 2000
		}

		text := extractText(html[start:end])
		if text != "" {
			*target = text
		}
	}
	return d
}

func extractText(block string) string {
	reP := regexp.MustCompile(`(?is)<p[^>]*>(.*?)</p>`)
	ms := reP.FindAllStringSubmatch(block, -1)
	var parts []string
	for _, m := range ms {
		t := cleanText(m[1])
		if len(t) > 8 {
			parts = append(parts, t)
		}
	}
	if len(parts) > 0 {
		return strings.Join(parts, "\n\n")
	}

	t := cleanText(block)
	if len(t) > 20 {
		return t
	}
	return ""
}

func cleanText(s string) string {
	s = reTag.ReplaceAllString(s, " ")
	s = strings.NewReplacer(
		"&amp;", "&", "&lt;", "<", "&gt;", ">",
		"&quot;", `"`, "&#39;", "'", "&nbsp;", " ",
	).Replace(s)
	s = reSpaces.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}
