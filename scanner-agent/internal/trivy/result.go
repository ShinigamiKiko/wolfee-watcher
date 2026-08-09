package trivy

import (
	"sort"
	"strings"
	"time"

	internal "github.com/wolfee-watcher/scanner-agent/internal"
)

func buildResult(ref string, r trivyReport, dur time.Duration) *internal.ScanResult {
	name, tag, digest := parseRef(ref)

	osFamily := r.Metadata.OS.Family
	osVer := r.Metadata.OS.Name
	osDisplay := osFamily
	switch {
	case osFamily == "":
		osDisplay = osVer
	case osVer != "":
		osDisplay = osFamily + " " + osVer
	}

	if !strings.HasPrefix(digest, "sha256:") {
		for _, rd := range r.Metadata.RepoDigests {
			if at := strings.LastIndex(rd, "@sha256:"); at >= 0 {
				digest = rd[at+1:]
				break
			}
		}
	}
	if digest == "" {
		digest = r.Metadata.ImageID
	}

	res := &internal.ScanResult{
		Image:      ref,
		Name:       name,
		Tag:        tag,
		Digest:     digest,
		OS:         osDisplay,
		OSFamily:   osFamily,
		Status:     internal.StatusDone,
		ScannedAt:  time.Now(),
		DurationMs: dur.Milliseconds(),
	}

	licenses := collectLicenses(r)

	for _, tr := range r.Results {
		for _, v := range tr.Vulnerabilities {
			cve := convertVuln(v, tr, licenses)
			res.CVEs = append(res.CVEs, cve)

			switch cve.Severity {
			case "CRITICAL":
				res.Summary.Critical++
			case "HIGH":
				res.Summary.High++
			case "MEDIUM":
				res.Summary.Medium++
			case "LOW":
				res.Summary.Low++
			default:
				res.Summary.Unknown++
			}
			res.Summary.Total++
			if cve.HasFix {
				res.Summary.Fixable++
			}
		}
	}

	return res
}

func collectLicenses(r trivyReport) map[string]string {
	out := map[string]string{}
	seen := map[string]map[string]bool{}
	for _, tr := range r.Results {
		for _, l := range tr.Licenses {
			if l.PkgName == "" || l.Name == "" {
				continue
			}
			if seen[l.PkgName] == nil {
				seen[l.PkgName] = map[string]bool{}
			}
			if seen[l.PkgName][l.Name] {
				continue
			}
			seen[l.PkgName][l.Name] = true
			if out[l.PkgName] == "" {
				out[l.PkgName] = l.Name
			} else {
				out[l.PkgName] += ", " + l.Name
			}
		}
	}
	return out
}

func convertVuln(v trivyVuln, tr trivyResult, licenses map[string]string) internal.CVE {
	sev := strings.ToUpper(strings.TrimSpace(v.Severity))
	if sev == "" {
		sev = "UNKNOWN"
	}

	cve := internal.CVE{
		ID:            v.VulnerabilityID,
		Severity:      sev,
		PkgName:       v.PkgName,
		PkgVersion:    v.InstalledVersion,
		PkgType:       pkgType(v.PkgIdentifier.PURL, tr.Type),
		PkgLicense:    licenses[v.PkgName],
		Title:         v.Title,
		Description:   v.Description,
		References:    v.References,
		FixedIn:       v.FixedVersion,
		FixState:      normalizeStatus(v.Status, v.FixedVersion),
		PublishedDate: normalizeDate(v.PublishedDate),
		CWEs:          v.CweIDs,
	}
	cve.HasFix = cve.FixState == "fixed"

	if len(cve.References) == 0 && v.PrimaryURL != "" {
		cve.References = []string{v.PrimaryURL}
	}

	v2, v3, v4 := pickBestCVSS(v.CVSS, v.SeveritySource)
	if v3 != nil {
		cve.CVSSv3Score = v3.V3Score
		cve.CVSSv3Vector = v3.V3Vector
	}
	if v2 != nil {
		cve.CVSSv2Score = v2.V2Score
		cve.CVSSv2Vector = v2.V2Vector
	}
	if v4 != nil {
		cve.CVSSv4Score = v4.V40Score
		cve.CVSSv4Vector = v4.V40Vector
	}

	return cve
}

func pickBestCVSS(scores map[string]trivyCVSS, preferred string) (v2, v3, v4 *trivyCVSS) {
	if len(scores) == 0 {
		return nil, nil, nil
	}

	rest := make([]string, 0, len(scores))
	for k := range scores {
		rest = append(rest, k)
	}
	sort.Strings(rest)

	order := make([]string, 0, len(scores)+2)
	for _, k := range []string{strings.ToLower(strings.TrimSpace(preferred)), "nvd", "redhat"} {
		if k == "" {
			continue
		}
		if _, ok := scores[k]; ok {
			order = append(order, k)
		}
	}
	order = append(order, rest...)

	for _, k := range order {
		s := scores[k]
		if v3 == nil && s.V3Score > 0 {
			c := s
			v3 = &c
		}
		if v2 == nil && s.V2Score > 0 {
			c := s
			v2 = &c
		}
		if v4 == nil && s.V40Score > 0 {
			c := s
			v4 = &c
		}
	}
	return v2, v3, v4
}

func normalizeStatus(status, fixedVersion string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "fixed":
		return "fixed"
	case "will_not_fix", "end_of_life":
		return "wont-fix"
	case "affected", "fix_deferred":
		return "not-fixed"
	}
	if fixedVersion != "" {
		return "fixed"
	}
	return "unknown"
}

func normalizeDate(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format("2006-01-02")
		}
	}
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

func pkgType(purl, resultType string) string {
	if strings.HasPrefix(purl, "pkg:") {
		rest := purl[len("pkg:"):]
		if idx := strings.IndexAny(rest, "/@"); idx > 0 {
			return rest[:idx]
		}
	}
	return resultType
}

func parseRef(ref string) (name, tag, digest string) {
	if strings.HasPrefix(ref, "sha256:") && !strings.Contains(ref, "/") {
		return ref, "", ref
	}
	if idx := strings.Index(ref, "@"); idx >= 0 {
		digest = ref[idx+1:]
		ref = ref[:idx]
	}
	lastSlash := strings.LastIndex(ref, "/")
	sub := ref[lastSlash+1:]
	if idx := strings.LastIndex(sub, ":"); idx >= 0 {
		tag = sub[idx+1:]
		name = ref[:lastSlash+1] + sub[:idx]
	} else {
		tag = "latest"
		name = ref
	}
	return
}
