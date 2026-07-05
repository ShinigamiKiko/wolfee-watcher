package grype

import (
	"strings"
	"time"

	internal "github.com/wolfee-watcher/scanner-agent/internal"
)

func buildResult(ref string, r grypeReport, dur time.Duration) *internal.ScanResult {
	name, tag, digest := parseRef(ref)

	osName := r.Distro.Name
	if osName == "" {
		osName = r.Source.Target.ArtifactMetadata.OS.Name
	}
	osVer := r.Distro.Version
	if osVer == "" {
		osVer = r.Source.Target.ArtifactMetadata.OS.Version
	}
	osDisplay := osName
	if osVer != "" {
		osDisplay = osName + " " + osVer
	}
	if digest == "" {
		digest = r.Source.Target.ManifestDigest
	}

	if !strings.HasPrefix(digest, "sha256:") {
		for _, rd := range r.Source.Target.RepoDigests {
			if at := strings.LastIndex(rd, "@sha256:"); at >= 0 {
				digest = rd[at+1:]
				break
			}
		}
	}

	res := &internal.ScanResult{
		Image:      ref,
		Name:       name,
		Tag:        tag,
		Digest:     digest,
		OS:         osDisplay,
		OSFamily:   osName,
		Status:     internal.StatusDone,
		ScannedAt:  time.Now(),
		DurationMs: dur.Milliseconds(),
	}

	for _, match := range r.Matches {
		cve := convertMatch(match)
		res.CVEs = append(res.CVEs, cve)

		switch strings.ToLower(match.Vulnerability.Severity) {
		case "critical":
			res.Summary.Critical++
		case "high":
			res.Summary.High++
		case "medium":
			res.Summary.Medium++
		case "low":
			res.Summary.Low++
		default:
			res.Summary.Unknown++
		}
		res.Summary.Total++
		if match.Vulnerability.Fix.State == "fixed" {
			res.Summary.Fixable++
		}
	}

	return res
}

func convertMatch(m grypeMatch) internal.CVE {
	v := m.Vulnerability
	a := m.Artifact

	cve := internal.CVE{
		ID:            v.ID,
		Severity:      strings.ToUpper(v.Severity),
		PkgName:       a.Name,
		PkgVersion:    a.Version,
		PkgType:       a.Type,
		PkgLicense:    strings.Join(a.Licenses, ", "),
		Description:   v.Description,
		References:    v.URLs,
		HasFix:        v.Fix.State == "fixed",
		FixState:      v.Fix.State,
		PublishedDate: v.PublishedDate,
	}
	if len(v.Fix.Versions) > 0 {
		cve.FixedIn = strings.Join(v.Fix.Versions, ", ")
	}
	for _, c := range v.CWEs {
		if c.CweID != "" {
			cve.CWEs = append(cve.CWEs, c.CweID)
		}
	}

	bestV3, bestV2 := pickBestCVSS(v.CVSS)
	if bestV3 != nil {
		cve.CVSSv3Score = bestV3.Metrics.BaseScore
		cve.CVSSv3Vector = bestV3.Vector
	}
	if bestV2 != nil {
		cve.CVSSv2Score = bestV2.Metrics.BaseScore
	}

	if cve.CVSSv3Score == 0 {
		for _, related := range m.RelatedVulnerabilities {
			if b3, b2 := pickBestCVSS(related.CVSS); b3 != nil {
				cve.CVSSv3Score = b3.Metrics.BaseScore
				cve.CVSSv3Vector = b3.Vector
				if b2 != nil {
					cve.CVSSv2Score = b2.Metrics.BaseScore
				}
				break
			}
		}
	}

	return cve
}

func pickBestCVSS(scores []grypeCVSS) (v3, v2 *grypeCVSS) {
	var v3s, v2s []*grypeCVSS
	for i := range scores {
		s := &scores[i]
		if strings.HasPrefix(s.Version, "3") {
			v3s = append(v3s, s)
		} else if strings.HasPrefix(s.Version, "2") {
			v2s = append(v2s, s)
		}
	}
	pick := func(list []*grypeCVSS) *grypeCVSS {
		if len(list) == 0 {
			return nil
		}
		for _, s := range list {
			if strings.Contains(strings.ToLower(s.Source), "nvd") {
				return s
			}
		}
		return list[0]
	}
	return pick(v3s), pick(v2s)
}

func parseRef(ref string) (name, tag, digest string) {
	ref = strings.TrimPrefix(ref, "registry:")
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
