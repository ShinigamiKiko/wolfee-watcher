package bdu

import (
	"encoding/xml"
	"strings"
)

func parseBDU(data []byte, noDetail bool) (map[string]bduEntry, map[string]*Detail, error) {
	var root bduRoot
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, nil, err
	}

	cveMap := make(map[string]bduEntry, len(root.Vulnerabilities)*2)
	var detailMap map[string]*Detail
	if !noDetail {
		detailMap = make(map[string]*Detail, len(root.Vulnerabilities))
	}

	for _, v := range root.Vulnerabilities {
		bduID := strings.TrimSpace(v.Identifier)
		if bduID == "" {
			continue
		}
		sev := normalizeSeverity(v.Severity)
		seen := map[string]bool{}
		hasAnyCVE := false
		addCVE := func(cve string) {
			cve = strings.ToUpper(strings.TrimSpace(cve))
			if cve == "" || !strings.HasPrefix(cve, "CVE-") || seen[cve] {
				return
			}
			seen[cve] = true
			hasAnyCVE = true
			if _, exists := cveMap[cve]; !exists {
				cveMap[cve] = bduEntry{BduID: bduID, Severity: sev}
			}
		}
		for _, id := range v.Identifiers.Items {
			if strings.EqualFold(id.Type, "CVE") {
				addCVE(id.Value)
			}
		}
		for _, cve := range v.CVEList.CVEs {
			addCVE(cve)
		}
		for _, cve := range v.CVE {
			addCVE(cve)
		}
		if noDetail || !hasAnyCVE {
			continue
		}
		if _, exists := detailMap[bduID]; exists {
			continue
		}
		detailMap[bduID] = buildDetail(bduID, &v)
	}
	return cveMap, detailMap, nil
}

func buildDetail(bduID string, v *bduVuln) *Detail {
	d := &Detail{
		Identifier:      bduID,
		Name:            strings.TrimSpace(v.Name),
		Description:     strings.TrimSpace(v.Description),
		Severity:        strings.TrimSpace(v.Severity),
		CVSS3Vector:     v.CVSS3.vector(),
		CVSS3Score:      v.CVSS3.score(),
		Solution:        strings.TrimSpace(v.Solution),
		FixStatus:       strings.TrimSpace(v.FixStatus),
		VulStatus:       strings.TrimSpace(v.VulStatus),
		ExploitStatus:   strings.TrimSpace(v.ExploitStatus),
		VulClass:        strings.TrimSpace(v.VulClass),
		VulElimination:  strings.TrimSpace(v.VulElimination),
		IdentifyDate:    strings.TrimSpace(v.IdentifyDate),
		PublicationDate: strings.TrimSpace(v.PublicationDate),
		LastUpdDate:     strings.TrimSpace(v.LastUpdDate),
		CVSS2Vector:     v.CVSS.vector(),
		CVSS2Score:      v.CVSS.score(),
		CVSS4Vector:     v.CVSS4.vector(),
		CVSS4Score:      v.CVSS4.score(),
	}
	appendSources(d, v)
	appendCWEs(d, v)
	appendSLOperProcs(d, v)
	appendSoftware(d, v)
	appendEnvironments(d, v)
	appendOtherIDs(d, v)
	return d
}

func appendSources(d *Detail, v *bduVuln) {
	for _, src := range v.Sources.Sources {
		if s := strings.TrimSpace(src); s != "" {
			d.Sources = append(d.Sources, s)
		}
	}
}

func appendCWEs(d *Detail, v *bduVuln) {
	for _, c := range v.CWEs.Items {
		id := strings.TrimSpace(c.Identifier)
		if id == "" {
			continue
		}
		d.CWEs = append(d.CWEs, CWE{ID: id, Name: strings.TrimSpace(c.Name)})
	}
}

func appendSLOperProcs(d *Detail, v *bduVuln) {
	for _, sop := range v.SLOperProcs.Items {
		if s := strings.TrimSpace(sop); s != "" {
			d.SLOperProcs = append(d.SLOperProcs, s)
		}
	}
}

func appendSoftware(d *Detail, v *bduVuln) {
	softs := append([]bduSoft{}, v.VulnerableSoftware.Soft...)
	softs = append(softs, v.VulnSoftwareAlt.Soft...)
	softs = append(softs, v.SoftFlat...)
	for _, s := range softs {
		sw := Software{
			Vendor:   strings.TrimSpace(s.Vendor),
			Name:     strings.TrimSpace(s.Name),
			Version:  strings.TrimSpace(s.Version),
			Platform: strings.TrimSpace(s.Platform),
		}
		for _, t := range s.Types.Items {
			if tt := strings.TrimSpace(t); tt != "" {
				sw.Types = append(sw.Types, tt)
			}
		}
		if sw.Vendor == "" && sw.Name == "" && sw.Version == "" && sw.Platform == "" && len(sw.Types) == 0 {
			continue
		}
		d.Software = append(d.Software, sw)
	}
}

func appendEnvironments(d *Detail, v *bduVuln) {
	for _, p := range v.Environment.Platforms {
		ep := EnvPlatform{
			Vendor:  strings.TrimSpace(p.Vendor),
			Name:    strings.TrimSpace(p.Name),
			Version: strings.TrimSpace(p.Version),
		}
		if ep.Vendor == "" && ep.Name == "" && ep.Version == "" {
			continue
		}
		d.Environments = append(d.Environments, ep)
	}
}

func appendOtherIDs(d *Detail, v *bduVuln) {
	for _, id := range v.Identifiers.Items {
		val := strings.TrimSpace(id.Value)
		typ := strings.TrimSpace(id.Type)
		if val == "" || strings.EqualFold(typ, "CVE") {
			continue
		}
		d.OtherIDs = append(d.OtherIDs, OtherID{Type: typ, Value: val})
	}
}

func normalizeSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "критический", "critical", "crit":
		return "critical"
	case "высокий", "high":
		return "high"
	case "средний", "medium", "med":
		return "medium"
	case "низкий", "low":
		return "low"
	case "":
		return ""
	default:
		return s
	}
}
