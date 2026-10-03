package bdu

import (
	"encoding/xml"
	"errors"
	"io"
	"strconv"
	"strings"
)

type interner struct {
	strs map[string]string
	soft map[string]*Software
}

func newInterner() *interner {
	return &interner{
		strs: make(map[string]string, 1<<16),
		soft: make(map[string]*Software, 1<<16),
	}
}

func (in *interner) str(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if got, ok := in.strs[v]; ok {
		return got
	}
	c := strings.Clone(v)
	in.strs[c] = c
	return c
}

func (in *interner) software(s Software) *Software {
	key := s.Vendor + "\x00" + s.Name + "\x00" + s.Version + "\x00" + s.Platform + "\x00" + strings.Join(s.Types, "\x01")
	if got, ok := in.soft[key]; ok {
		return got
	}
	c := s
	in.soft[strings.Clone(key)] = &c
	return &c
}

func text(v string) string {
	return strings.Clone(strings.TrimSpace(v))
}

func parseBDU(r io.Reader, noDetail bool) (map[string]bduEntry, map[string]*Detail, error) {
	dec := xml.NewDecoder(r)
	in := newInterner()
	cveMap := make(map[string]bduEntry, 1<<17)
	var detailMap map[string]*Detail
	if !noDetail {
		detailMap = make(map[string]*Detail, 1<<17)
	}

	seenRoot := false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "vulnerabilities":
			seenRoot = true
		case "vul":
			var v bduVuln
			if err := dec.DecodeElement(&v, &se); err != nil {
				return nil, nil, err
			}
			addVulnerability(cveMap, detailMap, &v, in, noDetail)
		}
	}
	if !seenRoot {
		return nil, nil, errors.New("expected element type <vulnerabilities>")
	}
	return cveMap, detailMap, nil
}

func addVulnerability(cveMap map[string]bduEntry, detailMap map[string]*Detail, v *bduVuln, in *interner, noDetail bool) {
	bduID := in.str(v.Identifier)
	if bduID == "" {
		return
	}
	sev := in.str(normalizeSeverity(v.Severity))
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
		return
	}
	if _, exists := detailMap[bduID]; exists {
		return
	}
	detailMap[bduID] = buildDetail(bduID, v, in)
}

func buildDetail(bduID string, v *bduVuln, in *interner) *Detail {
	d := &Detail{
		Identifier:      bduID,
		Name:            text(v.Name),
		Description:     text(v.Description),
		Severity:        in.str(v.Severity),
		CVSS3Vector:     in.str(v.CVSS3.vector()),
		CVSS3Score:      v.CVSS3.score(),
		Solution:        text(v.Solution),
		FixStatus:       in.str(v.FixStatus),
		VulStatus:       in.str(v.VulStatus),
		ExploitStatus:   in.str(v.ExploitStatus),
		VulClass:        in.str(v.VulClass),
		VulElimination:  text(v.VulElimination),
		IdentifyDate:    in.str(v.IdentifyDate),
		PublicationDate: in.str(v.PublicationDate),
		LastUpdDate:     in.str(v.LastUpdDate),
		CVSS2Vector:     in.str(v.CVSS.vector()),
		CVSS2Score:      v.CVSS.score(),
		CVSS4Vector:     in.str(v.CVSS4.vector()),
		CVSS4Score:      v.CVSS4.score(),
	}
	appendSources(d, v, in)
	appendCWEs(d, v, in)
	appendSLOperProcs(d, v, in)
	appendSoftware(d, v, in)
	appendEnvironments(d, v, in)
	appendOtherIDs(d, v, in)
	return d
}

func appendSources(d *Detail, v *bduVuln, in *interner) {
	for _, src := range v.Sources.Sources {
		if s := in.str(src); s != "" {
			d.Sources = append(d.Sources, s)
		}
	}
}

func appendCWEs(d *Detail, v *bduVuln, in *interner) {
	for _, c := range v.CWEs.Items {
		id := in.str(c.Identifier)
		if id == "" {
			continue
		}
		d.CWEs = append(d.CWEs, CWE{ID: id, Name: in.str(c.Name)})
	}
}

func appendSLOperProcs(d *Detail, v *bduVuln, in *interner) {
	for _, sop := range v.SLOperProcs.Items {
		if s := in.str(sop); s != "" {
			d.SLOperProcs = append(d.SLOperProcs, s)
		}
	}
}

func appendSoftware(d *Detail, v *bduVuln, in *interner) {
	softs := make([]bduSoft, 0, len(v.VulnerableSoftware.Soft)+len(v.VulnSoftwareAlt.Soft)+len(v.SoftFlat))
	softs = append(softs, v.VulnerableSoftware.Soft...)
	softs = append(softs, v.VulnSoftwareAlt.Soft...)
	softs = append(softs, v.SoftFlat...)
	for _, s := range softs {
		sw := Software{
			Vendor:   in.str(s.Vendor),
			Name:     in.str(s.Name),
			Version:  in.str(s.Version),
			Platform: in.str(s.Platform),
		}
		for _, t := range s.Types.Items {
			if tt := in.str(t); tt != "" {
				sw.Types = append(sw.Types, tt)
			}
		}
		if sw.Vendor == "" && sw.Name == "" && sw.Version == "" && sw.Platform == "" && len(sw.Types) == 0 {
			continue
		}
		d.Software = append(d.Software, in.software(sw))
	}
}

func appendEnvironments(d *Detail, v *bduVuln, in *interner) {
	for _, p := range v.Environment.Platforms {
		ep := EnvPlatform{
			Vendor:  in.str(p.Vendor),
			Name:    in.str(p.Name),
			Version: in.str(p.Version),
		}
		if ep.Vendor == "" && ep.Name == "" && ep.Version == "" {
			continue
		}
		d.Environments = append(d.Environments, ep)
	}
}

func appendOtherIDs(d *Detail, v *bduVuln, in *interner) {
	for _, id := range v.Identifiers.Items {
		val := in.str(id.Value)
		typ := in.str(id.Type)
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

func parseScore(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	s = strings.ReplaceAll(s, ",", ".")
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return f
}
