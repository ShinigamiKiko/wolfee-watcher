package bdu

import (
	"encoding/xml"
	"strconv"
	"strings"
)

type bduRoot struct {
	XMLName         xml.Name  `xml:"vulnerabilities"`
	Vulnerabilities []bduVuln `xml:"vul"`
}

type bduVuln struct {
	Identifier      string           `xml:"identifier"`
	Name            string           `xml:"name"`
	Description     string           `xml:"description"`
	Identifiers     bduIdentifiers   `xml:"identifiers"`
	Severity        string           `xml:"severity"`
	CVEList         bduCVEListNested `xml:"cve_list"`
	CVE             []string         `xml:"cve"`
	IdentifyDate    string           `xml:"identify_date"`
	PublicationDate string           `xml:"publication_date"`
	LastUpdDate     string           `xml:"last_upd_date"`
	VulClass        string           `xml:"vul_class"`
	FixStatus       string           `xml:"fix_status"`
	VulStatus       string           `xml:"vul_status"`
	ExploitStatus   string           `xml:"exploit_status"`
	VulElimination  string           `xml:"vul_elimination"`
	Solution        string           `xml:"solution"`

	CVSS  bduCVSS `xml:"cvss"`
	CVSS3 bduCVSS `xml:"cvss3"`
	CVSS4 bduCVSS `xml:"cvss4"`

	Sources     bduSources     `xml:"sources"`
	CWEs        bduCWEs        `xml:"cwes"`
	SLOperProcs bduSLOperProcs `xml:"sl_oper_procs"`

	VulnerableSoftware bduVulnSoftware `xml:"vulnerable_software"`
	VulnSoftwareAlt    bduVulnSoftware `xml:"vuln_software"`
	SoftFlat           []bduSoft       `xml:"soft"`
	Environment        bduEnvironment  `xml:"environment"`
}

type bduIdentifiers struct {
	Items []bduIdent `xml:"identifier"`
}

type bduIdent struct {
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}

type bduCVEListNested struct {
	CVEs []string `xml:"cve"`
}

type bduCVSS struct {
	Vector    bduVectorEl `xml:"vector"`
	ScoreElem string      `xml:"score"`
}

type bduVectorEl struct {
	Text  string `xml:",chardata"`
	Score string `xml:"score,attr"`
}

func (c bduCVSS) vector() string { return strings.TrimSpace(c.Vector.Text) }

func (c bduCVSS) score() float64 {
	if s := strings.TrimSpace(c.Vector.Score); s != "" {
		return parseScore(s)
	}
	return parseScore(c.ScoreElem)
}

type bduSources struct {
	Sources []string `xml:"source"`
}

type bduCWEs struct {
	Items []bduCWE `xml:"cwe"`
}

type bduCWE struct {
	Identifier string `xml:"identifier"`
	Name       string `xml:"name"`
}

type bduSLOperProcs struct {
	Items []string `xml:"sop"`
}

type bduVulnSoftware struct {
	Soft []bduSoft `xml:"soft"`
}

type bduSoft struct {
	Vendor   string      `xml:"vendor"`
	Name     string      `xml:"name"`
	Version  string      `xml:"version"`
	Platform string      `xml:"platform"`
	Types    bduSoftType `xml:"types"`
}

type bduSoftType struct {
	Items []string `xml:"type"`
}

type bduEnvironment struct {
	Platforms []bduEnvPlatform `xml:"platform"`
}

type bduEnvPlatform struct {
	Vendor  string `xml:"vendor"`
	Name    string `xml:"name"`
	Version string `xml:"version"`
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
