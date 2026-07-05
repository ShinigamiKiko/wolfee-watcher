package parser

import (
	"encoding/json"
	"strings"
)

type BenchReport struct {
	Controls []BenchControl `json:"controls"`
	Totals   BenchTotals    `json:"totals"`
}

type BenchTotals struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
	Warn int `json:"warn"`
	Info int `json:"info"`
}

type BenchControl struct {
	ID       string      `json:"id"`
	Text     string      `json:"text"`
	NodeType string      `json:"node_type,omitempty"`
	Version  string      `json:"version,omitempty"`
	Pass     int         `json:"pass"`
	Fail     int         `json:"fail"`
	Warn     int         `json:"warn"`
	Info     int         `json:"info"`
	Tests    []BenchTest `json:"tests"`
}

type BenchTest struct {
	Number      string `json:"number"`
	Desc        string `json:"desc"`
	Status      string `json:"status"`
	Scored      bool   `json:"scored"`
	Actual      string `json:"actual,omitempty"`
	Expected    string `json:"expected,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

type benchRaw struct {
	Controls []struct {
		ID        string `json:"id"`
		Version   string `json:"version"`
		Text      string `json:"text"`
		NodeType  string `json:"node_type"`
		TotalPass int    `json:"total_pass"`
		TotalFail int    `json:"total_fail"`
		TotalWarn int    `json:"total_warn"`
		TotalInfo int    `json:"total_info"`
		Tests     []struct {
			Section string `json:"section"`
			Desc    string `json:"desc"`
			Pass    int    `json:"pass"`
			Fail    int    `json:"fail"`
			Warn    int    `json:"warn"`
			Info    int    `json:"info"`
			Results []struct {
				TestNumber     string `json:"test_number"`
				TestDesc       string `json:"test_desc"`
				Status         string `json:"status"`
				Scored         bool   `json:"scored"`
				IsMultiple     bool   `json:"IsMultiple"`
				ActualValue    string `json:"actual_value"`
				ExpectedResult string `json:"expected_result"`
				Reason         string `json:"reason"`
				Remediation    string `json:"remediation"`
			} `json:"results"`
		} `json:"tests"`
	} `json:"Controls"`
	Totals struct {
		TotalPass int `json:"total_pass"`
		TotalFail int `json:"total_fail"`
		TotalWarn int `json:"total_warn"`
		TotalInfo int `json:"total_info"`
	} `json:"Totals"`
}

func ParseBench(raw string) *BenchReport {
	raw = strings.TrimSpace(raw)
	var out benchRaw

	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		idx := strings.Index(raw, "{")
		if idx < 0 {
			return nil
		}
		if err2 := json.Unmarshal([]byte(raw[idx:]), &out); err2 != nil {
			return nil
		}
	}

	report := &BenchReport{
		Totals: BenchTotals{
			Pass: out.Totals.TotalPass,
			Fail: out.Totals.TotalFail,
			Warn: out.Totals.TotalWarn,
			Info: out.Totals.TotalInfo,
		},
	}

	for _, c := range out.Controls {
		ctrl := BenchControl{
			ID:       c.ID,
			Text:     c.Text,
			NodeType: c.NodeType,
			Version:  c.Version,
			Pass:     c.TotalPass,
			Fail:     c.TotalFail,
			Warn:     c.TotalWarn,
			Info:     c.TotalInfo,
		}
		for _, t := range c.Tests {
			for _, r := range t.Results {
				ctrl.Tests = append(ctrl.Tests, BenchTest{
					Number:      r.TestNumber,
					Desc:        r.TestDesc,
					Status:      strings.ToUpper(r.Status),
					Scored:      r.Scored,
					Actual:      r.ActualValue,
					Expected:    r.ExpectedResult,
					Reason:      r.Reason,
					Remediation: r.Remediation,
				})

				if c.TotalPass+c.TotalFail+c.TotalWarn+c.TotalInfo == 0 {
					switch strings.ToUpper(r.Status) {
					case "PASS":
						ctrl.Pass++
						report.Totals.Pass++
					case "FAIL":
						ctrl.Fail++
						report.Totals.Fail++
					case "WARN":
						ctrl.Warn++
						report.Totals.Warn++
					default:
						ctrl.Info++
						report.Totals.Info++
					}
				}
			}
		}
		report.Controls = append(report.Controls, ctrl)
	}

	if report.Totals.Pass+report.Totals.Fail+report.Totals.Warn+report.Totals.Info == 0 {
		for _, c := range report.Controls {
			report.Totals.Pass += c.Pass
			report.Totals.Fail += c.Fail
			report.Totals.Warn += c.Warn
			report.Totals.Info += c.Info
		}
	}

	return report
}

type HunterReport struct {
	Nodes           []HunterNode `json:"nodes"`
	Services        []HunterSvc  `json:"services"`
	Vulnerabilities []HunterVuln `json:"vulnerabilities"`
	Totals          HunterTotals `json:"totals"`
}

type HunterTotals struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	None     int `json:"none"`
}

type HunterNode struct {
	Type     string `json:"type"`
	Location string `json:"location"`
}

type HunterSvc struct {
	Service  string `json:"service"`
	Location string `json:"location"`
}

type HunterVuln struct {
	ID            string `json:"id"`
	Vulnerability string `json:"vulnerability"`
	Description   string `json:"description"`
	Severity      string `json:"severity"`
	Category      string `json:"category,omitempty"`
	Location      string `json:"location,omitempty"`
	Evidence      string `json:"evidence,omitempty"`
	MITRE         string `json:"mitre,omitempty"`
	AvdLink       string `json:"avd_link,omitempty"`
	Hunter        string `json:"hunter,omitempty"`

	AVDDescription string `json:"avd_description,omitempty"`
	AVDRemediation string `json:"avd_remediation,omitempty"`
	AVDImpact      string `json:"avd_impact,omitempty"`
}

type hunterRaw struct {
	Nodes []struct {
		Type     string `json:"type"`
		Location string `json:"location"`
	} `json:"nodes"`
	Services []struct {
		Service  string `json:"service"`
		Location string `json:"location"`
	} `json:"services"`
	Vulnerabilities []struct {
		VID           string `json:"vid"`
		Name          string `json:"vulnerability"`
		Description   string `json:"description"`
		Severity      string `json:"severity"`
		Category      string `json:"category"`
		Location      string `json:"location"`
		Evidence      string `json:"evidence"`
		MITRECategory string `json:"mitre_category"`
		AvdReference  string `json:"avd_reference"`
		Hunter        string `json:"hunter"`
	} `json:"vulnerabilities"`
}

func ParseHunter(raw string) *HunterReport {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return &HunterReport{}
	}

	var out hunterRaw

	if err := json.Unmarshal([]byte(raw), &out); err == nil {
		return buildReport(out)
	}

	lines := strings.Split(raw, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, "{") {
			continue
		}
		candidate := strings.Join(lines[i:], "\n")
		if err := json.Unmarshal([]byte(candidate), &out); err == nil {
			return buildReport(out)
		}
	}

	idx := strings.Index(raw, "{")
	if idx >= 0 {
		if err := json.Unmarshal([]byte(raw[idx:]), &out); err == nil {
			return buildReport(out)
		}
	}

	return &HunterReport{}
}

func buildReport(out hunterRaw) *HunterReport {
	r := &HunterReport{}

	for _, n := range out.Nodes {
		r.Nodes = append(r.Nodes, HunterNode{Type: n.Type, Location: n.Location})
	}
	for _, s := range out.Services {
		r.Services = append(r.Services, HunterSvc{Service: s.Service, Location: s.Location})
	}
	for _, v := range out.Vulnerabilities {
		sev := strings.ToLower(v.Severity)
		r.Vulnerabilities = append(r.Vulnerabilities, HunterVuln{
			ID:            v.VID,
			Vulnerability: v.Name,
			Description:   v.Description,
			Severity:      sev,
			Category:      v.Category,
			Location:      v.Location,
			Evidence:      v.Evidence,
			MITRE:         v.MITRECategory,
			AvdLink:       v.AvdReference,
			Hunter:        v.Hunter,
		})
		switch sev {
		case "critical":
			r.Totals.Critical++
		case "high":
			r.Totals.High++
		case "medium":
			r.Totals.Medium++
		case "low":
			r.Totals.Low++
		default:
			r.Totals.None++
		}
	}
	return r
}
