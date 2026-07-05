package bdu

import (
	"strings"
	"testing"
)

const sampleXML = `<?xml version="1.0" encoding="UTF-8"?>
<vulnerabilities>
  <vul>
    <identifier>BDU:2024-01234</identifier>
    <severity>Критический</severity>
    <identifiers>
      <identifier type="CVE">CVE-2024-1234</identifier>
      <identifier type="CVE">CVE-2024-5678</identifier>
    </identifiers>
  </vul>
  <vul>
    <identifier>BDU:2024-00777</identifier>
    <severity>Высокий</severity>
    <cve_list>
      <cve>CVE-2024-9999</cve>
    </cve_list>
  </vul>
  <vul>
    <identifier>BDU:2023-00001</identifier>
    <severity>Low</severity>
    <cve>CVE-2023-1111</cve>
  </vul>
  <vul>
    <!-- entry without any CVE — should be skipped -->
    <identifier>BDU:2024-NOCVE</identifier>
    <severity>Средний</severity>
  </vul>
</vulnerabilities>`

func TestParseBDU(t *testing.T) {
	m, _, err := parseBDU([]byte(sampleXML), false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	tests := []struct {
		cve, wantBDU, wantSev string
	}{
		{"CVE-2024-1234", "BDU:2024-01234", "critical"},
		{"CVE-2024-5678", "BDU:2024-01234", "critical"},
		{"CVE-2024-9999", "BDU:2024-00777", "high"},
		{"CVE-2023-1111", "BDU:2023-00001", "low"},
	}
	for _, tt := range tests {
		e, ok := m[tt.cve]
		if !ok {
			t.Errorf("%s: missing", tt.cve)
			continue
		}
		if e.BduID != tt.wantBDU {
			t.Errorf("%s: BduID=%q want %q", tt.cve, e.BduID, tt.wantBDU)
		}
		if e.Severity != tt.wantSev {
			t.Errorf("%s: Severity=%q want %q", tt.cve, e.Severity, tt.wantSev)
		}
	}
	if len(m) != 4 {
		t.Errorf("map size=%d want 4 (NOCVE entry should be skipped)", len(m))
	}
}

func TestLookupCaseInsensitive(t *testing.T) {
	e := New(Options{})

	e.mu.Lock()
	e.cveToBdu = map[string]bduEntry{
		"CVE-2024-1234": {BduID: "BDU:2024-01234", Severity: "critical"},
	}
	e.mu.Unlock()

	cases := []string{"CVE-2024-1234", "cve-2024-1234", "  CVE-2024-1234  "}
	for _, c := range cases {
		id, sev, ok := e.Lookup(c)
		if !ok || id != "BDU:2024-01234" || sev != "critical" {
			t.Errorf("Lookup(%q) = %q %q %v; want BDU:2024-01234 critical true", c, id, sev, ok)
		}
	}
	if _, _, ok := e.Lookup("CVE-9999-9999"); ok {
		t.Error("Lookup of absent CVE should return ok=false")
	}
	if _, _, ok := e.Lookup(""); ok {
		t.Error("empty CVE lookup should return ok=false")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]string{
		"Критический": "critical",
		"КРИТИЧЕСКИЙ": "critical",
		"Critical":    "critical",
		"Высокий":     "high",
		"high":        "high",
		"Средний":     "medium",
		"Medium":      "medium",
		"Низкий":      "low",
		"low":         "low",
		"":            "",
		"Unknown-XX":  "unknown-xx",
	}
	for in, want := range cases {
		if got := normalizeSeverity(in); got != want {
			t.Errorf("normalizeSeverity(%q)=%q want %q", in, got, want)
		}
	}
}

func TestUnwrapZipIfNeededPassthroughXML(t *testing.T) {
	data := []byte(strings.TrimSpace(sampleXML))
	out, err := unwrapZipIfNeeded(data)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(data) {
		t.Error("non-zip XML should pass through unchanged")
	}
}

const richXML = `<?xml version="1.0" encoding="UTF-8"?>
<vulnerabilities>
  <vul>
    <identifier>BDU:2026-05810</identifier>
    <name>Уязвимость ядра Linux позволяющая повысить привилегии</name>
    <description>Уязвимость подсистемы X ядра Linux связана с отсутствием проверки границ.</description>
    <identify_date>14.04.2026</identify_date>
    <publication_date>15.04.2026</publication_date>
    <last_upd_date>20.04.2026</last_upd_date>
    <severity>Критический (8.8)</severity>
    <vul_class>Уязвимость кода</vul_class>
    <fix_status>Уязвимость устранена</fix_status>
    <vul_status>Подтверждена производителем</vul_status>
    <exploit_status>Существует</exploit_status>
    <vul_elimination>Обновление ПО</vul_elimination>
    <solution>Установить обновление ядра.
Ссылки на патчи:
https://kernel.org/patch1
https://kernel.org/patch2</solution>
    <cvss>
      <vector>AV:N/AC:M/Au:N/C:P/I:P/A:P</vector>
      <score>6.8</score>
    </cvss>
    <cvss3>
      <vector>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</vector>
      <score>8.8</score>
    </cvss3>
    <cvss4>
      <vector></vector>
      <score>0.0</score>
    </cvss4>
    <sources>
      <source>https://kernel.org/security</source>
      <source>https://security-tracker.debian.org/tracker/CVE-2026-12345</source>
    </sources>
    <cwes>
      <cwe>
        <identifier>CWE-787</identifier>
        <name>Запись за пределами буфера</name>
      </cwe>
      <cwe>
        <identifier>CWE-119</identifier>
        <name>Некорректная проверка границ</name>
      </cwe>
    </cwes>
    <sl_oper_procs>
      <sop>Манипулирование структурами</sop>
      <sop>Инъекция</sop>
    </sl_oper_procs>
    <vulnerable_software>
      <soft>
        <vendor>Linux Foundation</vendor>
        <name>Linux Kernel</name>
        <version>от 5.10 до 6.6</version>
        <platform>x86_64</platform>
        <types>
          <type>Операционная система</type>
        </types>
      </soft>
      <soft>
        <vendor>Red Hat</vendor>
        <name>RHEL</name>
        <version>9</version>
      </soft>
    </vulnerable_software>
    <environment>
      <platform>
        <vendor>Astra Linux</vendor>
        <name>Astra Linux Special Edition</name>
        <version>1.7</version>
      </platform>
    </environment>
    <identifiers>
      <identifier type="CVE">CVE-2026-12345</identifier>
      <identifier type="DSA">DSA-5612-1</identifier>
      <identifier type="RHSA">RHSA-2026:0123</identifier>
    </identifiers>
  </vul>
</vulnerabilities>`

func TestParseBDUDetail(t *testing.T) {
	cveMap, details, err := parseBDU([]byte(richXML), false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := len(cveMap); got != 1 {
		t.Fatalf("cveMap size=%d want 1", got)
	}
	d, ok := details["BDU:2026-05810"]
	if !ok {
		t.Fatalf("missing detail for BDU:2026-05810; have keys: %v", keysOf(details))
	}
	if d.Name != "Уязвимость ядра Linux позволяющая повысить привилегии" {
		t.Errorf("Name=%q", d.Name)
	}
	if !strings.Contains(d.Description, "отсутствием проверки границ") {
		t.Errorf("Description missing key phrase: %q", d.Description)
	}
	if d.Severity != "Критический (8.8)" {
		t.Errorf("Severity=%q", d.Severity)
	}
	if d.CVSS3Score != 8.8 {
		t.Errorf("CVSS3Score=%v want 8.8", d.CVSS3Score)
	}
	if d.CVSS3Vector == "" {
		t.Errorf("CVSS3Vector empty")
	}
	if d.CVSS2Score != 6.8 {
		t.Errorf("CVSS2Score=%v want 6.8", d.CVSS2Score)
	}
	if d.CVSS4Score != 0 {
		t.Errorf("CVSS4Score=%v want 0", d.CVSS4Score)
	}
	if !strings.Contains(d.Solution, "kernel.org/patch1") {
		t.Errorf("Solution missing patch URL: %q", d.Solution)
	}
	if d.FixStatus != "Уязвимость устранена" {
		t.Errorf("FixStatus=%q", d.FixStatus)
	}
	if d.VulStatus != "Подтверждена производителем" {
		t.Errorf("VulStatus=%q", d.VulStatus)
	}
	if d.ExploitStatus != "Существует" {
		t.Errorf("ExploitStatus=%q", d.ExploitStatus)
	}
	if len(d.Sources) != 2 {
		t.Errorf("Sources len=%d want 2", len(d.Sources))
	}
	if len(d.CWEs) != 2 || d.CWEs[0].ID != "CWE-787" {
		t.Errorf("CWEs=%+v", d.CWEs)
	}
	if d.VulClass != "Уязвимость кода" {
		t.Errorf("VulClass=%q", d.VulClass)
	}
	if d.VulElimination != "Обновление ПО" {
		t.Errorf("VulElimination=%q", d.VulElimination)
	}
	if d.IdentifyDate != "14.04.2026" || d.PublicationDate != "15.04.2026" || d.LastUpdDate != "20.04.2026" {
		t.Errorf("dates: identify=%q pub=%q upd=%q", d.IdentifyDate, d.PublicationDate, d.LastUpdDate)
	}
	if len(d.SLOperProcs) != 2 {
		t.Errorf("SLOperProcs=%v", d.SLOperProcs)
	}
	if len(d.Software) != 2 {
		t.Fatalf("Software len=%d want 2: %+v", len(d.Software), d.Software)
	}
	if d.Software[0].Vendor != "Linux Foundation" || d.Software[0].Name != "Linux Kernel" {
		t.Errorf("Software[0]=%+v", d.Software[0])
	}
	if !strings.Contains(d.Software[0].Version, "5.10") {
		t.Errorf("Software[0].Version=%q", d.Software[0].Version)
	}
	if len(d.Software[0].Types) != 1 || d.Software[0].Types[0] != "Операционная система" {
		t.Errorf("Software[0].Types=%v", d.Software[0].Types)
	}
	if len(d.Environments) != 1 || d.Environments[0].Vendor != "Astra Linux" {
		t.Errorf("Environments=%+v", d.Environments)
	}
	if len(d.OtherIDs) != 2 {
		t.Fatalf("OtherIDs len=%d want 2: %+v", len(d.OtherIDs), d.OtherIDs)
	}
	if d.OtherIDs[0].Type != "DSA" || d.OtherIDs[0].Value != "DSA-5612-1" {
		t.Errorf("OtherIDs[0]=%+v", d.OtherIDs[0])
	}
	if d.OtherIDs[1].Type != "RHSA" || d.OtherIDs[1].Value != "RHSA-2026:0123" {
		t.Errorf("OtherIDs[1]=%+v", d.OtherIDs[1])
	}
}

func TestParseBDUNoDetail(t *testing.T) {
	cveMap, details, err := parseBDU([]byte(richXML), true)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cveMap) != 1 {
		t.Errorf("cveMap size=%d want 1", len(cveMap))
	}
	if details != nil {
		t.Errorf("details should be nil when noDetail=true, got %d entries", len(details))
	}
}

func TestLookupDetail(t *testing.T) {
	e := New(Options{})
	cveMap, details, err := parseBDU([]byte(richXML), false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	e.mu.Lock()
	e.cveToBdu = cveMap
	e.bduDetails = details
	e.mu.Unlock()

	d, ok := e.LookupDetail("CVE-2026-12345")
	if !ok || d == nil || d.Identifier != "BDU:2026-05810" {
		t.Errorf("LookupDetail: ok=%v d=%+v", ok, d)
	}
	if _, ok := e.LookupDetail("CVE-9999-0000"); ok {
		t.Error("LookupDetail of absent CVE should be ok=false")
	}
	if _, ok := e.LookupDetail(""); ok {
		t.Error("LookupDetail of empty should be ok=false")
	}
}

const realSchemaXML = `<?xml version="1.0" encoding="UTF-8"?>
<vulnerabilities>
  <vul>
    <identifier>BDU:2026-04122</identifier>
    <name>Уязвимость функций File.ReadDir() и File.Readdir()</name>
    <description>Уязвимость связана с неправильным ограничением пути.</description>
    <severity>Низкий (2.5)</severity>
    <cvss>
      <vector score="1.6">AV:L/AC:H/Au:S/C:P/I:N/A:N</vector>
    </cvss>
    <cvss3>
      <vector score="2.5">AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N</vector>
    </cvss3>
    <identifiers>
      <identifier type="CVE">CVE-2026-27139</identifier>
    </identifiers>
  </vul>
</vulnerabilities>`

func TestParseBDUCVSSAttributeSchema(t *testing.T) {
	_, details, err := parseBDU([]byte(realSchemaXML), false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	d, ok := details["BDU:2026-04122"]
	if !ok {
		t.Fatalf("missing detail; have keys: %v", keysOf(details))
	}
	if d.CVSS3Score != 2.5 {
		t.Errorf("CVSS3Score=%v want 2.5", d.CVSS3Score)
	}
	if d.CVSS3Vector != "AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N" {
		t.Errorf("CVSS3Vector=%q", d.CVSS3Vector)
	}
	if d.CVSS2Score != 1.6 {
		t.Errorf("CVSS2Score=%v want 1.6", d.CVSS2Score)
	}
	if d.CVSS2Vector != "AV:L/AC:H/Au:S/C:P/I:N/A:N" {
		t.Errorf("CVSS2Vector=%q", d.CVSS2Vector)
	}
}

func TestParseScore(t *testing.T) {
	cases := map[string]float64{
		"":        0,
		"8.8":     8.8,
		"  6.8  ": 6.8,
		"6,8":     6.8,
		"abc":     0,
		"0.0":     0,
	}
	for in, want := range cases {
		if got := parseScore(in); got != want {
			t.Errorf("parseScore(%q)=%v want %v", in, got, want)
		}
	}
}

func keysOf(m map[string]*Detail) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
