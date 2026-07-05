package internal

import "time"

type ClusterImage struct {
	Ref        string   `json:"ref"`
	Name       string   `json:"name"`
	Tag        string   `json:"tag"`
	Digest     string   `json:"digest,omitempty"`
	Pods       []string `json:"pods"`
	Namespaces []string `json:"namespaces"`
	Nodes      []string `json:"nodes"`
	PullPolicy string   `json:"pullPolicy,omitempty"`
}

type ScanStatus string

const (
	StatusPending  ScanStatus = "pending"
	StatusScanning ScanStatus = "scanning"
	StatusDone     ScanStatus = "done"
	StatusError    ScanStatus = "error"
)

type ScanResult struct {
	Image  string `json:"image"`
	Name   string `json:"name"`
	Tag    string `json:"tag"`
	Digest string `json:"digest,omitempty"`

	PreviousDigest  string     `json:"previousDigest,omitempty"`
	DigestChanged   bool       `json:"digestChanged,omitempty"`
	DigestChangedAt *time.Time `json:"digestChangedAt,omitempty"`
	OS              string     `json:"os"`
	OSFamily        string     `json:"osFamily"`
	Status          ScanStatus `json:"status"`
	Error           string     `json:"error,omitempty"`
	ScannedAt       time.Time  `json:"scannedAt"`
	DurationMs      int64      `json:"durationMs"`
	Summary         CVESummary `json:"summary"`
	CVEs            []CVE      `json:"cves"`
	Pods            []string   `json:"pods,omitempty"`
	Namespaces      []string   `json:"namespaces,omitempty"`
	Nodes           []string   `json:"nodes,omitempty"`
}

type CVESummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
	Total    int `json:"total"`
	Fixable  int `json:"fixable"`
	InKEV    int `json:"inKev"`
	HasPoC   int `json:"hasPoc"`
}

type CVE struct {
	ID            string   `json:"id"`
	Severity      string   `json:"severity"`
	PkgName       string   `json:"pkgName"`
	PkgVersion    string   `json:"pkgVersion"`
	PkgType       string   `json:"pkgType,omitempty"`
	PkgLicense    string   `json:"pkgLicense,omitempty"`
	FixedIn       string   `json:"fixedIn,omitempty"`
	FixState      string   `json:"fixState,omitempty"`
	Title         string   `json:"title,omitempty"`
	Description   string   `json:"description,omitempty"`
	References    []string `json:"references,omitempty"`
	PublishedDate string   `json:"publishedDate,omitempty"`
	CWEs          []string `json:"cwes,omitempty"`

	CVSSv3Score  float64 `json:"cvssV3Score"`
	CVSSv3Vector string  `json:"cvssV3Vector,omitempty"`
	CVSSv2Score  float64 `json:"cvssV2Score,omitempty"`
	CVSSv2Vector string  `json:"cvssV2Vector,omitempty"`
	CVSSv4Score  float64 `json:"cvssV4Score,omitempty"`
	CVSSv4Vector string  `json:"cvssV4Vector,omitempty"`

	EPSSScore      float64 `json:"epssScore"`
	EPSSPercentile float64 `json:"epssPercentile"`

	InKEV bool `json:"inKev"`

	PoCs []PoCEntry `json:"pocs,omitempty"`

	VEXStatus string `json:"vexStatus,omitempty"`
	VEXSource string `json:"vexSource,omitempty"`

	RiskScore int    `json:"riskScore"`
	RiskLabel string `json:"riskLabel"`

	HasFix bool `json:"hasFix"`

	BduID       string `json:"bduId,omitempty"`
	BduSeverity string `json:"bduSeverity,omitempty"`

	BduDetail *BDUDetail `json:"bduDetail,omitempty"`
}

type BDUDetail struct {
	Identifier    string   `json:"identifier"`
	Name          string   `json:"name,omitempty"`
	Description   string   `json:"description,omitempty"`
	Severity      string   `json:"severity,omitempty"`
	CVSS3Vector   string   `json:"cvss3Vector,omitempty"`
	CVSS3Score    float64  `json:"cvss3Score,omitempty"`
	Solution      string   `json:"solution,omitempty"`
	Sources       []string `json:"sources,omitempty"`
	FixStatus     string   `json:"fixStatus,omitempty"`
	VulStatus     string   `json:"vulStatus,omitempty"`
	ExploitStatus string   `json:"exploitStatus,omitempty"`

	Software     []BDUSoftware    `json:"software,omitempty"`
	Environments []BDUEnvironment `json:"environments,omitempty"`

	CWEs            []BDUCWE     `json:"cwes,omitempty"`
	VulClass        string       `json:"vulClass,omitempty"`
	VulElimination  string       `json:"vulElimination,omitempty"`
	IdentifyDate    string       `json:"identifyDate,omitempty"`
	PublicationDate string       `json:"publicationDate,omitempty"`
	LastUpdDate     string       `json:"lastUpdDate,omitempty"`
	CVSS2Vector     string       `json:"cvss2Vector,omitempty"`
	CVSS2Score      float64      `json:"cvss2Score,omitempty"`
	CVSS4Vector     string       `json:"cvss4Vector,omitempty"`
	CVSS4Score      float64      `json:"cvss4Score,omitempty"`
	SLOperProcs     []string     `json:"slOperProcs,omitempty"`
	OtherIDs        []BDUOtherID `json:"otherIds,omitempty"`
}

type BDUCWE struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

type BDUSoftware struct {
	Vendor   string   `json:"vendor,omitempty"`
	Name     string   `json:"name,omitempty"`
	Version  string   `json:"version,omitempty"`
	Platform string   `json:"platform,omitempty"`
	Types    []string `json:"types,omitempty"`
}

type BDUEnvironment struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

type BDUOtherID struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value"`
}

type PoCEntry struct {
	Name  string `json:"name"`
	URL   string `json:"url"`
	Stars int    `json:"stars"`
}

type ScheduleFrequency string

const (
	FreqDisabled ScheduleFrequency = "disabled"
	FreqDaily    ScheduleFrequency = "daily"
	FreqWeekly   ScheduleFrequency = "weekly"
)

type ScanSchedule struct {
	Enabled   bool              `json:"enabled"`
	Frequency ScheduleFrequency `json:"frequency"`
	TimeOfDay string            `json:"timeOfDay"`
	DayOfWeek int               `json:"dayOfWeek"`
	NextRun   *time.Time        `json:"nextRun,omitempty"`
	LastRun   *time.Time        `json:"lastRun,omitempty"`
}

type ScanEvent struct {
	Type    string      `json:"type"`
	Image   string      `json:"image"`
	Message string      `json:"message,omitempty"`
	Result  *ScanResult `json:"result,omitempty"`
}

type HistoryStatus string

const (
	HistoryPending     HistoryStatus = "pending"
	HistoryFetching    HistoryStatus = "fetching"
	HistoryDone        HistoryStatus = "done"
	HistoryUnavailable HistoryStatus = "unavailable"
)

type HistoryLayer struct {
	CreatedBy  string `json:"created_by"`
	EmptyLayer bool   `json:"empty_layer,omitempty"`
}

type ImageHistory struct {
	Image     string         `json:"image"`
	Status    HistoryStatus  `json:"status"`
	Error     string         `json:"error,omitempty"`
	Stale     bool           `json:"stale,omitempty"`
	FetchedAt time.Time      `json:"fetched_at,omitempty"`
	Layers    []HistoryLayer `json:"layers"`
}

type ImagesResponse struct {
	Images []ClusterImage `json:"images"`
	Total  int            `json:"total"`
}

type HistoriesResponse struct {
	Histories []ImageHistory `json:"histories"`
	Total     int            `json:"total"`
}

type ResultsResponse struct {
	Results []ScanResult `json:"results"`
	Total   int          `json:"total"`
	Summary CVESummary   `json:"summary"`
}
