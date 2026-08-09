package trivy

type trivyReport struct {
	SchemaVersion int           `json:"SchemaVersion"`
	ArtifactName  string        `json:"ArtifactName"`
	ArtifactType  string        `json:"ArtifactType"`
	Metadata      trivyMetadata `json:"Metadata"`
	Results       []trivyResult `json:"Results"`
}

type trivyMetadata struct {
	OS          trivyOS  `json:"OS"`
	ImageID     string   `json:"ImageID"`
	RepoTags    []string `json:"RepoTags"`
	RepoDigests []string `json:"RepoDigests"`
}

type trivyOS struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
	EOSL   bool   `json:"EOSL"`
}

type trivyResult struct {
	Target          string         `json:"Target"`
	Class           string         `json:"Class"`
	Type            string         `json:"Type"`
	Vulnerabilities []trivyVuln    `json:"Vulnerabilities"`
	Licenses        []trivyLicense `json:"Licenses"`
}

type trivyLicense struct {
	PkgName  string `json:"PkgName"`
	Name     string `json:"Name"`
	Category string `json:"Category"`
	FilePath string `json:"FilePath"`
}

type trivyVuln struct {
	VulnerabilityID  string               `json:"VulnerabilityID"`
	PkgID            string               `json:"PkgID"`
	PkgName          string               `json:"PkgName"`
	PkgIdentifier    trivyPkgIdentifier   `json:"PkgIdentifier"`
	InstalledVersion string               `json:"InstalledVersion"`
	FixedVersion     string               `json:"FixedVersion"`
	Status           string               `json:"Status"`
	SeveritySource   string               `json:"SeveritySource"`
	PrimaryURL       string               `json:"PrimaryURL"`
	Title            string               `json:"Title"`
	Description      string               `json:"Description"`
	Severity         string               `json:"Severity"`
	CweIDs           []string             `json:"CweIDs"`
	CVSS             map[string]trivyCVSS `json:"CVSS"`
	References       []string             `json:"References"`
	PublishedDate    string               `json:"PublishedDate"`
	LastModifiedDate string               `json:"LastModifiedDate"`
}

type trivyPkgIdentifier struct {
	PURL string `json:"PURL"`
	UID  string `json:"UID"`
}

type trivyCVSS struct {
	V2Vector  string  `json:"V2Vector"`
	V3Vector  string  `json:"V3Vector"`
	V40Vector string  `json:"V40Vector"`
	V2Score   float64 `json:"V2Score"`
	V3Score   float64 `json:"V3Score"`
	V40Score  float64 `json:"V40Score"`
}
