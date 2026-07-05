package grype

type grypeReport struct {
	Matches    []grypeMatch    `json:"matches"`
	Source     grypeSource     `json:"source"`
	Distro     grypeDistro     `json:"distro"`
	Descriptor grypeDescriptor `json:"descriptor"`
}

type grypeMatch struct {
	Vulnerability          grypeVuln     `json:"vulnerability"`
	RelatedVulnerabilities []grypeVuln   `json:"relatedVulnerabilities"`
	Artifact               grypeArtifact `json:"artifact"`
}

type grypeVuln struct {
	ID            string          `json:"id"`
	DataSource    string          `json:"dataSource"`
	Namespace     string          `json:"namespace"`
	Severity      string          `json:"severity"`
	URLs          []string        `json:"urls"`
	Description   string          `json:"description"`
	CVSS          []grypeCVSS     `json:"cvss"`
	Fix           grypeFix        `json:"fix"`
	Advisories    []grypeAdvisory `json:"advisories"`
	CWEs          []grypeCWE      `json:"cwes"`
	PublishedDate string          `json:"publishedDate,omitempty"`
}

type grypeCVSS struct {
	Source  string           `json:"source"`
	Type    string           `json:"type"`
	Version string           `json:"version"`
	Vector  string           `json:"vector"`
	Metrics grypeCVSSMetrics `json:"metrics"`
}

type grypeCVSSMetrics struct {
	BaseScore           float64 `json:"baseScore"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
	ImpactScore         float64 `json:"impactScore"`
}

type grypeFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type grypeAdvisory struct {
	ID   string `json:"id"`
	Link string `json:"link"`
}

type grypeCWE struct {
	CweID       string `json:"cweId"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type grypeArtifact struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Type     string   `json:"type"`
	Language string   `json:"language"`
	Licenses []string `json:"licenses"`
	PURL     string   `json:"purl"`
}

type grypeSource struct {
	Type   string      `json:"type"`
	Target grypeTarget `json:"target"`
}

type grypeTarget struct {
	UserInput        string       `json:"userInput"`
	ImageID          string       `json:"imageID"`
	ManifestDigest   string       `json:"manifestDigest"`
	Tags             []string     `json:"tags"`
	RepoDigests      []string     `json:"repoDigests"`
	ArtifactMetadata grypeArtMeta `json:"artifactMetadata"`
}

type grypeArtMeta struct {
	OS grypeOS `json:"os"`
}

type grypeOS struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type grypeDistro struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	IDLike  []string `json:"idLike"`
}

type grypeDescriptor struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
