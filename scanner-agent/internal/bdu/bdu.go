package bdu

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	defaultArchiveURL = "https://bdu.fstec.ru/files/documents/vulxml.zip"
	defaultTimeout    = 60 * time.Second
	defaultInterval   = 24 * time.Hour
)

type Enricher struct {
	client     *http.Client
	archiveURL string
	localPath  string
	interval   time.Duration
	noDetail   bool

	mu         sync.RWMutex
	cveToBdu   map[string]bduEntry
	bduDetails map[string]*Detail
	lastFetch  time.Time
	lastErr    error
}

type bduEntry struct {
	BduID    string
	Severity string
}

type CWE struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

type Software struct {
	Vendor   string   `json:"vendor,omitempty"`
	Name     string   `json:"name,omitempty"`
	Version  string   `json:"version,omitempty"`
	Platform string   `json:"platform,omitempty"`
	Types    []string `json:"types,omitempty"`
}

type EnvPlatform struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

type OtherID struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value"`
}

type Detail struct {
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

	Software     []Software    `json:"software,omitempty"`
	Environments []EnvPlatform `json:"environments,omitempty"`

	CWEs            []CWE     `json:"cwes,omitempty"`
	VulClass        string    `json:"vulClass,omitempty"`
	VulElimination  string    `json:"vulElimination,omitempty"`
	IdentifyDate    string    `json:"identifyDate,omitempty"`
	PublicationDate string    `json:"publicationDate,omitempty"`
	LastUpdDate     string    `json:"lastUpdDate,omitempty"`
	CVSS2Vector     string    `json:"cvss2Vector,omitempty"`
	CVSS2Score      float64   `json:"cvss2Score,omitempty"`
	CVSS4Vector     string    `json:"cvss4Vector,omitempty"`
	CVSS4Score      float64   `json:"cvss4Score,omitempty"`
	SLOperProcs     []string  `json:"slOperProcs,omitempty"`
	OtherIDs        []OtherID `json:"otherIds,omitempty"`
}

type Options struct {
	LocalPath string

	ArchiveURL      string
	HTTPClient      *http.Client
	RefreshInterval time.Duration
	NoDetail        bool
}

func New(opts Options) *Enricher {
	url := opts.ArchiveURL
	if url == "" && opts.LocalPath == "" {
		url = defaultArchiveURL
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}
	interval := opts.RefreshInterval
	if interval <= 0 {
		interval = defaultInterval
	}
	return &Enricher{
		client:     client,
		archiveURL: url,
		localPath:  opts.LocalPath,
		interval:   interval,
		noDetail:   opts.NoDetail,
		cveToBdu:   make(map[string]bduEntry),
		bduDetails: make(map[string]*Detail),
	}
}

func (e *Enricher) Start(ctx context.Context) {
	if err := e.refresh(ctx); err != nil {
		logRefreshFailure("initial refresh failed", err)
	}
	go func() {
		t := time.NewTicker(e.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := e.refresh(ctx); err != nil {
					logRefreshFailure("refresh failed", err)
				}
			}
		}
	}()
}

func (e *Enricher) Lookup(cve string) (bduID, severity string, ok bool) {
	if cve == "" {
		return "", "", false
	}
	key := strings.ToUpper(strings.TrimSpace(cve))
	e.mu.RLock()
	defer e.mu.RUnlock()
	entry, found := e.cveToBdu[key]
	if !found {
		return "", "", false
	}
	return entry.BduID, entry.Severity, true
}

func (e *Enricher) LookupDetail(cve string) (*Detail, bool) {
	if cve == "" {
		return nil, false
	}
	key := strings.ToUpper(strings.TrimSpace(cve))
	e.mu.RLock()
	defer e.mu.RUnlock()
	entry, found := e.cveToBdu[key]
	if !found {
		return nil, false
	}
	d, ok := e.bduDetails[entry.BduID]
	if !ok || d == nil {
		return nil, false
	}
	return d, true
}

func (e *Enricher) Size() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.cveToBdu)
}

func (e *Enricher) LastFetch() time.Time {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.lastFetch
}

func (e *Enricher) LastError() error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.lastErr
}
