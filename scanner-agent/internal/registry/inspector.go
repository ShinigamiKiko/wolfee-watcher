package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type HistoryEntry struct {
	CreatedBy  string `json:"created_by"`
	Comment    string `json:"comment,omitempty"`
	EmptyLayer bool   `json:"empty_layer,omitempty"`
}

type Inspector struct {
	client    *http.Client
	mu        sync.RWMutex
	dockerCfg dockerConfig
}

func (ins *Inspector) credFor(base string) string {
	ins.mu.RLock()
	defer ins.mu.RUnlock()
	return ins.dockerCfg.credFor(base)
}

func New() *Inspector {
	return &Inspector{
		client:    &http.Client{Timeout: 30 * time.Second},
		dockerCfg: loadDockerConfig(),
	}
}

func (ins *Inspector) InjectCreds(registryURL, username, token string) {
	host := strings.TrimPrefix(strings.TrimPrefix(registryURL, "https://"), "http://")

	if idx := strings.Index(host, "/"); idx >= 0 {
		host = host[:idx]
	}
	cred := BasicAuth(username, token)
	ins.mu.Lock()
	defer ins.mu.Unlock()
	if ins.dockerCfg.Auths == nil {
		ins.dockerCfg = loadDockerConfig()
	}
	type authEntry = struct {
		Auth string `json:"auth"`
	}
	if ins.dockerCfg.Auths == nil {
		ins.dockerCfg.Auths = map[string]authEntry{}
	}
	ins.dockerCfg.Auths["https://"+host] = authEntry{Auth: cred}
}

func (ins *Inspector) FetchDigest(ctx context.Context, imageRef string) (string, error) {
	reg, repo, tag, err := parseImageRef(imageRef)
	if err != nil {
		return "", fmt.Errorf("parse ref %q: %w", imageRef, err)
	}
	scheme := "https"
	if isInsecureRegistry(reg) {
		scheme = "http"
	}
	base := fmt.Sprintf("%s://%s", scheme, reg)

	token, err := ins.getToken(ctx, base, repo)
	if err != nil {
		return "", fmt.Errorf("auth %s: %w", reg, err)
	}

	u := fmt.Sprintf("%s/v2/%s/manifests/%s", base, repo, tag)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
	}, ", "))
	ins.setAuth(req, base, token)

	resp, err := ins.client.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	d := resp.Header.Get("Docker-Content-Digest")
	if d == "" {
		return "", fmt.Errorf("registry did not return Docker-Content-Digest header")
	}
	return d, nil
}

func (ins *Inspector) FetchHistory(ctx context.Context, imageRef string) ([]HistoryEntry, error) {
	reg, repo, tag, err := parseImageRef(imageRef)
	if err != nil {
		return nil, fmt.Errorf("parse ref %q: %w", imageRef, err)
	}

	scheme := "https"
	if isInsecureRegistry(reg) {
		scheme = "http"
	}
	base := fmt.Sprintf("%s://%s", scheme, reg)

	token, err := ins.getToken(ctx, base, repo)
	if err != nil {
		return nil, fmt.Errorf("auth %s: %w", reg, err)
	}

	configDigest, err := ins.fetchManifest(ctx, base, repo, tag, token)
	if err != nil {
		return nil, fmt.Errorf("manifest %s/%s:%s: %w", reg, repo, tag, err)
	}

	history, err := ins.fetchConfig(ctx, base, repo, configDigest, token)
	if err != nil {
		return nil, fmt.Errorf("config blob %s: %w", configDigest, err)
	}
	return history, nil
}

func (ins *Inspector) fetchManifest(ctx context.Context, base, repo, tag, token string) (string, error) {
	u := fmt.Sprintf("%s/v2/%s/manifests/%s", base, repo, tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.index.v1+json",
	}, ", "))
	ins.setAuth(req, base, token)

	resp, err := ins.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}

	var probe struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				OS   string `json:"os"`
				Arch string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return "", err
	}

	if len(probe.Manifests) > 0 {
		pick := probe.Manifests[0].Digest
		for _, m := range probe.Manifests {
			if m.Platform.OS == "linux" && m.Platform.Arch == "amd64" {
				pick = m.Digest
				break
			}
		}
		return ins.fetchManifest(ctx, base, repo, pick, token)
	}

	if probe.Config.Digest == "" {
		return "", fmt.Errorf("no config digest in manifest")
	}
	return probe.Config.Digest, nil
}

func (ins *Inspector) fetchConfig(ctx context.Context, base, repo, digest, token string) ([]HistoryEntry, error) {
	u := fmt.Sprintf("%s/v2/%s/blobs/%s", base, repo, digest)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	ins.setAuth(req, base, token)

	resp, err := ins.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}

	var cfg struct {
		History []HistoryEntry `json:"history"`
	}
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, err
	}
	return cfg.History, nil
}

func (ins *Inspector) setAuth(req *http.Request, base, token string) {
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	} else if cred := ins.credFor(base); cred != "" {
		req.Header.Set("Authorization", "Basic "+cred)
	}
}
