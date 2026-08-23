package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = safeDialContext
	return &Inspector{
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
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
	if err := validateRegistry(reg); err != nil {
		return "", fmt.Errorf("registry %q: %w", reg, err)
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
	if err := validateRegistry(reg); err != nil {
		return nil, fmt.Errorf("registry %q: %w", reg, err)
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

var errPrivateRegistryAddress = errors.New("registry resolves to a private or otherwise unsafe address")

func validateRegistry(reg string) error {
	host := reg
	if h, _, err := net.SplitHostPort(reg); err == nil {
		host = h
	} else if strings.Contains(reg, ":") {
		return fmt.Errorf("invalid registry host: %w", err)
	}
	if host == "" || strings.ContainsAny(host, "/\\@") {
		return errors.New("invalid registry host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if blockedIP(ip) {
			return errPrivateRegistryAddress
		}
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("resolve registry: %w", err)
	}
	if len(ips) == 0 {
		return errors.New("registry has no addresses")
	}
	for _, ip := range ips {
		if blockedIP(ip) {
			return errPrivateRegistryAddress
		}
	}
	return nil
}

func blockedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip4InRange(ip, net.IPv4(100, 64, 0, 0), 10)
}

func ip4InRange(ip, base net.IP, prefixLen int) bool {
	ip = ip.To4()
	base = base.To4()
	if ip == nil || base == nil {
		return false
	}
	mask := net.CIDRMask(prefixLen, 32)
	return ip.Mask(mask).Equal(base.Mask(mask))
}

func safeDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		if blockedIP(ip) {
			return nil, errPrivateRegistryAddress
		}
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if blockedIP(ip) {
			return nil, errPrivateRegistryAddress
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("host has no addresses")
	}
	var lastErr error
	for _, ip := range ips {
		conn, dialErr := (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	return nil, lastErr
}

func validateTokenRealm(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, errors.New("token realm must be an absolute HTTPS URL")
	}
	if err := validateRegistry(u.Host); err != nil {
		return nil, err
	}
	return u, nil
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
