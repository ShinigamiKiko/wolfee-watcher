package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func (ins *Inspector) getToken(ctx context.Context, base, repo string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v2/", nil)
	if err != nil {
		return "", err
	}
	if cred := ins.credFor(base); cred != "" {
		req.Header.Set("Authorization", "Basic "+cred)
	}

	resp, err := ins.client.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return "", nil
	}

	www := resp.Header.Get("WWW-Authenticate")

	if resp.StatusCode == http.StatusUnauthorized && !strings.HasPrefix(www, "Bearer ") {
		return "", nil
	}

	if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(www, "Bearer ") {
		return "", fmt.Errorf("probe returned %d (WWW-Authenticate: %s)", resp.StatusCode, www)
	}

	return ins.exchangeBearerToken(ctx, www[len("Bearer "):], repo)
}

func (ins *Inspector) exchangeBearerToken(ctx context.Context, challenge, repo string) (string, error) {
	params := parseBearerChallenge(challenge)
	realm := params["realm"]
	if realm == "" {
		return "", fmt.Errorf("no realm in WWW-Authenticate")
	}

	tokenURL, err := url.Parse(realm)
	if err != nil {
		return "", err
	}
	q := tokenURL.Query()
	if svc := params["service"]; svc != "" {
		q.Set("service", svc)
	}
	scope := params["scope"]
	if scope == "" {
		scope = fmt.Sprintf("repository:%s:pull", repo)
	}
	q.Set("scope", scope)
	tokenURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL.String(), nil)
	if err != nil {
		return "", err
	}
	if cred := ins.credFor("https://" + tokenURL.Host); cred != "" {
		req.Header.Set("Authorization", "Basic "+cred)
	}

	resp, err := ins.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("token endpoint 403 — image may be private or credentials missing")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint %d", resp.StatusCode)
	}

	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", err
	}
	if tok.Token != "" {
		return tok.Token, nil
	}
	return tok.AccessToken, nil
}

type dockerConfig struct {
	Auths map[string]struct {
		Auth string `json:"auth"`
	} `json:"auths"`
}

func loadDockerConfig() dockerConfig {
	var cfg dockerConfig
	paths := []string{
		os.Getenv("DOCKER_CONFIG") + "/config.json",
		os.Getenv("HOME") + "/.docker/config.json",
		"/root/.docker/config.json",
		"/kaniko/.docker/config.json",
	}
	for _, p := range paths {
		if p == "/config.json" || p == "/.docker/config.json" {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if err := json.Unmarshal(b, &cfg); err == nil && len(cfg.Auths) > 0 {
			return cfg
		}
	}
	return cfg
}

func (d dockerConfig) credFor(registryBase string) string {
	host := strings.TrimPrefix(strings.TrimPrefix(registryBase, "https://"), "http://")
	for key, v := range d.Auths {
		k := strings.TrimPrefix(strings.TrimPrefix(key, "https://"), "http://")
		if k == host || k == host+"/v1/" {
			return v.Auth
		}
	}

	if host == "registry-1.docker.io" || host == "index.docker.io" || host == "docker.io" {
		for _, alias := range []string{"https://index.docker.io/v1/", "index.docker.io/v1/", "docker.io"} {
			if v, ok := d.Auths[alias]; ok {
				return v.Auth
			}
		}
	}
	return ""
}

func parseImageRef(ref string) (registry, repo, tag string, err error) {

	if idx := strings.Index(ref, "@"); idx >= 0 {
		ref = ref[:idx]
	}

	tag = "latest"
	if idx := strings.LastIndex(ref, ":"); idx >= 0 {

		if !strings.Contains(ref[idx:], "/") {
			tag = ref[idx+1:]
			ref = ref[:idx]
		}
	}

	parts := strings.SplitN(ref, "/", 2)
	if len(parts) == 1 {

		return "registry-1.docker.io", "library/" + ref, tag, nil
	}

	first := parts[0]
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		if first == "docker.io" {
			registry = "registry-1.docker.io"
		} else {
			registry = first
		}
		repo = parts[1]

		if registry == "registry-1.docker.io" && !strings.Contains(repo, "/") {
			repo = "library/" + repo
		}
	} else {

		registry = "registry-1.docker.io"
		repo = ref
	}
	return
}

func isInsecureRegistry(reg string) bool {
	insecure := os.Getenv("INSECURE_REGISTRIES")
	if insecure == "" {
		return false
	}
	for _, r := range strings.Split(insecure, ",") {
		if strings.TrimSpace(r) == reg {
			return true
		}
	}
	return false
}

func parseBearerChallenge(s string) map[string]string {
	params := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.Trim(strings.TrimSpace(kv[1]), `"`)
		params[key] = val
	}
	return params
}

func BasicAuth(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}
