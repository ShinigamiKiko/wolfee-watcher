package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	internal "github.com/wolfee-watcher/scanner-agent/internal"
)

type Scanner struct {
	trivyPath    string
	dbCacheDir   string
	workspaceDir string
	javaDB       bool

	dbMu        sync.Mutex
	dbReady     bool
	dbUpdatedAt time.Time

	scanGate sync.RWMutex

	harborMu        sync.Mutex
	harborAuthority string
	harborUsername  string
	harborPassword  string
}

func New(trivyPath, dbCacheDir, workspaceDir string) *Scanner {
	if trivyPath == "" {
		trivyPath = "trivy"
	}
	if workspaceDir != "" {
		if err := os.MkdirAll(workspaceDir, 0o755); err != nil {
			log.Printf("[trivy] cannot create workspace %s: %v (will fall back to system tmp)", workspaceDir, err)
			workspaceDir = ""
		}
	}
	return &Scanner{
		trivyPath:    trivyPath,
		dbCacheDir:   dbCacheDir,
		workspaceDir: workspaceDir,
		javaDB:       os.Getenv("TRIVY_JAVA_DB") == "true",
	}
}

func (s *Scanner) Scan(ctx context.Context, imageRef string) (*internal.ScanResult, error) {
	start := time.Now()

	if strings.HasPrefix(imageRef, "localhost/") ||
		strings.HasPrefix(imageRef, "127.0.0.1") {
		return nil, fmt.Errorf("skipping local-only image (not in registry): %s", imageRef)
	}

	if err := s.EnsureDB(ctx); err != nil {
		return nil, fmt.Errorf("prepare vulnerability DB: %w", err)
	}

	args := []string{
		"image",
		"--format", "json",
		"--quiet",
		"--scanners", "vuln,license",
		"--image-src", "remote",
		"--skip-db-update",
		"--skip-java-db-update",
		"--detection-priority", "comprehensive",
	}
	if s.dbCacheDir != "" {
		args = append(args, "--cache-dir", s.dbCacheDir)
	}
	args = append(args, imageRef)

	cmd := exec.CommandContext(ctx, s.trivyPath, args...)
	cmd.Env = append(cmd.Environ(), "TRIVY_SKIP_VERSION_CHECK=true")

	s.harborMu.Lock()
	authority, username, password := s.harborAuthority, s.harborUsername, s.harborPassword
	s.harborMu.Unlock()
	if password != "" && registryHost(imageRef) == normalizeAuthority(authority) {
		cmd.Env = append(cmd.Env,
			"TRIVY_USERNAME="+username,
			"TRIVY_PASSWORD="+password,
		)
	}

	var perScanTmp string
	if s.workspaceDir != "" {
		var err error
		perScanTmp, err = os.MkdirTemp(s.workspaceDir, "scan-")
		if err != nil {
			return nil, fmt.Errorf("create per-scan tmpdir under %s: %w", s.workspaceDir, err)
		}
		defer func() {
			if rmErr := os.RemoveAll(perScanTmp); rmErr != nil {
				log.Printf("[trivy] cleanup %s: %v", perScanTmp, rmErr)
			}
		}()
		cmd.Env = append(cmd.Env,
			"TMPDIR="+perScanTmp,
			"TMP="+perScanTmp,
			"TEMP="+perScanTmp,
		)
	}

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	s.scanGate.RLock()
	err := cmd.Run()
	s.scanGate.RUnlock()

	outStr := strings.TrimSpace(stdout.String())
	errStr := strings.TrimSpace(stderr.String())

	if err != nil {
		if !strings.HasPrefix(outStr, "{") {
			log.Printf("[trivy] scan failed for %s: %v\ncommand: %s %s\nstderr:\n%s",
				imageRef, err, s.trivyPath, strings.Join(args, " "), truncate(errStr, 4000))

			msg := "trivy: " + err.Error()
			switch {
			case errStr != "":
				msg += " — " + lastLine(errStr)
			case outStr != "":
				msg += " — " + lastLine(outStr)
			default:
				msg += " (no output — vulnerability DB likely missing or failed to download; check the earlier [trivy] DB log lines)"
			}
			return nil, fmt.Errorf("%s", msg)
		}
	}

	if outStr == "" {
		return nil, fmt.Errorf("trivy produced no output (stderr: %s)", errStr)
	}

	var report trivyReport
	if err := json.Unmarshal([]byte(outStr), &report); err != nil {
		return nil, fmt.Errorf("parse trivy output: %w (stderr: %s)", err, errStr)
	}

	return buildResult(imageRef, report, time.Since(start)), nil
}

func registryHost(ref string) string {
	ref = strings.TrimPrefix(ref, "registry:")
	idx := strings.Index(ref, "/")
	if idx < 0 {
		return "index.docker.io"
	}
	host := ref[:idx]
	if !strings.Contains(host, ".") && !strings.Contains(host, ":") && host != "localhost" {
		return "index.docker.io"
	}
	return host
}

func normalizeAuthority(authority string) string {
	a := strings.TrimSpace(authority)
	if a == "" {
		return ""
	}
	if idx := strings.Index(a, "://"); idx >= 0 {
		a = a[idx+3:]
	}
	if idx := strings.Index(a, "/"); idx >= 0 {
		a = a[:idx]
	}
	return a
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			if len(l) > 300 {
				l = l[:300] + "…"
			}
			return l
		}
	}
	return ""
}

func (s *Scanner) SweepWorkspace() {
	if s.workspaceDir == "" {
		return
	}
	entries, err := os.ReadDir(s.workspaceDir)
	if err != nil {
		log.Printf("[trivy] sweep workspace %s: %v", s.workspaceDir, err)
		return
	}
	swept := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "scan-") && !strings.HasPrefix(name, "fanal-") && !strings.HasPrefix(name, "trivy-") {
			continue
		}
		full := filepath.Join(s.workspaceDir, name)
		if err := os.RemoveAll(full); err != nil {
			log.Printf("[trivy] sweep %s: %v", full, err)
			continue
		}
		swept++
	}
	if swept > 0 {
		log.Printf("[trivy] swept %d orphan scan tmpdirs from %s", swept, s.workspaceDir)
	}
}

func (s *Scanner) SetHarborCreds(authority, username, password string) {
	s.harborMu.Lock()
	s.harborAuthority = authority
	s.harborUsername = username
	s.harborPassword = password
	s.harborMu.Unlock()
}

func (s *Scanner) EnsureDB(ctx context.Context) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	if s.dbReady {
		return nil
	}
	log.Printf("[trivy] no vulnerability DB yet — downloading once into %s …", s.dbCacheDir)
	start := time.Now()
	if err := s.updateLocked(ctx); err != nil {
		return err
	}
	s.dbReady = true
	log.Printf("[trivy] vulnerability DB ready (%s)", time.Since(start).Round(time.Second))
	return nil
}

func (s *Scanner) UpdateDB(ctx context.Context) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	if err := s.updateLocked(ctx); err != nil {
		return err
	}
	s.dbReady = true
	return nil
}

func (s *Scanner) DBUpdatedAt() time.Time {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	return s.dbUpdatedAt
}

func (s *Scanner) StartDBRefresh(ctx context.Context, interval, timeout time.Duration) {
	if interval <= 0 {
		log.Printf("[trivy] scheduled DB refresh disabled")
		return
	}
	log.Printf("[trivy] scheduled DB refresh every %s", interval)
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				start := time.Now()
				c, cancel := context.WithTimeout(ctx, timeout)
				err := s.UpdateDB(c)
				cancel()
				if err != nil {
					log.Printf("[trivy] scheduled DB refresh failed (previous DB kept): %v", err)
					continue
				}
				log.Printf("[trivy] vulnerability DB refreshed (%s)", time.Since(start).Round(time.Second))
			}
		}
	}()
}

func (s *Scanner) updateLocked(ctx context.Context) error {
	if s.dbCacheDir != "" {
		if err := os.MkdirAll(s.dbCacheDir, 0o777); err != nil {
			return fmt.Errorf("create trivy db cache dir %s: %w", s.dbCacheDir, err)
		}
	}

	s.scanGate.Lock()
	defer s.scanGate.Unlock()

	if err := s.downloadDB(ctx, "--download-db-only"); err != nil {
		return err
	}
	if s.javaDB {
		if err := s.downloadDB(ctx, "--download-java-db-only"); err != nil {
			log.Printf("[trivy] java DB download failed (jar findings may be incomplete): %v", err)
		}
	}
	s.dbUpdatedAt = time.Now()
	return nil
}

func (s *Scanner) downloadDB(ctx context.Context, flag string) error {
	args := []string{"image", flag, "--quiet", "--no-progress"}
	if s.dbCacheDir != "" {
		args = append(args, "--cache-dir", s.dbCacheDir)
	}
	cmd := exec.CommandContext(ctx, s.trivyPath, args...)
	cmd.Env = append(cmd.Environ(),
		"TRIVY_SKIP_VERSION_CHECK=true",
		"TRIVY_SKIP_DB_UPDATE=false",
		"TRIVY_SKIP_JAVA_DB_UPDATE=false",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("trivy %s: %w\n%s", flag, err, string(out))
	}
	return nil
}
