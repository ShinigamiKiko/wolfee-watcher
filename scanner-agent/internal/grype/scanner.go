package grype

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
	grypePath    string
	dbCacheDir   string
	workspaceDir string

	dbMu    sync.Mutex
	dbReady bool

	harborMu        sync.Mutex
	harborAuthority string
	harborUsername  string
	harborPassword  string
}

func New(grypePath, dbCacheDir, workspaceDir string) *Scanner {
	if grypePath == "" {
		grypePath = "grype"
	}
	if workspaceDir != "" {
		if err := os.MkdirAll(workspaceDir, 0o755); err != nil {
			log.Printf("[grype] cannot create workspace %s: %v (will fall back to system tmp)", workspaceDir, err)
			workspaceDir = ""
		}
	}
	return &Scanner{grypePath: grypePath, dbCacheDir: dbCacheDir, workspaceDir: workspaceDir}
}

func (s *Scanner) Scan(ctx context.Context, imageRef string) (*internal.ScanResult, error) {
	start := time.Now()

	if strings.HasPrefix(imageRef, "localhost/") ||
		strings.HasPrefix(imageRef, "127.0.0.1") {
		return nil, fmt.Errorf("skipping local-only image (not in registry): %s", imageRef)
	}

	scanTarget := imageRef
	if !strings.HasPrefix(imageRef, "registry:") &&
		!strings.HasPrefix(imageRef, "docker:") &&
		!strings.HasPrefix(imageRef, "docker-daemon:") {
		scanTarget = "registry:" + imageRef
	}

	if err := s.EnsureDB(ctx); err != nil {
		return nil, fmt.Errorf("prepare vulnerability DB: %w", err)
	}

	cmd := exec.CommandContext(ctx, s.grypePath,
		scanTarget,
		"--output", "json",
		"--add-cpes-if-none",
		"--by-cve",
	)
	cmd.Env = cmd.Environ()
	if s.dbCacheDir != "" {
		cmd.Env = append(cmd.Env, "GRYPE_DB_CACHE_DIR="+s.dbCacheDir)
	}

	s.harborMu.Lock()
	authority, username, password := s.harborAuthority, s.harborUsername, s.harborPassword
	s.harborMu.Unlock()
	if authority != "" && password != "" {
		cmd.Env = append(cmd.Env,
			"GRYPE_REGISTRY_AUTH_AUTHORITY="+authority,
			"GRYPE_REGISTRY_AUTH_USERNAME="+username,
			"GRYPE_REGISTRY_AUTH_PASSWORD="+password,
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
				log.Printf("[grype] cleanup %s: %v", perScanTmp, rmErr)
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

	err := cmd.Run()
	outStr := stdout.String()
	errStr := strings.TrimSpace(stderr.String())

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {

			if exitErr.ExitCode() == 1 && len(outStr) > 0 && strings.HasPrefix(strings.TrimSpace(outStr), "{") {

			} else {
				msg := fmt.Sprintf("grype exited %d", exitErr.ExitCode())
				switch {
				case errStr != "":
					msg += ": " + errStr
				case len(outStr) > 0:
					msg += ": " + lastLine(outStr)
				default:
					msg += " (no output — vulnerability DB likely missing or failed to download; check the earlier [grype] DB log lines)"
				}
				return nil, fmt.Errorf("%s", msg)
			}
		} else if len(outStr) == 0 {
			msg := "grype exec: " + err.Error()
			if errStr != "" {
				msg += " — " + errStr
			}
			return nil, fmt.Errorf("%s", msg)
		}
	}

	if len(outStr) == 0 {
		return nil, fmt.Errorf("grype produced no output (stderr: %s)", errStr)
	}

	var report grypeReport
	if err := json.Unmarshal([]byte(outStr), &report); err != nil {
		return nil, fmt.Errorf("parse grype output: %w (stderr: %s)", err, errStr)
	}

	return buildResult(imageRef, report, time.Since(start)), nil
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
		log.Printf("[grype] sweep workspace %s: %v", s.workspaceDir, err)
		return
	}
	swept := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "scan-") && !strings.HasPrefix(name, "stereoscope-") {
			continue
		}
		full := filepath.Join(s.workspaceDir, name)
		if err := os.RemoveAll(full); err != nil {
			log.Printf("[grype] sweep %s: %v", full, err)
			continue
		}
		swept++
	}
	if swept > 0 {
		log.Printf("[grype] swept %d orphan scan tmpdirs from %s", swept, s.workspaceDir)
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
	log.Printf("[grype] no vulnerability DB yet — downloading once into %s …", s.dbCacheDir)
	start := time.Now()
	if err := s.UpdateDB(ctx); err != nil {
		return err
	}
	s.dbReady = true
	log.Printf("[grype] vulnerability DB ready (%s)", time.Since(start).Round(time.Second))
	return nil
}

func (s *Scanner) UpdateDB(ctx context.Context) error {
	if s.dbCacheDir != "" {
		if err := os.MkdirAll(s.dbCacheDir, 0o777); err != nil {
			return fmt.Errorf("create grype db cache dir %s: %w", s.dbCacheDir, err)
		}
	}
	cmd := exec.CommandContext(ctx, s.grypePath, "db", "update")
	if s.dbCacheDir != "" {
		cmd.Env = append(cmd.Environ(), "GRYPE_DB_CACHE_DIR="+s.dbCacheDir)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("grype db update: %w\n%s", err, string(out))
	}
	return nil
}
