package line

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

//go:embed internal/*
var internalAssets embed.FS

type Generator struct {
	tempDir string
}

var (
	setupOnce sync.Once
	setupDir  string
	setupErr  error
)

func setupTempDir() {
	setupDir = filepath.Join(os.TempDir(), "hmac_runner")
	if err := os.MkdirAll(setupDir, 0755); err != nil {
		setupErr = fmt.Errorf("failed to create temp dir: %w", err)
		return
	}

	files := []string{"internal/runner.js", "internal/ltsm.wasm"}
	for _, file := range files {
		target := filepath.Join(setupDir, filepath.Base(file))
		if _, err := os.Stat(target); err == nil {
			continue
		}
		data, err := internalAssets.ReadFile(file)
		if err != nil {
			setupErr = fmt.Errorf("failed to read embedded file %s: %w", file, err)
			return
		}
		err = os.WriteFile(target, data, 0644)
		if err != nil {
			setupErr = fmt.Errorf("failed to write temp file %s: %w", target, err)
			return
		}
	}
}

func NewGenerator() (*Generator, error) {
	setupOnce.Do(setupTempDir)
	if setupErr != nil {
		return nil, setupErr
	}
	return &Generator{tempDir: setupDir}, nil
}

func (g *Generator) Close() {
}

func (g *Generator) GenerateSignature(reqPath, body, accessToken string) (string, error) {
	runnerPath := filepath.Join(g.tempDir, "runner.js")
	wasmPath := filepath.Join(g.tempDir, "ltsm.wasm")

	cmd := exec.Command("node", runnerPath, wasmPath, reqPath, body, accessToken)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("runner failed: %s (stderr: %s)", err, stderr.String())
	}

	return strings.TrimSpace(stdout.String()), nil
}
