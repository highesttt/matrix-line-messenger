package line

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

//go:embed internal/*
var internalAssets embed.FS

type Runner struct {
	ctx      context.Context
	jsPath   string
	wasmPath string
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	stdout   io.ReadCloser
	sigCh    chan string
	secCh    chan *SecretResult
	errch    chan error
	wg       sync.WaitGroup
	mu       sync.Mutex
}

type CommandRequest struct {
	Type        string `json:"type"`
	ReqPath     string `json:"reqPath"`
	Body        string `json:"body"`
	AccessToken string `json:"accessToken,omitempty"`
}

type CommandResponse struct {
	Signature    string `json:"signature,omitempty"`
	Secret       string `json:"secret,omitempty"`
	Pin          string `json:"pin,omitempty"`
	PublicKeyHex string `json:"publicKeyHex,omitempty"`
	Error        string `json:"error,omitempty"`
}

type SecretResult struct {
	Secret       string `json:"secret"`
	Pin          string `json:"pin"`
	PublicKeyHex string `json:"publicKeyHex"`
}

var (
	globalRunner *Runner
	runnerOnce   sync.Once
	runnerErr    error
)

func GetRunner() (*Runner, error) {
	runnerOnce.Do(func() {
		dir, err := setupTempDir()
		if err != nil {
			runnerErr = err
			return
		}
		globalRunner = NewRunner(context.Background(), filepath.Join(dir, "runner.js"), filepath.Join(dir, "ltsm.wasm"))
		if err := globalRunner.start(); err != nil {
			runnerErr = err
			return
		}
		go globalRunner.run()
	})
	return globalRunner, runnerErr
}

func setupTempDir() (string, error) {
	setupDir := filepath.Join(os.TempDir(), "hmac_runner")
	if err := os.MkdirAll(setupDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	pkgJson := filepath.Join(setupDir, "package.json")
	if err := os.WriteFile(pkgJson, []byte(`{"type": "module"}`), 0644); err != nil {
		return "", fmt.Errorf("failed to write package.json: %w", err)
	}

	files := []string{"internal/runner.js", "internal/ltsm.wasm", "internal/wasm-wrapper.js"}
	for _, file := range files {
		target := filepath.Join(setupDir, filepath.Base(file))
		data, err := internalAssets.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("failed to read embedded file %s: %w", file, err)
		}
		err = os.WriteFile(target, data, 0644)
		if err != nil {
			return "", fmt.Errorf("failed to write temp file %s: %w", target, err)
		}
	}
	return setupDir, nil
}

func NewRunner(ctx context.Context, jsPath, wasmPath string) *Runner {
	return &Runner{
		ctx:      ctx,
		jsPath:   jsPath,
		wasmPath: wasmPath,
		sigCh:    make(chan string),
		secCh:    make(chan *SecretResult),
		errch:    make(chan error),
	}
}

func (r *Runner) run() error {
	scanner := bufio.NewScanner(r.stdout)

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		for scanner.Scan() {
			line := scanner.Text()
			var res CommandResponse
			if err := json.Unmarshal([]byte(line), &res); err != nil {
				continue
			}

			if res.Error != "" {
				r.errch <- fmt.Errorf("runner error: %s", res.Error)
				continue
			}

			if res.Signature != "" {
				r.sigCh <- res.Signature
			} else if res.Secret != "" || res.Pin != "" || res.PublicKeyHex != "" {
				r.secCh <- &SecretResult{
					Secret:       res.Secret,
					Pin:          res.Pin,
					PublicKeyHex: res.PublicKeyHex,
				}
			}
		}
	}()

	return nil
}

func (r *Runner) start() error {
	var err error
	r.cmd = exec.CommandContext(r.ctx, "node", r.jsPath, r.wasmPath)
	r.stdin, err = r.cmd.StdinPipe()
	if err != nil {
		return err
	}
	r.stdout, err = r.cmd.StdoutPipe()
	if err != nil {
		return err
	}
	// Capture stderr for debugging
	r.cmd.Stderr = os.Stderr

	return r.cmd.Start()
}

func (r *Runner) stop() error {
	if r.cmd != nil && r.cmd.Process != nil {
		return r.cmd.Process.Kill()
	}
	_, err := r.cmd.Process.Wait()
	if err != nil {
		return err
	}
	r.wg.Wait()
	return nil
}

func (r *Runner) GetSignature(reqPath, body, accessToken string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	req := CommandRequest{
		Type:        "sign",
		ReqPath:     reqPath,
		Body:        body,
		AccessToken: accessToken,
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	_, err = r.stdin.Write(append(reqBytes, '\n'))
	if err != nil {
		return "", err
	}

	select {
	case sig := <-r.sigCh:
		return sig, nil
	case err := <-r.errch:
		return "", err
	}
}

func (r *Runner) GenerateE2EESecret() (*SecretResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	req := CommandRequest{Type: "e2ee"}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	_, err = r.stdin.Write(append(reqBytes, '\n'))
	if err != nil {
		return nil, err
	}

	select {
	case res := <-r.secCh:
		return res, nil
	case err := <-r.errch:
		return nil, err
	}
}
