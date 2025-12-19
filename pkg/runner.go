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
	respCh   chan map[string]json.RawMessage
	errch    chan error
	wg       sync.WaitGroup
	mu       sync.Mutex
}

type CommandRequest struct {
	Type              string `json:"type"`
	ReqPath           string `json:"reqPath"`
	Body              string `json:"body"`
	AccessToken       string `json:"accessToken,omitempty"`
	ServerPublicKey   string `json:"serverPublicKey,omitempty"`
	EncryptedKeyChain string `json:"encryptedKeyChain,omitempty"`
}

type CommandResponse struct {
	Signature    string `json:"signature,omitempty"`
	Secret       string `json:"secret,omitempty"`
	Pin          string `json:"pin,omitempty"`
	PublicKeyHex string `json:"publicKeyHex,omitempty"`
	Hash         string `json:"hash,omitempty"`
	Error        string `json:"error,omitempty"`
}

type SecretResult struct {
	Secret       string `json:"secret"`
	Pin          string `json:"pin"`
	PublicKeyHex string `json:"publicKeyHex"`
	Hash         string `json:"hash"`
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
		respCh:   make(chan map[string]json.RawMessage),
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
			var raw map[string]json.RawMessage
			if err := json.Unmarshal([]byte(line), &raw); err != nil {
				continue
			}

			if errVal, ok := raw["error"]; ok {
				r.errch <- fmt.Errorf("runner error: %s", string(errVal))
				continue
			}

			if sigVal, ok := raw["signature"]; ok {
				var sig string
				_ = json.Unmarshal(sigVal, &sig)
				r.sigCh <- sig
				continue
			}

			if raw["secret"] != nil || raw["pin"] != nil || raw["publicKeyHex"] != nil || raw["hash"] != nil {
				var res CommandResponse
				_ = json.Unmarshal([]byte(line), &res)
				r.secCh <- &SecretResult{
					Secret:       res.Secret,
					Pin:          res.Pin,
					PublicKeyHex: res.PublicKeyHex,
					Hash:         res.Hash,
				}
				continue
			}

			r.respCh <- raw
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

func (r *Runner) call(rawReq any) (map[string]json.RawMessage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	reqBytes, err := json.Marshal(rawReq)
	if err != nil {
		return nil, err
	}

	if _, err = r.stdin.Write(append(reqBytes, '\n')); err != nil {
		return nil, err
	}

	select {
	case resp := <-r.respCh:
		return resp, nil
	case err := <-r.errch:
		return nil, err
	}
}

/*
The following methods are related to the storage and key management functionalities
provided by the runner for E2EE operations
*/

// initializes the storage key using getEncryptedIdentityV3 response fields
func (r *Runner) StorageInit(wrappedNonce, kdf1, kdf2 string) error {
	_, err := r.call(map[string]any{
		"type":          "storage_init",
		"wrappedNonce":  wrappedNonce,
		"kdfParameter1": kdf1,
		"kdfParameter2": kdf2,
	})
	return err
}

// decrypts lcs_secure blobs with the initialized storage key
func (r *Runner) StorageDecrypt(ciphertext string) (string, error) {
	resp, err := r.call(map[string]any{
		"type":       "storage_decrypt",
		"ciphertext": ciphertext,
	})
	if err != nil {
		return "", err
	}
	var plaintext string
	if v, ok := resp["plaintext"]; ok {
		_ = json.Unmarshal(v, &plaintext)
	}
	return plaintext, nil
}

// encrypts plaintext with the initialized storage key
func (r *Runner) StorageEncrypt(plaintext string) (string, error) {
	resp, err := r.call(map[string]any{
		"type":      "storage_encrypt",
		"plaintext": plaintext,
	})
	if err != nil {
		return "", err
	}
	var ct string
	if v, ok := resp["ciphertext"]; ok {
		_ = json.Unmarshal(v, &ct)
	}
	return ct, nil
}

// unwraps the encrypted key chain from LF1 using the login curve key
func (r *Runner) LoginUnwrapKeyChain(serverPubB64, encryptedKeyChainB64 string) ([]UnwrappedKey, error) {
	resp, err := r.call(map[string]any{
		"type":              "login_unwrap_keychain",
		"serverPublicKey":   serverPubB64,
		"encryptedKeyChain": encryptedKeyChainB64,
	})
	if err != nil {
		return nil, err
	}
	var keys []UnwrappedKey
	if v, ok := resp["keys"]; ok {
		_ = json.Unmarshal(v, &keys)
	}
	return keys, nil
}

// loads a base64 E2EE key and returns an internal key id
func (r *Runner) KeyLoad(b64Key string) (int, error) {
	resp, err := r.call(map[string]any{
		"type": "key_load",
		"key":  b64Key,
	})
	if err != nil {
		return 0, err
	}
	var keyID int
	if v, ok := resp["keyId"]; ok {
		_ = json.Unmarshal(v, &keyID)
	}
	return keyID, nil
}

// get the raw key id for a loaded key
func (r *Runner) KeyGetID(keyID int) (int, error) {
	resp, err := r.call(map[string]any{
		"type":  "key_get_id",
		"keyId": keyID,
	})
	if err != nil {
		return 0, err
	}
	var rawID int
	if v, ok := resp["key"]; ok {
		_ = json.Unmarshal(v, &rawID)
	}
	return rawID, nil
}

// get the base64 public key for a loaded key
func (r *Runner) KeyGetPublic(keyID int) (string, error) {
	resp, err := r.call(map[string]any{
		"type":  "key_get_public",
		"keyId": keyID,
	})
	if err != nil {
		return "", err
	}
	var pub string
	if v, ok := resp["publicKey"]; ok {
		_ = json.Unmarshal(v, &pub)
	}
	return pub, nil
}

// creates a channel with our key and peer public key
func (r *Runner) ChannelCreate(keyID int, peerPublicB64 string) (int, error) {
	resp, err := r.call(map[string]any{
		"type":          "channel_create",
		"keyId":         keyID,
		"peerPublicKey": peerPublicB64,
	})
	if err != nil {
		return 0, err
	}
	var chanID int
	if v, ok := resp["channelId"]; ok {
		_ = json.Unmarshal(v, &chanID)
	}
	return chanID, nil
}

type UnwrappedKey struct {
	KeyID    int    `json:"keyId"`
	Exported string `json:"exported"`
	Version  int    `json:"version"`
	RawKeyID int    `json:"rawKeyId"`
}

// ChannelEncryptV2 encrypts plaintext with channel v2.
func (r *Runner) ChannelEncryptV2(channelID int, to, from string, senderKeyID, receiverKeyID, contentType, seq int, plaintext string) (string, error) {
	resp, err := r.call(map[string]any{
		"type":           "channel_encrypt_v2",
		"channelId":      channelID,
		"to":             to,
		"from":           from,
		"senderKeyId":    senderKeyID,
		"receiverKeyId":  receiverKeyID,
		"contentType":    contentType,
		"sequenceNumber": seq,
		"plaintext":      plaintext,
	})
	if err != nil {
		return "", err
	}
	var ct string
	if v, ok := resp["ciphertext"]; ok {
		_ = json.Unmarshal(v, &ct)
	}
	return ct, nil
}

// decrypts ciphertext with channel v2
func (r *Runner) ChannelDecryptV2(channelID int, to, from string, senderKeyID, receiverKeyID, contentType int, ciphertext string) (string, string, error) {
	resp, err := r.call(map[string]any{
		"type":          "channel_decrypt_v2",
		"channelId":     channelID,
		"to":            to,
		"from":          from,
		"senderKeyId":   senderKeyID,
		"receiverKeyId": receiverKeyID,
		"contentType":   contentType,
		"ciphertext":    ciphertext,
	})
	if err != nil {
		return "", "", err
	}
	var plaintext, base64 string
	if v, ok := resp["plaintext"]; ok {
		_ = json.Unmarshal(v, &plaintext)
	}
	if v, ok := resp["base64"]; ok {
		_ = json.Unmarshal(v, &base64)
	}
	return plaintext, base64, nil
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

// GenerateConfirmHash derives the hash key chain for confirmE2EELogin using the
// previously generated login key pair (must be generated via GenerateE2EESecret first).
func (r *Runner) GenerateConfirmHash(serverPublicKeyB64, encryptedKeyChainB64 string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	req := CommandRequest{
		Type:              "confirm_hash",
		ServerPublicKey:   serverPublicKeyB64,
		EncryptedKeyChain: encryptedKeyChainB64,
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
	case res := <-r.secCh:
		if res.Hash != "" {
			return res.Hash, nil
		}
		if res.Secret != "" {
			return res.Secret, nil
		}
		if res.Pin != "" {
			return res.Pin, nil
		}
		return res.PublicKeyHex, nil
	case err := <-r.errch:
		return "", err
	case sig := <-r.sigCh:
		return sig, nil
	}
}
