package line

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	gen "github.com/highesttt/mautrix-line-messenger/pkg"
	"github.com/highesttt/mautrix-line-messenger/pkg/line/password"
	"github.com/highesttt/mautrix-line-messenger/pkg/line/secret"
)

const (
	BaseURL          = "https://line-chrome-gw.line-apps.com/api/talk/thrift/Talk"
	ExtensionVersion = "3.7.1"
	UserAgent        = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
)

type Client struct {
	HTTPClient  *http.Client
	AccessToken string
}

func NewClient(token string) *Client {
	return &Client{
		HTTPClient:  &http.Client{Timeout: 30 * time.Second},
		AccessToken: token,
	}
}

func (c *Client) Login(email, pass string) (*LoginResult, error) {
	// 1. Get RSA Key Info
	rsaKey, err := c.GetRSAKeyInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get RSA key info: %w", err)
	}

	// 2. Encrypt Password
	encryptedPass, err := password.EncryptPassword(email, pass, rsaKey.SessionKey, rsaKey.NValue, rsaKey.EValue)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt password: %w", err)
	}

	// 3. Generate E2EE Secret
	secretRes, err := secret.GenerateSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate e2ee secret: %w", err)
	}

	// 4. LoginV2
	// Identifier is KeyName when using RSA
	respBytes, err := c.LoginV2(rsaKey.KeyName, encryptedPass, "", secretRes.Secret)
	if err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	var wrapper struct {
		Code    int         `json:"code"`
		Message string      `json:"message"`
		Data    LoginResult `json:"data"`
	}
	if err := json.Unmarshal(respBytes, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to parse login response: %w", err)
	}
	res := wrapper.Data
	if res.PinCode != "" {
		res.Pin = res.PinCode
	} else {
		res.Pin = secretRes.Pin // Store locally for display
	}

	if res.AuthToken != "" {
		c.AccessToken = res.AuthToken
	}
	return &res, nil
}

func (c *Client) WaitForLogin(verifier string) (*LoginResult, error) {
	url := "https://line-chrome-gw.line-apps.com/api/talk/long-polling/LF1"

	fmt.Printf("[DEBUG] Starting Long Polling for Verifier: %s\n", verifier)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-line-chrome-version", ExtensionVersion)
	req.Header.Set("x-lal", "en_US")
	req.Header["X-Line-Session-ID"] = []string{verifier}
	req.Header["X-LST"] = []string{"110000"} // Long Polling Timeout?

	// Generate HMAC for Polling
	hmacRunner, err := gen.GetRunner()
	if err != nil {
		return nil, fmt.Errorf("failed to get HMAC runner: %w", err)
	}

	path := strings.Split(url, "https://line-chrome-gw.line-apps.com")[1]

	signature, err := hmacRunner.GetSignature(path, "", c.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to generate HMAC for polling: %w", err)
	}
	req.Header.Set("x-hmac", signature)

	pollClient := &http.Client{Timeout: 120 * time.Second} // Increased timeout
	resp, err := pollClient.Do(req)
	if err != nil {
		fmt.Printf("[DEBUG] Polling network error: %v\n", err)
		time.Sleep(2 * time.Second)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		fmt.Printf("[DEBUG] Polling HTTP %d: %s\n", resp.StatusCode, string(body))
	} else {
		fmt.Printf("[DEBUG] Polling Response: %s\n", string(body))
	}

	var wrapper struct {
		Code    int                `json:"code"`
		Message string             `json:"message"`
		Data    LoginPollingResult `json:"data"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		fmt.Printf("[DEBUG] JSON Parse Error: %v\n", err)
		time.Sleep(2 * time.Second)
	}

	if wrapper.Data.Result.Metadata.AuthToken != "" || wrapper.Data.Result.Metadata.Certificate != "" {
		return &LoginResult{
			AuthToken:   wrapper.Data.Result.Metadata.AuthToken,
			Certificate: wrapper.Data.Result.Metadata.Certificate,
		}, nil
	}

	return nil, fmt.Errorf("polling timed out after 60 attempts")
}

func (c *Client) GetRSAKeyInfo() (*RSAKeyInfo, error) {
	// callRPC args marshals to [1]
	resp, err := c.callRPC("TalkService", "getRSAKeyInfo", 1)
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Code    int        `json:"code"`
		Message string     `json:"message"`
		Data    RSAKeyInfo `json:"data"`
	}
	if err := json.Unmarshal(resp, &wrapper); err != nil {
		return nil, err
	}
	return &wrapper.Data, nil
}

func (c *Client) callRPC(service, method string, args ...interface{}) ([]byte, error) {
	url := fmt.Sprintf("%s/%s/%s", BaseURL, service, method)

	bodyBytes, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal args: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-line-chrome-version", ExtensionVersion)
	req.Header.Set("x-line-application", "CHROMEOS\t3.7.1\tChrome_OS\t1")
	req.Header.Set("x-lal", "en_US")

	if c.AccessToken != "" {
		req.Header.Set("x-line-access", c.AccessToken)
	}

	hmacRunner, err := gen.GetRunner()
	if err != nil {
		return nil, fmt.Errorf("failed to get HMAC runner: %w", err)
	}

	signature, err := hmacRunner.GetSignature(strings.Split(url, "https://line-chrome-gw.line-apps.com")[1], string(bodyBytes), c.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to generate HMAC signature: %w", err)
	}
	req.Header.Set("x-hmac", signature)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// postWithHMAC is a small helper for non-standard RPC endpoints that still expect
// the same headers and HMAC signature as the Talk endpoints.
func (c *Client) postWithHMAC(fullURL string, body []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-line-chrome-version", ExtensionVersion)
	req.Header.Set("x-line-application", "CHROMEOS\t3.7.1\tChrome_OS\t1")
	req.Header.Set("x-lal", "en_US")

	hmacRunner, err := gen.GetRunner()
	if err != nil {
		return nil, fmt.Errorf("failed to get HMAC runner: %w", err)
	}

	path := strings.Split(fullURL, "https://line-chrome-gw.line-apps.com")[1]
	signature, err := hmacRunner.GetSignature(path, string(body), c.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to generate HMAC signature: %w", err)
	}
	req.Header.Set("x-hmac", signature)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return io.ReadAll(resp.Body)
}
