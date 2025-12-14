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
)

const (
	BaseURL       = "https://line-chrome-gw.line-apps.com/api/talk/thrift/Talk"
	ExtensionVersion = "3.7.1"
	UserAgent     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
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
	req.Header.Set("x-lal", "en_US")

	if c.AccessToken != "" {
		req.Header.Set("x-line-access", c.AccessToken)
	}

	hmacGenerator, err := gen.NewGenerator()
	if err != nil {
		return nil, fmt.Errorf("failed to create HMAC generator: %w", err)
	}
	defer hmacGenerator.Close()

	signature, err := hmacGenerator.GenerateSignature(strings.Split(url, "https://line-chrome-gw.line-apps.com")[1], string(bodyBytes), c.AccessToken)
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