package line

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	BaseURL       = "https://line-chrome-gw.line-apps.com/api/talk/thrift/Talk"
	ChromeVersion = "3.7.1"
	UserAgent     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
	// !FIX: ChannelSecret is required for x-hmac header, but its value is unknown at the moment
	ChannelSecret = "NOT YET IMPLEMENTED"
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
	req.Header.Set("x-line-chrome-version", ChromeVersion)
	req.Header.Set("x-lal", "en_US")

	if c.AccessToken != "" {
		req.Header.Set("x-line-access", c.AccessToken)
	}

	// !FIX: Requests don't work without hmac header but generating them does not work
	signature := c.generateHMAC(bodyBytes)
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

// temporary generateHMAC function for x-hmac
func (c *Client) generateHMAC(body []byte) string {
	mac := hmac.New(sha256.New, []byte(ChannelSecret))
	mac.Write(body)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
