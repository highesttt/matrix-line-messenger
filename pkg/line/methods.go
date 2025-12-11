package line

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// LoginV2 performs the loginV2 RPC call to authenticate a user
func (c *Client) LoginV2(email, password, certificate string) ([]byte, error) {
	req := LoginRequest{
		Type:             0,
		IdentityProvider: 1,
		Identifier:       email,
		Password:         password,
		KeepLoggedIn:     true,
		AccessLocation:   "127.0.0.1",
		SystemName:       "Chrome",
		Certificate:      certificate,
		E2EEVersion:      1,
	}
	return c.callRPC("AuthService", "loginV2", req)
}

// GetProfile fetches the user's profile information
func (c *Client) GetProfile() ([]byte, error) {
	return c.callRPC("TalkService", "getProfile", 2)
}

// FetchOps calls /api/operation/receive
func (c *Client) FetchOps(localRev int64) ([]byte, error) {
	q := url.Values{}
	q.Set("localRev", strconv.FormatInt(localRev, 10))
	q.Set("version", ChromeVersion)
	q.Set("lastPartialFullSyncs", "{}")
	q.Set("language", "en_US")

	fullURL := fmt.Sprintf("https://line-chrome-gw.line-apps.com/api/operation/receive?%s", q.Encode())

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")

	if c.AccessToken != "" {
		req.Header.Set("x-line-access", c.AccessToken)
		req.Header.Set("Cookie", fmt.Sprintf("lct=%s", c.AccessToken))
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("polling error: %d - %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

func (c *Client) GetMessageBoxes() ([]byte, error) {
	reqStruct := map[string]interface{}{
		"activeOnly":                     true,
		"unreadOnly":                     false,
		"messageBoxCountLimit":           100,
		"withUnreadCount":                true,
		"lastMessagesPerMessageBoxCount": 1,
	}
	// "2" is the syncReason
	return c.callRPC("TalkService", "getMessageBoxes", reqStruct, 2)
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-line-chrome-version", ChromeVersion)
	req.Header.Set("x-lal", "en_US")
	if c.AccessToken != "" {
		req.Header.Set("x-line-access", c.AccessToken)
	}
}
