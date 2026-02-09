package line

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	gen "github.com/highesttt/matrix-line-messenger/pkg"
	"github.com/highesttt/matrix-line-messenger/pkg/line/password"
	"github.com/highesttt/matrix-line-messenger/pkg/line/secret"
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
	if err != nil && isLoginNotSupported(err) {
		respBytes, err = c.LoginV2WithType(0, rsaKey.KeyName, encryptedPass, "", "")
	}
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
	if wrapper.Code != 0 {
		return nil, fmt.Errorf("loginV2 failed: %s (code %d)", wrapper.Message, wrapper.Code)
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

func isLoginNotSupported(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "\"code\":89") || strings.Contains(msg, "not supported")
}

func (c *Client) WaitForLogin(verifier string) (*LoginResult, error) {
	url := "https://line-chrome-gw.line-apps.com/api/talk/long-polling/LF1"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-line-chrome-version", ExtensionVersion)
	req.Header.Set("x-lal", "en_US")
	req.Header["X-Line-Session-ID"] = []string{verifier}
	req.Header["X-LST"] = []string{"110000"} // Long Polling Timeout

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
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var wrapper struct {
		Code    int                `json:"code"`
		Message string             `json:"message"`
		Data    LoginPollingResult `json:"data"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to parse polling response: %w", err)
	}

	meta := wrapper.Data.Result.Metadata

	// Send confirmE2EELogin when the encrypted key chain is provided (post-LF1 step)
	if meta.EncryptedKeyChain != "" && meta.PublicKey != "" {
		if err := c.ConfirmE2EELogin(verifier, meta.PublicKey, meta.EncryptedKeyChain); err == nil {
			// After confirm succeeds, finalize login using the verifier to get our access token
			if res, err := c.LoginV2WithVerifier(verifier); err == nil {
				res.EncryptedKeyChain = meta.EncryptedKeyChain
				res.E2EEPublicKey = meta.PublicKey
				res.E2EEVersion = meta.E2EEVersion
				res.E2EEKeyID = meta.KeyID
				return res, nil
			}
		}
	}

	if meta.AuthToken != "" || meta.Certificate != "" {
		return &LoginResult{
			AuthToken:   meta.AuthToken,
			Certificate: meta.Certificate,
		}, nil
	}

	return nil, fmt.Errorf("polling returned without success")
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

	var bodyBytes []byte
	if len(args) == 0 {
		bodyBytes = []byte("[]")
	} else {
		var err error
		bodyBytes, err = json.Marshal(args)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal args: %w", err)
		}
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
		req.Header.Set("Cookie", fmt.Sprintf("lct=%s", c.AccessToken))
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

// ConfirmE2EELogin completes the E2EE handshake after LF1 by hashing the encrypted key
// chain and posting it alongside the verifier.
func (c *Client) ConfirmE2EELogin(verifier, serverPublicKeyB64, encryptedKeyChainB64 string) error {
	runner, err := gen.GetRunner()
	if err != nil {
		return fmt.Errorf("failed to init runner: %w", err)
	}

	hash, err := runner.GenerateConfirmHash(serverPublicKeyB64, encryptedKeyChainB64)
	if err != nil {
		return fmt.Errorf("failed to derive confirm hash: %w", err)
	}

	bodyBytes, err := json.Marshal([]string{verifier, hash})
	if err != nil {
		return fmt.Errorf("failed to marshal confirm payload: %w", err)
	}

	url := "https://line-chrome-gw.line-apps.com/api/talk/thrift/Talk/AuthService/confirmE2EELogin"
	respBytes, err := c.postWithHMAC(url, bodyBytes)
	if err != nil {
		return err
	}

	var wrapper struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    string `json:"data"`
	}
	if err := json.Unmarshal(respBytes, &wrapper); err != nil {
		return fmt.Errorf("failed to parse confirmE2EELogin response: %w", err)
	}
	if wrapper.Code != 0 {
		return fmt.Errorf("confirmE2EELogin failed: %s", wrapper.Message)
	}

	return nil
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
	if c.AccessToken != "" {
		req.Header.Set("x-line-access", c.AccessToken)
		req.Header.Set("Cookie", fmt.Sprintf("lct=%s", c.AccessToken))
	}

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

func (c *Client) RefreshAccessToken(refreshToken string) (*TokenV3IssueResult, error) {
	url := "https://line-chrome-gw.line-apps.com/api/auth/tokenRefresh"

	reqBody := RefreshAccessTokenRequest{
		RefreshToken: refreshToken,
		RetryCount:   0,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal refresh request: %w", err)
	}

	respBytes, err := c.postWithHMAC(url, bodyBytes)
	if err != nil {
		return nil, err
	}

	var res TokenV3IssueResult
	if err := json.Unmarshal(respBytes, &res); err != nil {
		return nil, fmt.Errorf("failed to parse refresh response: %w", err)
	}

	if res.AccessToken != "" {
		c.AccessToken = res.AccessToken
	}

	return &res, nil
}

const OBSBaseURL = "https://obs.line-apps.com"

// UploadOBS uploads media to LINE's Object Storage and returns the Object ID (OID).
// Default uses "emi" SID for images
func (c *Client) UploadOBS(data []byte) (string, error) {
	return c.UploadOBSWithSID(data, "emi")
}

// SID: emi (images), emv (videos), ema (audio), emf (files)
func (c *Client) UploadOBSWithSID(data []byte, sid string) (string, error) {
	// First, acquire the OBS-specific encrypted access token
	obsToken, err := c.AcquireEncryptedAccessToken()
	if err != nil {
		return "", fmt.Errorf("failed to acquire OBS token: %w", err)
	}

	// Generate a random Request ID (UUID-like)
	reqIDBytes := make([]byte, 16)
	if _, err := rand.Read(reqIDBytes); err != nil {
		return "", fmt.Errorf("failed to generate reqID: %w", err)
	}
	reqID := fmt.Sprintf("%x-%x-%x-%x-%x", reqIDBytes[0:4], reqIDBytes[4:6], reqIDBytes[6:8], reqIDBytes[8:10], reqIDBytes[10:])

	url := fmt.Sprintf("%s/r/talk/%s/reqid-%s", OBSBaseURL, sid, reqID)

	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("failed to create OBS request: %w", err)
	}

	// Construct X-Obs-Params header (base64 encoded JSON)
	obsParams := map[string]string{
		"ver":  "2.0",
		"name": fmt.Sprintf("%d", time.Now().UnixMilli()),
		"type": "file",
	}
	obsParamsJSON, _ := json.Marshal(obsParams)
	obsParamsB64 := base64.StdEncoding.EncodeToString(obsParamsJSON)

	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-line-application", "CHROMEOS\t3.7.1\tChrome_OS\t1")
	req.Header.Set("x-lal", "en_US")
	// OBS expects application/octet-stream for binary uploads
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Obs-Params", obsParamsB64)

	// Use the OBS-specific access token
	req.Header.Set("x-line-access", obsToken)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("OBS upload request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return "", fmt.Errorf("OBS upload failed (%d): %s", resp.StatusCode, string(body))
	}

	// The OID is typically returned in the x-obs-oid header
	oid := resp.Header.Get("x-obs-oid")
	if oid == "" {
		// Fallback: checks if reqID is used as OID or if body contains it (rare for this endpoint)
		return "", fmt.Errorf("OBS upload succeeded but no x-obs-oid header returned")
	}

	return oid, nil
}

// UploadOBSWithOID uploads data to a specific OID (used for preview/thumbnail uploads)
func (c *Client) UploadOBSWithOID(data []byte, oid string) error {
	return c.UploadOBSWithOIDAndSID(data, oid, "emi")
}

// UploadOBSWithOIDAndSID uploads data to a specific OID with a specific SID
func (c *Client) UploadOBSWithOIDAndSID(data []byte, oid string, sid string) error {
	// First, acquire the OBS-specific encrypted access token
	obsToken, err := c.AcquireEncryptedAccessToken()
	if err != nil {
		return fmt.Errorf("failed to acquire OBS token: %w", err)
	}

	url := fmt.Sprintf("%s/r/talk/%s/%s", OBSBaseURL, sid, oid)

	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create OBS request: %w", err)
	}

	// Construct X-Obs-Params header (base64 encoded JSON)
	obsParams := map[string]string{
		"ver":  "2.0",
		"name": fmt.Sprintf("%d", time.Now().UnixMilli()),
		"type": "file",
	}
	obsParamsJSON, _ := json.Marshal(obsParams)
	obsParamsB64 := base64.StdEncoding.EncodeToString(obsParamsJSON)

	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-line-application", "CHROMEOS\t3.7.1\tChrome_OS\t1")
	req.Header.Set("x-lal", "en_US")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Obs-Params", obsParamsB64)
	req.Header.Set("x-line-access", obsToken)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("OBS upload request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return fmt.Errorf("OBS upload failed (%d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// DownloadOBS retrieves media from LINE's Object Storage using the OID.
func (c *Client) DownloadOBS(oid string, messageID string) ([]byte, error) {
	return c.DownloadOBSWithSID(oid, messageID, "emi")
}

func (c *Client) DownloadOBSWithSID(oid string, messageID string, sid string) ([]byte, error) {
	// URL structure: https://obs.line-apps.com/r/talk/{SID}/{OID}
	// SID: emi (images), emv (videos), ema (audio), emf (files)
	url := fmt.Sprintf("%s/r/talk/%s/%s", OBSBaseURL, sid, oid)

	obsToken, err := c.AcquireEncryptedAccessToken()
	if err != nil {
		return nil, fmt.Errorf("failed to acquire encrypted access token: %w", err)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create OBS download request: %w", err)
	}

	req.Header.Set("User-Agent", UserAgent)
	if obsToken != "" {
		req.Header.Set("x-line-access", obsToken)
	}

	// Add x-talk-meta header with Thrift-encoded message
	if messageID != "" {
		talkMeta := c.constructTalkMeta(messageID)
		req.Header.Set("x-talk-meta", talkMeta)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OBS download request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OBS download failed (%d): %s", resp.StatusCode, string(body))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OBS response body: %w", err)
	}

	return data, nil
}

// this builds x-talk-meta
// base64(json({"message": base64(thrift_message)}))
func (c *Client) constructTalkMeta(messageID string) string {
	// [field_type][field_id_16bit][string_length_32bit][string_bytes]...[stop_byte]
	var buf bytes.Buffer

	// Field 4 (id) - STRING type (0x0B)
	buf.WriteByte(0x0B)                                          // TType.STRING
	binary.Write(&buf, binary.BigEndian, uint16(4))              // field ID = 4
	binary.Write(&buf, binary.BigEndian, uint32(len(messageID))) // string length
	buf.WriteString(messageID)                                   // message ID

	// required to send a valid struct
	buf.WriteByte(0x0F)                              // TType.LIST
	binary.Write(&buf, binary.BigEndian, uint16(27)) // field ID = 27
	buf.WriteByte(0x0C)                              // element type = STRUCT
	binary.Write(&buf, binary.BigEndian, uint32(0))  // list size = 0

	buf.WriteByte(0x00)

	thriftB64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	metaJSON := map[string]string{"message": thriftB64}
	metaBytes, _ := json.Marshal(metaJSON)

	return base64.StdEncoding.EncodeToString(metaBytes)
}

func (c *Client) GetPageInfo(url string) (*PageInfoResult, error) {
	apiURL := "https://legy-jp.line-apps.com/sc/api/v2/pageinfo/get"
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Add("url", url)
	q.Add("caller", "LINE_CHROME")
	req.URL.RawQuery = q.Encode()

	req.Header.Set("User-Agent", UserAgent)
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
		return nil, fmt.Errorf("pageinfo request failed: %d", resp.StatusCode)
	}

	var wrapper PageInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, err
	}

	if wrapper.Code != 0 {
		return nil, fmt.Errorf("pageinfo API error: %s", wrapper.Message)
	}

	return &wrapper.Result, nil
}
