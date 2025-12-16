package line

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// LoginV2 performs the loginV2 RPC call to authenticate a user
func (c *Client) LoginV2(email, password, certificate, secret string) ([]byte, error) {
	req := LoginRequest{
		Type:             2,
		IdentityProvider: 1,
		Identifier:       email,
		Password:         password,
		KeepLoggedIn:     false,
		AccessLocation:   "",
		SystemName:       "Chrome",
		ModelName:        "",
		Certificate:      certificate,
		Verifier:         "",
		Secret:           secret, // PIN for Secret for type 2
		E2EEVersion:      1,
	}
	return c.callRPC("AuthService", "loginV2", req)
}

// LoginV2WithVerifier finalizes login using the verifier (post-E2EE confirm flow)
func (c *Client) LoginV2WithVerifier(verifier string) (*LoginResult, error) {
	req := LoginRequest{
		Type:             1,
		IdentityProvider: 1,
		Identifier:       "",
		Password:         "",
		KeepLoggedIn:     false,
		AccessLocation:   "",
		SystemName:       "Chrome",
		ModelName:        "",
		Certificate:      "",
		Verifier:         verifier,
		Secret:           "",
		E2EEVersion:      1,
	}

	respBytes, err := c.callRPC("AuthService", "loginV2", req)
	if err != nil {
		return nil, err
	}

	var wrapper struct {
		Code    int         `json:"code"`
		Message string      `json:"message"`
		Data    LoginResult `json:"data"`
	}
	if err := json.Unmarshal(respBytes, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to parse loginV2 (verifier) response: %w", err)
	}
	if wrapper.Code != 0 {
		return nil, fmt.Errorf("loginV2 with verifier failed: %s", wrapper.Message)
	}

	// Prefer the V3 token if present, otherwise fall back to legacy authToken
	if wrapper.Data.TokenV3IssueResult != nil && wrapper.Data.TokenV3IssueResult.AccessToken != "" {
		wrapper.Data.AuthToken = wrapper.Data.TokenV3IssueResult.AccessToken
		c.AccessToken = wrapper.Data.TokenV3IssueResult.AccessToken
	} else if wrapper.Data.AuthToken != "" {
		c.AccessToken = wrapper.Data.AuthToken
	}

	return &wrapper.Data, nil
}

// GetProfile fetches the user's profile information
func (c *Client) GetProfile() ([]byte, error) {
	return c.callRPC("TalkService", "getProfile", 2)
}

// GetEncryptedIdentityV3 fetches wrapped nonce and KDF params used to derive storage key.
func (c *Client) GetEncryptedIdentityV3() (*EncryptedIdentityV3, error) {
	resp, err := c.callRPC("TalkService", "getEncryptedIdentityV3")
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Code    int                 `json:"code"`
		Message string              `json:"message"`
		Data    EncryptedIdentityV3 `json:"data"`
	}
	if err := json.Unmarshal(resp, &wrapper); err != nil {
		return nil, err
	}
	if wrapper.Code != 0 {
		return nil, fmt.Errorf("getEncryptedIdentityV3 failed: %s", wrapper.Message)
	}
	return &wrapper.Data, nil
}

// NegotiateE2EEPublicKey fetches (or renews) the public key of the person you're talking to (E2EE).
func (c *Client) NegotiateE2EEPublicKey(mid string) (*E2EEPublicKey, error) {
	resp, err := c.callRPC("TalkService", "negotiateE2EEPublicKey", mid)
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(resp, &wrapper); err != nil {
		return nil, err
	}
	if wrapper.Code != 0 {
		return nil, fmt.Errorf("negotiateE2EEPublicKey failed: %s", wrapper.Message)
	}
	var data map[string]any
	if err := json.Unmarshal(wrapper.Data, &data); err != nil {
		return nil, err
	}

	var findString func(any) string
	findString = func(v any) string {
		switch t := v.(type) {
		case string:
			return t
		case map[string]any:
			for _, val := range t {
				if s := findString(val); s != "" {
					return s
				}
			}
		case []any:
			for _, val := range t {
				if s := findString(val); s != "" {
					return s
				}
			}
		}
		return ""
	}

	var findInt64 func(any) int64
	findInt64 = func(v any) int64 {
		switch t := v.(type) {
		case json.Number:
			if n, err := t.Int64(); err == nil {
				return n
			}
		case float64:
			return int64(t)
		case int64:
			return t
		case int:
			return int64(t)
		case string:
			if t == "" {
				return 0
			}
			if n, err := strconv.ParseInt(t, 10, 64); err == nil {
				return n
			}
		case map[string]any:
			for _, val := range t {
				if n := findInt64(val); n != 0 {
					return n
				}
			}
		case []any:
			for _, val := range t {
				if n := findInt64(val); n != 0 {
					return n
				}
			}
		}
		return 0
	}

	var findBool func(any) bool
	findBool = func(v any) bool {
		switch t := v.(type) {
		case bool:
			return t
		case string:
			b, err := strconv.ParseBool(t)
			return err == nil && b
		case map[string]any:
			for _, val := range t {
				if b := findBool(val); b {
					return true
				}
			}
		case []any:
			for _, val := range t {
				if b := findBool(val); b {
					return true
				}
			}
		}
		return false
	}

	pub := ""
	keyID := int64(0)
	if pk, ok := data["publicKey"].(map[string]any); ok {
		pub = findString(pk["keyData"])
		if keyID == 0 {
			keyID = findInt64(pk["keyId"])
		}
	}
	if pub == "" {
		pub = findString(data["publicKey"])
	}
	if pub == "" {
		pub = findString(data)
	}
	if keyID == 0 {
		keyID = findInt64(data["keyId"])
	}
	if keyID == 0 {
		keyID = findInt64(data)
	}
	if pub == "" || keyID == 0 {
		return nil, fmt.Errorf("negotiateE2EEPublicKey: missing fields (pub=%t keyID=%d raw=%s)", pub != "", keyID, string(wrapper.Data))
	}

	return &E2EEPublicKey{
		KeyID:        json.Number(strconv.FormatInt(keyID, 10)),
		PublicKey:    pub,
		E2EEVersion:  int(findInt64(data["e2eeVersion"])),
		Expired:      findBool(data["expired"]),
		CreatedTime:  json.Number(strconv.FormatInt(findInt64(data["createdTime"]), 10)),
		RenewalCount: int(findInt64(data["renewalCount"])),
	}, nil
}

func (c *Client) SendMessage(reqSeq int64, msg *Message) error {
	resp, err := c.callRPC("TalkService", "sendMessage", reqSeq, msg)
	if err != nil {
		return err
	}
	var wrapper struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(resp, &wrapper); err != nil {
		return err
	}
	if wrapper.Code != 0 {
		return fmt.Errorf("sendMessage failed: %s", wrapper.Message)
	}
	return nil
}

