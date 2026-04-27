package line

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// LoginV2 performs the loginV2 RPC call to authenticate a user
func (c *Client) LoginV2(email, password, certificate, secret string) ([]byte, error) {
	return c.LoginV2WithType(2, email, password, certificate, secret)
}

func (c *Client) LoginV2WithType(loginType int, email, password, certificate, secret string) ([]byte, error) {
	req := LoginRequest{
		Type:             loginType,
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

func (c *Client) CreateQRSession() (string, error) {
	var wrapper struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			AuthSessionID string `json:"authSessionId"`
		} `json:"data"`
	}
	if err := c.callQRRPC("SecondaryQrCodeLoginService", "createSession", "", "", &wrapper, struct{}{}); err != nil {
		return "", err
	}
	if wrapper.Code != 0 {
		return "", fmt.Errorf("createSession failed: %s", wrapper.Message)
	}
	return wrapper.Data.AuthSessionID, nil
}

func (c *Client) CreateQRCode(authSessionID string) (*QRCodeResponse, error) {
	var wrapper struct {
		Code    int            `json:"code"`
		Message string         `json:"message"`
		Data    QRCodeResponse `json:"data"`
	}
	req := struct {
		AuthSessionID string `json:"authSessionId"`
	}{AuthSessionID: authSessionID}
	if err := c.callQRRPC("SecondaryQrCodeLoginService", "createQrCode", "", "", &wrapper, req); err != nil {
		return nil, err
	}
	if wrapper.Code != 0 {
		return nil, fmt.Errorf("createQrCode failed: %s", wrapper.Message)
	}
	return &wrapper.Data, nil
}

func (c *Client) CheckQRCodeVerified(authSessionID string) error {
	return c.checkQRPermitNotice("checkQrCodeVerified", authSessionID, "150000")
}

func (c *Client) VerifyCertificate(authSessionID, certificate string) error {
	var wrapper struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	req := struct {
		AuthSessionID string `json:"authSessionId"`
		Certificate   string `json:"certificate"`
	}{AuthSessionID: authSessionID, Certificate: certificate}
	if err := c.callQRRPC("SecondaryQrCodeLoginService", "verifyCertificate", "", "", &wrapper, req); err != nil {
		return err
	}
	if wrapper.Code != 0 {
		return fmt.Errorf("verifyCertificate failed: %s", wrapper.Message)
	}
	return nil
}

func (c *Client) CreatePinCode(authSessionID string) (string, error) {
	var wrapper struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			PinCode string `json:"pinCode"`
		} `json:"data"`
	}
	req := struct {
		AuthSessionID string `json:"authSessionId"`
	}{AuthSessionID: authSessionID}
	if err := c.callQRRPC("SecondaryQrCodeLoginService", "createPinCode", "", "", &wrapper, req); err != nil {
		return "", err
	}
	if wrapper.Code != 0 {
		return "", fmt.Errorf("createPinCode failed: %s", wrapper.Message)
	}
	return wrapper.Data.PinCode, nil
}

func (c *Client) CheckPinCodeVerified(authSessionID string) error {
	return c.checkQRPermitNotice("checkPinCodeVerified", authSessionID, "110000")
}

func (c *Client) QRCodeLoginV2(authSessionID string) (*LoginResult, error) {
	var wrapper struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			LoginResult
			LastBindTimestamp string `json:"lastBindTimestamp"`
			MetaData          struct {
				EncryptedKeyChain string `json:"encryptedKeyChain"`
				E2EEVersion       string `json:"e2eeVersion"`
				KeyID             string `json:"keyId"`
				PublicKey         string `json:"publicKey"`
			} `json:"metaData"`
		} `json:"data"`
	}
	req := struct {
		SystemName          string `json:"systemName"`
		ModelName           string `json:"modelName"`
		AutoLoginIsRequired bool   `json:"autoLoginIsRequired"`
		AuthSessionID       string `json:"authSessionId"`
	}{
		SystemName:          "CHROMEOS",
		ModelName:           "CHROME",
		AutoLoginIsRequired: false,
		AuthSessionID:       authSessionID,
	}
	if err := c.callQRRPC("SecondaryQrCodeLoginService", "qrCodeLoginV2", "", "", &wrapper, req); err != nil {
		return nil, err
	}
	if wrapper.Code != 0 {
		return nil, fmt.Errorf("qrCodeLoginV2 failed: %s", wrapper.Message)
	}

	res := wrapper.Data.LoginResult
	res.LastPrimaryBindTime = wrapper.Data.LastBindTimestamp
	res.EncryptedKeyChain = wrapper.Data.MetaData.EncryptedKeyChain
	res.E2EEPublicKey = wrapper.Data.MetaData.PublicKey
	res.E2EEVersion = wrapper.Data.MetaData.E2EEVersion
	res.E2EEKeyID = wrapper.Data.MetaData.KeyID
	if res.TokenV3IssueResult != nil && res.TokenV3IssueResult.AccessToken != "" {
		res.AuthToken = res.TokenV3IssueResult.AccessToken
		c.AccessToken = res.TokenV3IssueResult.AccessToken
	} else if res.AuthToken != "" {
		c.AccessToken = res.AuthToken
	}
	return &res, nil
}

func (c *Client) checkQRPermitNotice(method, authSessionID, longPollingTimeout string) error {
	var wrapper struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	req := struct {
		AuthSessionID string `json:"authSessionId"`
	}{AuthSessionID: authSessionID}
	if err := c.callQRRPC("SecondaryQrCodeLoginPermitNoticeService", method, authSessionID, longPollingTimeout, &wrapper, req); err != nil {
		return err
	}
	if wrapper.Code != 0 {
		return fmt.Errorf("%s failed: %s", method, wrapper.Message)
	}
	return nil
}

func (c *Client) callQRRPC(service, method, authSessionID, longPollingTimeout string, out interface{}, args ...interface{}) error {
	url := fmt.Sprintf("%s/%s/%s", QRLoginBaseURL, service, method)

	bodyBytes, err := json.Marshal(args)
	if err != nil {
		return fmt.Errorf("failed to marshal QR args: %w", err)
	}

	respBytes, err := c.postWithHMACOptions(url, bodyBytes, hmacPostOptions{
		includeLineApplication: false,
		sessionID:              authSessionID,
		longPollingTimeout:     longPollingTimeout,
	})
	if err != nil {
		return err
	}
	if err := json.Unmarshal(respBytes, out); err != nil {
		return fmt.Errorf("failed to parse %s response: %w", method, err)
	}
	return nil
}

// GetProfile fetches the user's profile information
func (c *Client) GetProfile() (*Profile, error) {
	resp, err := c.callRPC("TalkService", "getProfile", 2)
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Code    int     `json:"code"`
		Message string  `json:"message"`
		Data    Profile `json:"data"`
	}
	if err := json.Unmarshal(resp, &wrapper); err != nil {
		return nil, err
	}
	if wrapper.Code != 0 {
		return nil, fmt.Errorf("getProfile failed: %s", wrapper.Message)
	}
	return &wrapper.Data, nil
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
	return &wrapper.Data, nil
}

func (c *Client) GetE2EEGroupSharedKey(chatMid string, groupKeyID int) (*E2EEGroupSharedKey, error) {
	// args: [1, chatMid, groupKeyID]
	resp, err := c.callRPC("TalkService", "getE2EEGroupSharedKey", 1, chatMid, groupKeyID)
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
		return nil, parseE2EEGroupKeyError("getE2EEGroupSharedKey", wrapper.Message, wrapper.Data)
	}
	var data E2EEGroupSharedKey
	if err := json.Unmarshal(wrapper.Data, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

func (c *Client) GetLastE2EEGroupSharedKey(chatMid string) (*E2EEGroupSharedKey, error) {
	resp, err := c.callRPC("TalkService", "getLastE2EEGroupSharedKey", 1, chatMid)
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
		return nil, parseE2EEGroupKeyError("getLastE2EEGroupSharedKey", wrapper.Message, wrapper.Data)
	}
	var data E2EEGroupSharedKey
	if err := json.Unmarshal(wrapper.Data, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

func (c *Client) RegisterE2EEGroupKey(chatMid string, receiverMids []string, receiverKeyIDs []int, encryptedSharedKeys []string) (*E2EEGroupSharedKey, error) {
	resp, err := c.callRPC("TalkService", "registerE2EEGroupKey", 1, chatMid, receiverMids, receiverKeyIDs, encryptedSharedKeys)
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
		return nil, parseE2EEGroupKeyError("registerE2EEGroupKey", wrapper.Message, wrapper.Data)
	}
	var data E2EEGroupSharedKey
	if err := json.Unmarshal(wrapper.Data, &data); err != nil {
		return nil, err
	}
	return &data, nil
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
	return parseE2EEPublicKey(wrapper.Data)
}

func parseE2EEPublicKey(rawData []byte) (*E2EEPublicKey, error) {
	var payload e2eePublicKeyPayload
	dec := json.NewDecoder(bytes.NewReader(rawData))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return nil, fmt.Errorf("%w: failed to parse key data: %w", ErrNoUsableE2EEPublicKey, err)
	}

	key := payload.PublicKey
	if key == nil && (payload.KeyData != "" || payload.KeyID != "") {
		key = &e2eePublicKeyData{
			Version:     payload.Version,
			KeyID:       payload.KeyID,
			KeyData:     payload.KeyData,
			CreatedTime: payload.CreatedTime,
		}
	}
	if key == nil || key.KeyData == "" || key.KeyID == "" {
		return nil, fmt.Errorf("%w: missing fields (pub=%t keyID=%s raw=%s)", ErrNoUsableE2EEPublicKey, key != nil && key.KeyData != "", keyIDString(key), string(rawData))
	}
	if err := validateE2EEPublicKeyData(key.KeyData); err != nil {
		return nil, fmt.Errorf("%w: invalid key data: %w", ErrNoUsableE2EEPublicKey, err)
	}

	keyID, err := key.KeyID.Int64()
	if err != nil || keyID == 0 {
		return nil, fmt.Errorf("%w: invalid key ID %q", ErrNoUsableE2EEPublicKey, key.KeyID)
	}

	return &E2EEPublicKey{
		KeyID:        json.Number(strconv.FormatInt(keyID, 10)),
		PublicKey:    key.KeyData,
		E2EEVersion:  payload.E2EEVersion,
		Expired:      payload.Expired,
		CreatedTime:  key.CreatedTime,
		RenewalCount: payload.RenewalCount,
	}, nil
}

type e2eePublicKeyPayload struct {
	AllowedTypes []int              `json:"allowedTypes"`
	SpecVersion  int                `json:"specVersion"`
	PublicKey    *e2eePublicKeyData `json:"publicKey"`
	Version      int                `json:"version"`
	KeyID        json.Number        `json:"keyId"`
	KeyData      string             `json:"keyData"`
	CreatedTime  json.Number        `json:"createdTime"`
	E2EEVersion  int                `json:"e2eeVersion"`
	Expired      bool               `json:"expired"`
	RenewalCount int                `json:"renewalCount"`
}

type e2eePublicKeyData struct {
	Version     int         `json:"version"`
	KeyID       json.Number `json:"keyId"`
	KeyData     string      `json:"keyData"`
	CreatedTime json.Number `json:"createdTime"`
}

func keyIDString(key *e2eePublicKeyData) string {
	if key == nil {
		return "0"
	}
	return key.KeyID.String()
}

func validateE2EEPublicKeyData(keyData string) error {
	decoded, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		return err
	}
	if len(decoded) != 32 {
		return fmt.Errorf("decoded key length %d, want 32", len(decoded))
	}
	return nil
}

func (c *Client) GetLastE2EEPublicKeys(chatMid string) (map[string]*E2EEPublicKey, error) {
	resp, err := c.callRPC("TalkService", "getLastE2EEPublicKeys", chatMid)
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
		return nil, parseE2EEPublicKeyError("getLastE2EEPublicKeys", wrapper.Message, wrapper.Data)
	}

	var rawKeys map[string]json.RawMessage
	if err := json.Unmarshal(wrapper.Data, &rawKeys); err != nil {
		return nil, err
	}
	keys := make(map[string]*E2EEPublicKey, len(rawKeys))
	for mid, rawKey := range rawKeys {
		key, err := parseE2EEPublicKey(rawKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse E2EE public key for %s: %w", mid, err)
		}
		keys[mid] = key
	}
	return keys, nil
}

func (c *Client) GetE2EEPublicKey(mid string, keyVersion, keyID int) (*E2EEPublicKey, error) {
	resp, err := c.callRPC("TalkService", "getE2EEPublicKey", mid, keyVersion, keyID)
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
		return nil, fmt.Errorf("getE2EEPublicKey failed: %s", wrapper.Message)
	}

	return parseE2EEPublicKey(wrapper.Data)
}

func (c *Client) SendMessage(reqSeq int64, msg *Message) (*Message, error) {
	resp, err := c.callRPC("TalkService", "sendMessage", reqSeq, msg)
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Code    int      `json:"code"`
		Message string   `json:"message"`
		Data    *Message `json:"data"`
	}
	if err := json.Unmarshal(resp, &wrapper); err != nil {
		return nil, err
	}
	if wrapper.Code != 0 {
		return nil, fmt.Errorf("sendMessage failed: %s", wrapper.Message)
	}
	return wrapper.Data, nil
}

// SendChatChecked sends a read receipt for a message in a chat
func (c *Client) SendChatChecked(chatMid, messageID string) error {
	_, err := c.callRPC("TalkService", "sendChatChecked", 0, chatMid, messageID)
	return err
}

// GetContactsV2 fetches contact details for a list of MIDs.
func (c *Client) GetContactsV2(mids []string) (*ContactsResponse, error) {
	req := GetContactsV2Request{TargetUserMids: mids}
	resp, err := c.callRPC("TalkService", "getContactsV2", req, 2)
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Code    int              `json:"code"`
		Message string           `json:"message"`
		Data    ContactsResponse `json:"data"`
	}
	if err := json.Unmarshal(resp, &wrapper); err != nil {
		return nil, err
	}
	if wrapper.Code != 0 {
		return nil, fmt.Errorf("getContactsV2 failed: %s", wrapper.Message)
	}
	return &wrapper.Data, nil
}

// GetBuddyProfile fetches the profile of a LINE official/business account (buddy).
func (c *Client) GetBuddyProfile(mid string) (*BuddyProfile, error) {
	resp, err := c.callRPC("BuddyService", "getBuddyProfile", mid)
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Code    int          `json:"code"`
		Message string       `json:"message"`
		Data    BuddyProfile `json:"data"`
	}
	if err := json.Unmarshal(resp, &wrapper); err != nil {
		return nil, err
	}
	if wrapper.Code != 0 {
		return nil, fmt.Errorf("getBuddyProfile failed: %s", wrapper.Message)
	}
	return &wrapper.Data, nil
}

func (c *Client) GetAllChatMids(withMemberChats, withInvitedChats bool) (*GetAllChatMidsResponse, error) {
	req := GetAllChatMidsRequest{
		WithMemberChats:  withMemberChats,
		WithInvitedChats: withInvitedChats,
	}
	resp, err := c.callRPC("TalkService", "getAllChatMids", req, 2)
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Code    int                    `json:"code"`
		Message string                 `json:"message"`
		Data    GetAllChatMidsResponse `json:"data"`
	}
	if err := json.Unmarshal(resp, &wrapper); err != nil {
		return nil, err
	}
	if wrapper.Code != 0 {
		return nil, fmt.Errorf("getAllChatMids failed: %s", wrapper.Message)
	}
	return &wrapper.Data, nil
}

func (c *Client) GetChats(mids []string, withMembers, withInvitees bool) (*GetChatsResponse, error) {
	req := GetChatsRequest{
		ChatMids:     mids,
		WithMembers:  withMembers,
		WithInvitees: withInvitees,
	}
	resp, err := c.callRPC("TalkService", "getChats", req, 2)
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Code    int              `json:"code"`
		Message string           `json:"message"`
		Data    GetChatsResponse `json:"data"`
	}
	if err := json.Unmarshal(resp, &wrapper); err != nil {
		return nil, err
	}
	if wrapper.Code != 0 {
		return nil, fmt.Errorf("getChats failed: %s", wrapper.Message)
	}
	return &wrapper.Data, nil
}

func (c *Client) GetLastOpRevision() (int64, error) {
	resp, err := c.callRPC("TalkService", "getLastOpRevision")
	if err != nil {
		return 0, err
	}
	var wrapper struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    string `json:"data"`
	}
	if err := json.Unmarshal(resp, &wrapper); err != nil {
		return 0, err
	}
	if wrapper.Code != 0 {
		return 0, fmt.Errorf("getLastOpRevision failed: %s", wrapper.Message)
	}
	if wrapper.Data == "" {
		return 0, fmt.Errorf("getLastOpRevision returned empty data")
	}
	rev, err := strconv.ParseInt(wrapper.Data, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("getLastOpRevision invalid data: %w", err)
	}
	return rev, nil
}

// this token is used to encrypt images, videos, and files uploaded to LINE's OBS storage
func (c *Client) AcquireEncryptedAccessToken() (string, error) {
	// 2 = FeatureType::OBS_Authorization.
	resp, err := c.callRPC("TalkService", "acquireEncryptedAccessToken", 2)
	if err != nil {
		return "", err
	}

	var wrapper struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    string `json:"data"` // Format: "expirySeconds\x1eToken"
	}

	if err := json.Unmarshal(resp, &wrapper); err != nil {
		return "", fmt.Errorf("failed to decode acquireEncryptedAccessToken response: %w", err)
	}

	if wrapper.Code != 0 {
		return "", fmt.Errorf("acquireEncryptedAccessToken API error: %s", wrapper.Message)
	}

	parts := strings.Split(wrapper.Data, "\x1e")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid encrypted token format: missing separator")
	}

	return parts[1], nil
}

func (c *Client) GetMessageBoxes(options MessageBoxesOptions) (*MessageBoxesResponse, error) {
	resp, err := c.callRPC("TalkService", "getMessageBoxes", options, 2)
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Code    int                  `json:"code"`
		Message string               `json:"message"`
		Data    MessageBoxesResponse `json:"data"`
	}
	if err := json.Unmarshal(resp, &wrapper); err != nil {
		return nil, err
	}
	if wrapper.Code != 0 {
		return nil, fmt.Errorf("getMessageBoxes failed: %s", wrapper.Message)
	}
	return &wrapper.Data, nil
}

func (c *Client) GetRecentMessagesV2(chatMid string, limit int) ([]*Message, error) {
	resp, err := c.callRPC("TalkService", "getRecentMessagesV2", chatMid, limit)
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Code    int        `json:"code"`
		Message string     `json:"message"`
		Data    []*Message `json:"data"`
	}
	if err := json.Unmarshal(resp, &wrapper); err != nil {
		return nil, err
	}
	if wrapper.Code != 0 {
		return nil, fmt.Errorf("getRecentMessagesV2 failed: %s", wrapper.Message)
	}
	return wrapper.Data, nil
}

func (c *Client) UnsendMessage(reqSeq int64, messageID string) error {
	_, err := c.callRPC("TalkService", "unsendMessage", reqSeq, messageID)
	return err
}

func (c *Client) SendChatRemoved(reqSeq int64, chatMid, lastReadMessageId string, lastReadMessageTime int64) error {
	_, err := c.callRPC("TalkService", "sendChatRemoved", reqSeq, chatMid, lastReadMessageId, lastReadMessageTime)
	return err
}

// DetermineMediaMessageFlow asks the server which upload path to use for media
// in a given chat. Flow value 2 = E2EE encrypted upload, 1 = plain upload.
func (c *Client) DetermineMediaMessageFlow(chatMid string) (*MediaMessageFlowResponse, error) {
	req := map[string]string{"chatMid": chatMid}
	resp, err := c.callRPC("TalkService", "determineMediaMessageFlow", req)
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Code    int                      `json:"code"`
		Message string                   `json:"message"`
		Data    MediaMessageFlowResponse `json:"data"`
	}
	if err := json.Unmarshal(resp, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to parse determineMediaMessageFlow response: %w", err)
	}
	if wrapper.Code != 0 {
		return nil, fmt.Errorf("determineMediaMessageFlow failed: %s", wrapper.Message)
	}
	return &wrapper.Data, nil
}
