package line

import "encoding/json"

type LoginRequest struct {
	Type             int    `json:"type"` // 0=Email/Password, 1=QRCode, 2=Secret
	IdentityProvider int    `json:"identityProvider"`
	Identifier       string `json:"identifier"` // Identifier from RSA
	Password         string `json:"password"`   // \sessionkeysize{sessionKey}+\emailsize{email}+\passwordsize{password}
	KeepLoggedIn     bool   `json:"keepLoggedIn"`
	AccessLocation   string `json:"accessLocation"`
	SystemName       string `json:"systemName"`
	ModelName        string `json:"modelName"`
	Certificate      string `json:"certificate"` // When device has been verified, Type=0
	Verifier         string `json:"verifier"`
	Secret           string `json:"secret"` // PIN for Type=2 login
	E2EEVersion      int    `json:"e2eeVersion"`
}

type Location struct {
	Title     string  `json:"title"`
	Address   string  `json:"address"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// SyncReason is often just an integer, e.g. 2
type SyncReason int

type Operation struct {
	Revision    json.Number `json:"revision"`
	Type        int         `json:"type"` // 25=Send, 26=Receive
	ReqSeq      int         `json:"reqSeq"`
	Message     *Message    `json:"message,omitempty"`
	Param1      string      `json:"param1,omitempty"`
	Param2      string      `json:"param2,omitempty"`
	Param3      string      `json:"param3,omitempty"`
	CreatedTime json.Number `json:"createdTime"`
}

type Message struct {
	ID              string            `json:"id"`
	From            string            `json:"from"`
	To              string            `json:"to"`
	ToType          int               `json:"toType"`
	CreatedTime     json.Number       `json:"createdTime"`
	ContentType     int               `json:"contentType"`
	ContentMetadata map[string]string `json:"contentMetadata"`

	Text string `json:"text,omitempty"`

	Chunks []string `json:"chunks,omitempty"`
}

type RSAKeyInfo struct {
	KeyName    string `json:"keynm"`
	NValue     string `json:"nvalue"`
	EValue     string `json:"evalue"`
	SessionKey string `json:"sessionKey"`
}

type LoginResult struct {
	AuthToken   string `json:"authToken"`
	Certificate string `json:"certificate"`
	Verifier    string `json:"verifier"`
	PinCode     string `json:"pinCode"`
	Pin         string `json:"-"` // Generated locally
	Type        int    `json:"type"`
	Param       string `json:"param"` // Sometimes used
	Message     string `json:"message"`
}

type LoginPollingResult struct {
	Result struct {
		Metadata struct {
			ErrorCode         string `json:"errorCode"`
			EncryptedKeyChain string `json:"encryptedKeyChain"`
			E2EEVersion       string `json:"e2eeVersion"`
			KeyID             string `json:"keyId"`
			PublicKey         string `json:"publicKey"`
			AuthToken         string `json:"authToken"`   // Sometimes here
			Certificate       string `json:"certificate"` // Sometimes here
			PinCode           string `json:"pinCode"`
		} `json:"metadata"`
	} `json:"result"`
	Timestamp string `json:"timestamp"`
	AuthPhase string `json:"authPhase"`
}
