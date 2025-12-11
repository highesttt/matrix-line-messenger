package line

import "encoding/json"

type LoginRequest struct {
	Type             int    `json:"type"`
	IdentityProvider int    `json:"identityProvider"`
	Identifier       string `json:"identifier"` // Email
	Password         string `json:"password"`   // Hashded password?
	KeepLoggedIn     bool   `json:"keepLoggedIn"`
	AccessLocation   string `json:"accessLocation"`
	SystemName       string `json:"systemName"`
	Certificate      string `json:"certificate"`
	Verifier         string `json:"verifier"`
	Secret           string `json:"secret"`
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
