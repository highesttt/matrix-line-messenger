package line

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrNoUsableE2EEPublicKey = errors.New("no usable E2EE public key")
	ErrNoUsableE2EEGroupKey  = errors.New("no usable E2EE group key")
)

type talkExceptionData struct {
	Name    string `json:"name"`
	Message string `json:"message"`
	Code    int    `json:"code"`
	Reason  string `json:"reason"`
}

type apiError struct {
	HTTPStatus int
	Code       int
	Message    string
	Talk       talkExceptionData
	RawBody    string

	kind error
}

func (e *apiError) Error() string {
	return fmt.Sprintf("API error %d: %s", e.HTTPStatus, e.RawBody)
}

func (e *apiError) Unwrap() error {
	return e.kind
}

func parseAPIError(status int, body []byte) error {
	apiErr := &apiError{
		HTTPStatus: status,
		RawBody:    string(body),
	}

	var wrapper struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return apiErr
	}

	apiErr.Code = wrapper.Code
	apiErr.Message = wrapper.Message
	apiErr.Talk = parseTalkExceptionData(wrapper.Data)
	if isNoUsableE2EEGroupKeyTalkException(wrapper.Message, apiErr.Talk) {
		apiErr.kind = ErrNoUsableE2EEGroupKey
	}

	return apiErr
}

func parseTalkExceptionData(raw json.RawMessage) talkExceptionData {
	var data talkExceptionData
	_ = json.Unmarshal(raw, &data)
	return data
}

func isNoUsableE2EEGroupKeyTalkException(message string, data talkExceptionData) bool {
	return strings.EqualFold(message, "RESPONSE_ERROR") &&
		strings.EqualFold(data.Name, "TalkException") &&
		data.Code == 5 &&
		strings.EqualFold(data.Reason, "not found")
}

func parseE2EEGroupKeyError(method, message string, rawData json.RawMessage) error {
	talk := parseTalkExceptionData(rawData)
	if isNoUsableE2EEGroupKeyTalkException(message, talk) {
		return fmt.Errorf("%w: %s", ErrNoUsableE2EEGroupKey, talk.Reason)
	}
	return fmt.Errorf("%s failed: %s", method, message)
}

func IsNoUsableE2EEPublicKey(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrNoUsableE2EEPublicKey) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "missing fields (pub=false keyID=-1") ||
		strings.Contains(msg, "missing fields (pub=false keyID=0") ||
		strings.Contains(msg, "\"allowedTypes\":[]") && strings.Contains(msg, "\"specVersion\":-1")
}

func IsNoUsableE2EEGroupKey(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrNoUsableE2EEGroupKey) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no group key found") ||
		strings.Contains(msg, "no group shared key returned")
}
