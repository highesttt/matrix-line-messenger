package line

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type capturedRequest struct {
	method string
	path   string
	body   string
	header http.Header
}

type queuedResponse struct {
	status int
	body   string
}

type recordingTransport struct {
	t         *testing.T
	responses []queuedResponse
	requests  []capturedRequest
}

func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		rt.t.Fatalf("failed to read request body: %v", err)
	}
	if len(rt.responses) == 0 {
		rt.t.Fatalf("unexpected request to %s", req.URL.String())
	}
	resp := rt.responses[0]
	rt.responses = rt.responses[1:]
	rt.requests = append(rt.requests, capturedRequest{
		method: req.Method,
		path:   req.URL.Path,
		body:   string(body),
		header: req.Header.Clone(),
	})
	return &http.Response{
		StatusCode: resp.status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(resp.body)),
		Request:    req,
	}, nil
}

func TestGetLastE2EEPublicKeysParsesCapturedGroupShape(t *testing.T) {
	const publicKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	rt := &recordingTransport{
		t: t,
		responses: []queuedResponse{
			{status: 200, body: `{"code":0,"message":"OK","data":{"Upeer":{"version":1,"keyId":5808453,"keyData":"` + publicKey + `","createdTime":"1776353631192"}}}`},
		},
	}
	client := NewClient("access")
	client.HTTPClient = &http.Client{Transport: rt}

	keys, err := client.GetLastE2EEPublicKeys("Cgroup")
	if err != nil {
		t.Fatalf("GetLastE2EEPublicKeys returned error: %v", err)
	}
	key := keys["Upeer"]
	if key == nil {
		t.Fatal("missing Upeer key")
	}
	if key.PublicKey != publicKey || key.KeyID.String() != "5808453" {
		t.Fatalf("key = %#v", key)
	}
	if len(rt.requests) != 1 {
		t.Fatalf("recorded %d requests, want 1", len(rt.requests))
	}
	if rt.requests[0].path != "/api/talk/thrift/Talk/TalkService/getLastE2EEPublicKeys" || rt.requests[0].body != `["Cgroup"]` {
		t.Fatalf("request = %#v", rt.requests[0])
	}
}

func TestRegisterE2EEGroupKeyMatchesCapturedRequestShape(t *testing.T) {
	rt := &recordingTransport{
		t: t,
		responses: []queuedResponse{
			{status: 200, body: `{"code":0,"message":"OK","data":{"keyVersion":1,"groupKeyId":162718348,"creator":"Ume","creatorKeyId":5747884,"receiver":"Ume","receiverKeyId":5747884,"encryptedSharedKey":"wrapped-self","allowedTypes":[0,1,2,3,14,15],"specVersion":2}}`},
		},
	}
	client := NewClient("access")
	client.HTTPClient = &http.Client{Transport: rt}

	key, err := client.RegisterE2EEGroupKey(
		"Cgroup",
		[]string{"Upeer", "Ume"},
		[]int{5727582, 5747884},
		[]string{"wrapped-peer", "wrapped-self"},
	)
	if err != nil {
		t.Fatalf("RegisterE2EEGroupKey returned error: %v", err)
	}
	if key.GroupKeyID != 162718348 || key.Creator != "Ume" || key.EncryptedSharedKey != "wrapped-self" {
		t.Fatalf("key = %#v", key)
	}
	if len(rt.requests) != 1 {
		t.Fatalf("recorded %d requests, want 1", len(rt.requests))
	}
	if rt.requests[0].path != "/api/talk/thrift/Talk/TalkService/registerE2EEGroupKey" {
		t.Fatalf("path = %q", rt.requests[0].path)
	}
	wantBody := `[1,"Cgroup",["Upeer","Ume"],[5727582,5747884],["wrapped-peer","wrapped-self"]]`
	if rt.requests[0].body != wantBody {
		t.Fatalf("body = %q, want %q", rt.requests[0].body, wantBody)
	}
}

func TestGroupE2EEErrorClassificationSeparatesMismatchFromLSOFF(t *testing.T) {
	memberSettingsOff := errFromString(`API error 400: {"code":10051,"message":"RESPONSE_ERROR","data":{"name":"TalkException","code":98,"reason":"member settings off"}}`)
	if !IsNoUsableE2EEGroupKey(memberSettingsOff) {
		t.Fatal("code 98 was not classified as no usable group E2EE key")
	}
	if IsE2EEGroupKeyMismatch(memberSettingsOff) {
		t.Fatal("code 98 was classified as group key mismatch")
	}

	memberMismatch := errFromString(`API error 400: {"code":10051,"message":"RESPONSE_ERROR","data":{"name":"TalkException","code":99,"reason":"group key member mismatch"}}`)
	if !IsE2EEGroupKeyMismatch(memberMismatch) {
		t.Fatal("code 99 was not classified as group key mismatch")
	}
	if IsNoUsableE2EEGroupKey(memberMismatch) {
		t.Fatal("code 99 was classified as no usable group E2EE key")
	}
}

func TestParseE2EEPublicKeyRejectsMalformedFallbackData(t *testing.T) {
	_, err := parseE2EEPublicKey([]byte(`{"publicKey":{"keyId":5747884,"keyData":{"0":"0"}}}`))
	if err == nil {
		t.Fatal("parseE2EEPublicKey accepted malformed keyData")
	}
	if !IsNoUsableE2EEPublicKey(err) {
		t.Fatalf("error = %v, want no usable E2EE public key", err)
	}
}

type errFromString string

func (e errFromString) Error() string {
	return string(e)
}
