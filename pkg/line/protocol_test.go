package line

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
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

func TestQRCodeLoginFlowMatchesCapturedV372Requests(t *testing.T) {
	const authSessionID = "SQtestsession"
	rt := &recordingTransport{
		t: t,
		responses: []queuedResponse{
			{status: 200, body: `{"code":0,"message":"OK","data":{"authSessionId":"` + authSessionID + `"}}`},
			{status: 200, body: `{"code":0,"message":"OK","data":{"callbackUrl":"https://line.me/R/au/lgn/sq/` + authSessionID + `","longPollingMaxCount":2,"longPollingIntervalSec":150}}`},
			{status: 200, body: `{"code":0,"message":"OK","data":{}}`},
			{status: 200, body: `{"code":0,"message":"OK","data":{"pinCode":"045566"}}`},
			{status: 200, body: `{"code":0,"message":"OK","data":{}}`},
			{status: 200, body: `{"code":0,"message":"OK","data":{"certificate":"cert","tokenV3IssueResult":{"accessToken":"access","refreshToken":"refresh","durationUntilRefreshInSec":"263522","loginSessionId":"session","tokenIssueTimeEpochSec":"1777269505"},"mid":"U123","lastBindTimestamp":"1534608800980","metaData":{"keyId":"5747884","errorCode":"SUCCESS","encryptedKeyChain":"encrypted","publicKey":"public","e2eeVersion":"1","hashKeyChain":"hash"}}}`},
		},
	}
	client := NewClient("")
	client.HTTPClient = &http.Client{Transport: rt}

	sessionID, err := client.CreateQRSession()
	if err != nil {
		t.Fatalf("CreateQRSession returned error: %v", err)
	}
	if sessionID != authSessionID {
		t.Fatalf("CreateQRSession = %q, want %q", sessionID, authSessionID)
	}

	qrCode, err := client.CreateQRCode(sessionID)
	if err != nil {
		t.Fatalf("CreateQRCode returned error: %v", err)
	}
	if qrCode.CallbackURL != "https://line.me/R/au/lgn/sq/"+authSessionID {
		t.Fatalf("CallbackURL = %q", qrCode.CallbackURL)
	}
	if qrCode.LongPollingMaxCount != 2 || qrCode.LongPollingIntervalSeconds != 150 {
		t.Fatalf("polling params = %#v", qrCode)
	}

	if err := client.CheckQRCodeVerified(sessionID); err != nil {
		t.Fatalf("CheckQRCodeVerified returned error: %v", err)
	}
	pin, err := client.CreatePinCode(sessionID)
	if err != nil {
		t.Fatalf("CreatePinCode returned error: %v", err)
	}
	if pin != "045566" {
		t.Fatalf("pin = %q", pin)
	}
	if err := client.CheckPinCodeVerified(sessionID); err != nil {
		t.Fatalf("CheckPinCodeVerified returned error: %v", err)
	}

	login, err := client.QRCodeLoginV2(sessionID)
	if err != nil {
		t.Fatalf("QRCodeLoginV2 returned error: %v", err)
	}
	if login.AuthToken != "access" || client.AccessToken != "access" {
		t.Fatalf("access token was not promoted from tokenV3IssueResult")
	}
	if login.LastPrimaryBindTime != "1534608800980" {
		t.Fatalf("LastPrimaryBindTime = %q", login.LastPrimaryBindTime)
	}
	if login.EncryptedKeyChain != "encrypted" || login.E2EEPublicKey != "public" || login.E2EEVersion != "1" || login.E2EEKeyID != "5747884" {
		t.Fatalf("E2EE metadata was not mapped: %#v", login)
	}

	expected := []capturedRequest{
		{method: "POST", path: "/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginService/createSession", body: "[{}]"},
		{method: "POST", path: "/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginService/createQrCode", body: `[{"authSessionId":"` + authSessionID + `"}]`},
		{method: "POST", path: "/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginPermitNoticeService/checkQrCodeVerified", body: `[{"authSessionId":"` + authSessionID + `"}]`},
		{method: "POST", path: "/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginService/createPinCode", body: `[{"authSessionId":"` + authSessionID + `"}]`},
		{method: "POST", path: "/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginPermitNoticeService/checkPinCodeVerified", body: `[{"authSessionId":"` + authSessionID + `"}]`},
		{method: "POST", path: "/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginService/qrCodeLoginV2", body: `[{"systemName":"CHROMEOS","modelName":"CHROME","autoLoginIsRequired":false,"authSessionId":"` + authSessionID + `"}]`},
	}
	if len(rt.requests) != len(expected) {
		t.Fatalf("recorded %d requests, want %d", len(rt.requests), len(expected))
	}
	for i, want := range expected {
		got := rt.requests[i]
		if got.method != want.method || got.path != want.path || got.body != want.body {
			t.Fatalf("request %d = %#v, want %#v", i, got, want)
		}
		if got.header.Get("x-line-application") != "" {
			t.Fatalf("request %d unexpectedly sent x-line-application", i)
		}
		if got.header.Get("x-line-chrome-version") != ExtensionVersion {
			t.Fatalf("request %d missing x-line-chrome-version", i)
		}
		if got.header.Get("x-hmac") == "" {
			t.Fatalf("request %d missing x-hmac", i)
		}
	}
	if rt.requests[2].header.Get("X-Line-Session-ID") != authSessionID || rt.requests[2].header.Get("X-LST") != "150000" {
		t.Fatalf("QR verification headers = %#v", rt.requests[2].header)
	}
	if rt.requests[4].header.Get("X-Line-Session-ID") != authSessionID || rt.requests[4].header.Get("X-LST") != "110000" {
		t.Fatalf("PIN verification headers = %#v", rt.requests[4].header)
	}
}

func TestQRCodeCallbackURLWithE2EESecretMatchesChromeShape(t *testing.T) {
	got, err := QRCodeCallbackURLWithE2EESecret(
		"https://line.me/R/au/lgn/sq/SQ123?existing=1",
		"abcd+/==",
	)
	if err != nil {
		t.Fatalf("QRCodeCallbackURLWithE2EESecret returned error: %v", err)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("failed to parse generated URL: %v", err)
	}
	if parsed.Scheme != "https" || parsed.Host != "line.me" || parsed.Path != "/R/au/lgn/sq/SQ123" {
		t.Fatalf("generated URL changed callback target: %s", got)
	}
	query := parsed.Query()
	if query.Get("existing") != "1" {
		t.Fatalf("existing query param was not preserved: %s", got)
	}
	if query.Get("secret") != "abcd+/==" {
		t.Fatalf("secret param = %q", query.Get("secret"))
	}
	if query.Get("e2eeVersion") != "1" {
		t.Fatalf("e2eeVersion param = %q", query.Get("e2eeVersion"))
	}
}

func TestVerifyCertificatePropagatesFreshLoginFailure(t *testing.T) {
	const authSessionID = "SQfresh"
	rt := &recordingTransport{
		t: t,
		responses: []queuedResponse{
			{status: 400, body: `{"code":10051,"message":"RESPONSE_ERROR","data":{"name":"SecondaryQrCodeException","code":2,"alertMessage":"The verification code you entered is incorrect."}}`},
		},
	}
	client := NewClient("")
	client.HTTPClient = &http.Client{Transport: rt}

	err := client.VerifyCertificate(authSessionID, "")
	if err == nil {
		t.Fatal("VerifyCertificate returned nil error for captured fresh-profile rejection")
	}
	if !strings.Contains(err.Error(), "SecondaryQrCodeException") {
		t.Fatalf("VerifyCertificate error = %q", err.Error())
	}
	if len(rt.requests) != 1 {
		t.Fatalf("recorded %d requests, want 1", len(rt.requests))
	}
	if rt.requests[0].path != "/api/talk/thrift/LoginQrCode/SecondaryQrCodeLoginService/verifyCertificate" {
		t.Fatalf("path = %q", rt.requests[0].path)
	}
	if rt.requests[0].body != `[{"authSessionId":"`+authSessionID+`","certificate":""}]` {
		t.Fatalf("body = %q", rt.requests[0].body)
	}
	if rt.requests[0].header.Get("x-line-application") != "" {
		t.Fatal("VerifyCertificate unexpectedly sent x-line-application")
	}
}

func TestEmailPasswordLoginWithCertificateSkipsPIN(t *testing.T) {
	certificate := strings.Repeat("a", 64)
	rt := &recordingTransport{
		t: t,
		responses: []queuedResponse{
			{status: 200, body: `{"code":0,"message":"OK","data":{"keynm":"15461","nvalue":"90ddd407a8c0d9c4c91e4b3c9ccb1fc83af3b677f517eb6e4e6b49e5556c6809dcdbfb0ee977044114aa52816cc3b4e7c64c21990904e6414ea1fcce8efbb2f4c32674a76f8d9ee1c856e16addf085d98f5c71026aa0a8f8e509a7361534be6581ae0ff81bca232077567d7f3de6279515e6419be01d1f23c138b17944703b5f312c8fc3d36ba9ef8fe49f0e31a8330be1def8a2aedf","evalue":"10001","sessionKey":"L|s60P6ipA97"}}`},
			{status: 200, body: `{"code":0,"message":"OK","data":{"type":1,"tokenV3IssueResult":{"accessToken":"access","refreshToken":"refresh"},"mid":"U123"}}`},
		},
	}
	client := NewClient("")
	client.HTTPClient = &http.Client{Transport: rt}

	res, err := client.Login("user@example.com", "password", certificate)
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if res.AuthToken != "access" {
		t.Fatalf("AuthToken = %q", res.AuthToken)
	}
	if len(rt.requests) != 2 {
		t.Fatalf("recorded %d requests, want 2", len(rt.requests))
	}
	if rt.requests[0].path != "/api/talk/thrift/Talk/TalkService/getRSAKeyInfo" || rt.requests[0].body != "[1]" {
		t.Fatalf("unexpected RSA request: %#v", rt.requests[0])
	}

	var loginBody []LoginRequest
	if err := json.Unmarshal([]byte(rt.requests[1].body), &loginBody); err != nil {
		t.Fatalf("failed to parse login body: %v", err)
	}
	if len(loginBody) != 1 {
		t.Fatalf("login body len = %d", len(loginBody))
	}
	req := loginBody[0]
	if req.Type != 0 {
		t.Fatalf("login type = %d, want 0", req.Type)
	}
	if req.Certificate != certificate {
		t.Fatalf("certificate = %q", req.Certificate)
	}
	if req.Secret != "" {
		t.Fatalf("secret = %q, want empty", req.Secret)
	}
}
