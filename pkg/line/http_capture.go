package line

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var captureMu sync.Mutex

func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: newCaptureTransport(http.DefaultTransport),
	}
}

func newCaptureTransport(base http.RoundTripper) http.RoundTripper {
	path := os.Getenv("LINE_HTTP_CAPTURE_PATH")
	if path == "" {
		return base
	}
	if base == nil {
		base = http.DefaultTransport
	}
	return &captureTransport{base: base, path: path}
}

type captureTransport struct {
	base http.RoundTripper
	path string
}

type capturedHTTPRequest struct {
	Timestamp string      `json:"timestamp"`
	Method    string      `json:"method"`
	URL       string      `json:"url"`
	Path      string      `json:"path"`
	Headers   http.Header `json:"headers"`
	Body      any         `json:"body,omitempty"`
}

func (ct *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ct.capture(req)
	return ct.base.RoundTrip(req)
}

func (ct *captureTransport) capture(req *http.Request) {
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
	entry := capturedHTTPRequest{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Method:    req.Method,
		URL:       req.URL.String(),
		Path:      req.URL.Path,
		Headers:   sanitizeHeaders(req.Header),
		Body:      sanitizeBody(bodyBytes),
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	captureMu.Lock()
	defer captureMu.Unlock()
	f, err := os.OpenFile(ct.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}

func sanitizeHeaders(headers http.Header) http.Header {
	out := make(http.Header, len(headers))
	for key, values := range headers {
		lowerKey := strings.ToLower(key)
		if lowerKey == "authorization" || lowerKey == "cookie" || lowerKey == "x-line-access" || lowerKey == "x-hmac" {
			out[key] = []string{"<redacted>"}
			continue
		}
		out[key] = append([]string(nil), values...)
	}
	return out
}

func sanitizeBody(body []byte) any {
	if len(body) == 0 {
		return nil
	}
	var parsed any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return string(body)
	}
	return sanitizeJSON(parsed)
}

func sanitizeJSON(value any) any {
	switch typed := value.(type) {
	case []any:
		for idx, item := range typed {
			typed[idx] = sanitizeJSON(item)
		}
		return typed
	case map[string]any:
		for key, item := range typed {
			switch strings.ToLower(key) {
			case "accesstoken", "refreshtoken", "authtoken", "password", "secret", "certificate", "verifier", "authsessionid":
				if s, ok := item.(string); ok && s != "" {
					typed[key] = "<redacted>"
				}
			default:
				typed[key] = sanitizeJSON(item)
			}
		}
		return typed
	default:
		return value
	}
}
