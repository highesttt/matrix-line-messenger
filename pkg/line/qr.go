package line

import (
	"fmt"
	"net/url"
)

func QRCodeCallbackURLWithE2EESecret(callbackURL, publicKeyBase64 string) (string, error) {
	parsed, err := url.Parse(callbackURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse QR callback URL: %w", err)
	}
	query := parsed.Query()
	query.Set("secret", publicKeyBase64)
	query.Set("e2eeVersion", "1")
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}
