package secret

import (
	"fmt"

	gen "github.com/highesttt/mautrix-line-messenger/pkg"
)

type SecretResult struct {
	Secret       string `json:"secret"`
	Pin          string `json:"pin"`
	PublicKeyHex string `json:"publicKeyHex"`
}

// GenerateSecret performs the E2EE handshake logic using the WASM module via Node.js.
func GenerateSecret() (*SecretResult, error) {
	runner, err := gen.GetRunner()

	if err != nil {
		return nil, fmt.Errorf("failed to get runner: %w", err)
	}
	res, err := runner.GenerateE2EESecret()

	if err != nil {
		return nil, fmt.Errorf("failed to generate secret: %w", err)
	}

	return &SecretResult{
		Secret:       res.Secret,
		Pin:          res.Pin,
		PublicKeyHex: res.PublicKeyHex,
	}, nil

}
