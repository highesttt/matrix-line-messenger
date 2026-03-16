package line

import (
	"errors"
	"strings"
)

var (
	ErrNoUsableE2EEPublicKey = errors.New("no usable E2EE public key")
	ErrNoUsableE2EEGroupKey  = errors.New("no usable E2EE group key")
)

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
		strings.Contains(msg, "no group shared key returned") ||
		strings.Contains(msg, "getlaste2eegroupsharedkey failed: not found") ||
		strings.Contains(msg, "gete2eegroupsharedkey failed: not found") ||
		strings.Contains(msg, "talkexception code 5 reason \"not found\"")
}
