package line

import (
	"errors"
	"strings"
)

var (
	ErrNoUsableE2EEPublicKey = errors.New("no usable E2EE public key")
	ErrNoUsableE2EEGroupKey  = errors.New("no usable E2EE group key")
)

// IsNoUsableE2EEPublicKey returns true when a peer has Letter Sealing disabled
// (negotiateE2EEPublicKey returns empty allowedTypes / specVersion -1, or no key data).
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
		(strings.Contains(msg, "\"allowedTypes\":[]") && strings.Contains(msg, "\"specVersion\":-1"))
}

// IsNoUsableE2EEGroupKey returns true when a group has no shared E2EE key
// (at least one member has Letter Sealing disabled).
func IsNoUsableE2EEGroupKey(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrNoUsableE2EEGroupKey) {
		return true
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "no group key found") ||
		strings.Contains(msg, "no group shared key returned") {
		return true
	}
	// Detect TalkException codes in raw API error strings (HTTP 400 with code 10051).
	// Code 5 "not found" = no group shared key; Code 98 = member has LS off;
	// Code 1 "Authentication Failed" from getE2EEGroupSharedKey also indicates no key access.
	if strings.Contains(msg, "\"code\":10051") && strings.Contains(msg, "talkexception") {
		if strings.Contains(msg, "\"code\":5") || strings.Contains(msg, "\"code\":98") || strings.Contains(msg, "\"code\":1") {
			return true
		}
	}
	return false
}
