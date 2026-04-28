package connector

import (
	"testing"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
)

func TestPeerKeyFromLoginsUsesStoredE2EEPublicKey(t *testing.T) {
	const (
		peerMID = "Upeer"
		keyID   = 5747884
		pubKey  = "peer-public-key"
	)

	lc := &LineClient{}
	raw, pub, ok := lc.peerKeyFromLogins(peerMID, keyID, []*bridgev2.UserLogin{{
		UserLogin: &database.UserLogin{
			ID: networkid.UserLoginID(peerMID),
			Metadata: &UserLoginMetadata{
				E2EEPublicKey: pubKey,
				E2EEKeyID:     "5747884",
			},
		},
	}})
	if !ok {
		t.Fatal("peerKeyFromLogins did not find stored key")
	}
	if raw != keyID || pub != pubKey {
		t.Fatalf("peer key = (%d, %q), want (%d, %q)", raw, pub, keyID, pubKey)
	}
	if lc.peerKeys[peerMID].raw != keyID || lc.peerKeys[peerMID].pub != pubKey {
		t.Fatalf("cached peer key = %#v", lc.peerKeys[peerMID])
	}
}

func TestPeerKeyFromLoginsRejectsMismatchedKeyID(t *testing.T) {
	lc := &LineClient{}
	_, _, ok := lc.peerKeyFromLogins("Upeer", 1234, []*bridgev2.UserLogin{{
		UserLogin: &database.UserLogin{
			ID: networkid.UserLoginID("Upeer"),
			Metadata: &UserLoginMetadata{
				E2EEPublicKey: "peer-public-key",
				E2EEKeyID:     "5747884",
			},
		},
	}})
	if ok {
		t.Fatal("peerKeyFromLogins accepted a mismatched key ID")
	}
	if len(lc.peerKeys) != 0 {
		t.Fatalf("peer key cache was populated: %#v", lc.peerKeys)
	}
}

func TestParseKeyIDRejectsMalformedValues(t *testing.T) {
	if id, err := parseKeyID("5747884"); err != nil || id != 5747884 {
		t.Fatalf("parseKeyID valid value = (%d, %v)", id, err)
	}
	if _, err := parseKeyID("5747884extra"); err == nil {
		t.Fatal("parseKeyID accepted a partially numeric key ID")
	}
}
