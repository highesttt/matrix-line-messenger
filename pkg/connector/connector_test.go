package connector

import "testing"

func TestUserLoginMetadataCopyFromReplacesMetadata(t *testing.T) {
	target := &UserLoginMetadata{
		AccessToken:   "old-access",
		RefreshToken:  "old-refresh",
		E2EEPublicKey: "old-public",
	}
	source := &UserLoginMetadata{
		AccessToken:    "new-access",
		RefreshToken:   "new-refresh",
		Mid:            "Unew",
		E2EEPublicKey:  "new-public",
		E2EEKeyID:      "5747884",
		ExportedKeyMap: map[string]string{"1": "secret"},
	}

	target.CopyFrom(source)

	if target.AccessToken != source.AccessToken ||
		target.RefreshToken != source.RefreshToken ||
		target.Mid != source.Mid ||
		target.E2EEPublicKey != source.E2EEPublicKey ||
		target.E2EEKeyID != source.E2EEKeyID ||
		target.ExportedKeyMap["1"] != "secret" {
		t.Fatalf("metadata was not copied: %#v", target)
	}
}
