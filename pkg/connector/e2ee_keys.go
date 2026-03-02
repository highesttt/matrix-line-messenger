package connector

import (
	"context"
	"fmt"

	"github.com/highesttt/matrix-line-messenger/pkg/e2ee"
	"github.com/highesttt/matrix-line-messenger/pkg/line"
)

// fetchAndUnwrapGroupKey retrieves a specific group key (or the latest when groupKeyID == 0)
// and unwraps it so the E2EE manager can encrypt/decrypt group messages.
func (lc *LineClient) fetchAndUnwrapGroupKey(ctx context.Context, chatMid string, groupKeyID int) error {
	if lc.E2EE == nil {
		return fmt.Errorf("E2EE manager not initialized")
	}

	client := line.NewClient(lc.AccessToken)
	fetch := func() (*line.E2EEGroupSharedKey, error) {
		if groupKeyID > 0 {
			return client.GetE2EEGroupSharedKey(chatMid, groupKeyID)
		}
		return client.GetLastE2EEGroupSharedKey(chatMid)
	}

	sharedKey, err := fetch()
	if err != nil && lc.isRefreshRequired(err) {
		if errRefresh := lc.refreshAndSave(ctx); errRefresh == nil {
			client = line.NewClient(lc.AccessToken)
			sharedKey, err = fetch()
		} else {
			return fmt.Errorf("failed to refresh token before fetching group key: %w", errRefresh)
		}
	}
	if err != nil {
		return err
	}
	if sharedKey == nil {
		return fmt.Errorf("no group shared key returned for %s", chatMid)
	}

	lc.UserLogin.Bridge.Log.Debug().
		Str("chat_mid", chatMid).
		Int("group_key_id", sharedKey.GroupKeyID).
		Int("creator_key_id", sharedKey.CreatorKeyID).
		Int("receiver_key_id", sharedKey.ReceiverKeyID).
		Msg("Fetched group shared key")

	if _, _, err := lc.ensurePeerKey(ctx, sharedKey.Creator); err != nil {
		return fmt.Errorf("failed to ensure creator key: %w", err)
	}
	if _, _, err := lc.ensurePeerKeyByID(ctx, sharedKey.Creator, sharedKey.CreatorKeyID); err != nil {
		return fmt.Errorf("failed to ensure creator key id %d: %w", sharedKey.CreatorKeyID, err)
	}

	unwrappedID, err := lc.E2EE.UnwrapGroupSharedKey(chatMid, sharedKey)
	if err != nil {
		return fmt.Errorf("failed to unwrap group key: %w", err)
	}

	lc.UserLogin.Bridge.Log.Debug().
		Str("chat_mid", chatMid).
		Int("group_key_id", sharedKey.GroupKeyID).
		Int("receiver_key_id", sharedKey.ReceiverKeyID).
		Int("unwrapped_id", unwrappedID).
		Msg("Unwrapped group shared key")

	return nil
}

func (lc *LineClient) ensurePeerKey(_ context.Context, mid string) (int, string, error) {
	if lc.peerKeys == nil {
		lc.peerKeys = make(map[string]peerKeyInfo)
	}
	if cached, ok := lc.peerKeys[mid]; ok && cached.raw != 0 && cached.pub != "" {
		if lc.E2EE != nil {
			lc.E2EE.RegisterPeerPublicKey(cached.raw, cached.pub)
		}
		return cached.raw, cached.pub, nil
	}
	client := line.NewClient(lc.AccessToken)
	res, err := client.NegotiateE2EEPublicKey(mid)
	if err != nil {
		return 0, "", err
	}
	keyID, err := res.KeyID.Int64()
	if err != nil {
		return 0, "", err
	}
	pk := peerKeyInfo{raw: int(keyID), pub: res.PublicKey}
	lc.peerKeys[mid] = pk
	if lc.E2EE != nil {
		lc.E2EE.RegisterPeerPublicKey(pk.raw, pk.pub)
	}
	return pk.raw, pk.pub, nil
}

func (lc *LineClient) ensurePeerKeyByID(_ context.Context, mid string, keyID int) (int, string, error) {
	if lc.peerKeys == nil {
		lc.peerKeys = make(map[string]peerKeyInfo)
	}
	if cached, ok := lc.peerKeys[mid]; ok && cached.raw == keyID && cached.pub != "" {
		if lc.E2EE != nil {
			lc.E2EE.RegisterPeerPublicKey(cached.raw, cached.pub)
		}
		return cached.raw, cached.pub, nil
	}

	client := line.NewClient(lc.AccessToken)
	// keyVersion 1
	res, err := client.GetE2EEPublicKey(mid, 1, keyID)
	if err != nil {
		return 0, "", err
	}

	resKeyID, err := res.KeyID.Int64()
	if err != nil {
		return 0, "", err
	}

	if int(resKeyID) != keyID {
		return 0, "", fmt.Errorf("fetched key ID %d does not match requested %d", resKeyID, keyID)
	}

	pk := peerKeyInfo{raw: int(resKeyID), pub: res.PublicKey}
	// Cache the fetched key so subsequent lookups reuse it.
	lc.peerKeys[mid] = pk
	if lc.E2EE != nil {
		lc.E2EE.RegisterPeerPublicKey(pk.raw, pk.pub)
	}
	return pk.raw, pk.pub, nil
}

func (lc *LineClient) ensurePeerKeyForMessage(ctx context.Context, msg *line.Message) {
	if lc.E2EE == nil || len(msg.Chunks) < 5 {
		return
	}
	senderKeyID, err1 := e2ee.DecodeKeyID(msg.Chunks[len(msg.Chunks)-2])
	receiverKeyID, err2 := e2ee.DecodeKeyID(msg.Chunks[len(msg.Chunks)-1])
	myRaw, _, errMy := lc.E2EE.MyKeyIDs()
	if err1 != nil || err2 != nil || errMy != nil {
		lc.UserLogin.Bridge.Log.Warn().AnErr("sender_err", err1).AnErr("receiver_err", err2).AnErr("my_key_err", errMy).Msg("Failed to extract key IDs for peer key fetch")
		return
	}
	peerRaw := senderKeyID
	peerMid := msg.From
	if senderKeyID == myRaw {
		peerRaw = receiverKeyID
		peerMid = msg.To
	}
	if peerRaw == 0 || peerRaw == myRaw {
		return
	}
	if lc.E2EE.HasPeerPublicKey(peerRaw) {
		return
	}
	lc.UserLogin.Bridge.Log.Debug().Int("peer_key_id", peerRaw).Str("peer_mid", peerMid).Msg("Fetching peer public key for decrypt")
	if _, _, err := lc.ensurePeerKeyByID(ctx, peerMid, peerRaw); err != nil {
		lc.UserLogin.Bridge.Log.Debug().Err(err).Int("key_id", peerRaw).Msg("ensurePeerKeyByID failed, trying NegotiateE2EEPublicKey")
		if _, _, err2 := lc.ensurePeerKey(ctx, peerMid); err2 != nil {
			lc.UserLogin.Bridge.Log.Warn().Err(err2).Str("peer", peerMid).Int("key_id", peerRaw).Msg("Failed to fetch peer key for decrypt")
		}
	}
}
