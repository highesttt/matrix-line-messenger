package connector

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	_ "image/gif"
	"image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	ffmpeg "github.com/u2takey/ffmpeg-go"
	"go.mau.fi/util/ptr"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/image/draw"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/simplevent"
	"maunium.net/go/mautrix/bridgev2/status"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/rs/zerolog"

	"github.com/highesttt/matrix-line-messenger/pkg/e2ee"
	"github.com/highesttt/matrix-line-messenger/pkg/line"
)

type LineClient struct {
	UserLogin    *bridgev2.UserLogin
	AccessToken  string
	RefreshToken string
	Mid          string
	HTTPClient   *http.Client
	E2EE         *e2ee.Manager
	peerKeys     map[string]peerKeyInfo

	reqSeqMu    sync.Mutex
	sentReqSeqs map[int]time.Time

	contactCache map[string]line.Contact
}

var _ bridgev2.NetworkAPI = (*LineClient)(nil)
var _ bridgev2.ReadReceiptHandlingNetworkAPI = (*LineClient)(nil)

func (lc *LineClient) refreshAndSave(ctx context.Context) error {
	if lc.RefreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	client := line.NewClient(lc.AccessToken)
	res, err := client.RefreshAccessToken(lc.RefreshToken)
	if err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	lc.AccessToken = res.AccessToken
	if res.RefreshToken != "" {
		lc.RefreshToken = res.RefreshToken
	}

	meta := lc.UserLogin.Metadata.(*UserLoginMetadata)
	meta.AccessToken = lc.AccessToken
	meta.RefreshToken = lc.RefreshToken
	err = lc.UserLogin.Save(ctx)
	if err != nil {
		lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to save refreshed tokens to DB")
	} else {
		lc.UserLogin.Bridge.Log.Info().Msg("Tokens refreshed and saved")
	}

	return nil
}

// AES-256-CTR
// LINE's E2EE file format: [encrypted_data][32-byte HMAC]
// The keyMaterial is derived using HKDF to get encKey (32), macKey (32), and nonce (12 bytes)
func (lc *LineClient) decryptImageData(encryptedData []byte, keyMaterialB64 string) ([]byte, error) {
	keyMaterial, err := base64.StdEncoding.DecodeString(keyMaterialB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key material: %w", err)
	}

	// Derive keys using HKDF (SHA-256, no salt, info="FileEncryption")
	// Derives 76 bytes: encKey(32) + macKey(32) + nonce(12)
	kdf := hkdf.New(sha256.New, keyMaterial, nil, []byte("FileEncryption"))
	derived := make([]byte, 76)
	if _, err := io.ReadFull(kdf, derived); err != nil {
		return nil, fmt.Errorf("failed to derive keys: %w", err)
	}

	encKey := derived[0:32]
	// macKey := derived[32:64] // for HMAC verification
	nonce := derived[64:76]

	// Create 16-byte counter: nonce(12 bytes) + zero counter(4 bytes)
	counter := make([]byte, 16)
	copy(counter, nonce)
	// Last 4 bytes remain zero

	if len(encryptedData) < 32 {
		return nil, fmt.Errorf("encrypted data too short (< 32 bytes for HMAC)")
	}
	encryptedData = encryptedData[:len(encryptedData)-32]

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	stream := cipher.NewCTR(block, counter)

	decrypted := make([]byte, len(encryptedData))
	stream.XORKeyStream(decrypted, encryptedData)

	return decrypted, nil
}

// AES-256-CTR
func (lc *LineClient) encryptFileData(plainData []byte) ([]byte, string, error) {
	keyMaterial := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, keyMaterial); err != nil {
		return nil, "", fmt.Errorf("failed to generate key material: %w", err)
	}

	// Derive keys using HKDF (SHA-256, no salt, info="FileEncryption")
	// Derives 76 bytes: encKey(32) + macKey(32) + nonce(12)
	kdf := hkdf.New(sha256.New, keyMaterial, nil, []byte("FileEncryption"))
	derived := make([]byte, 76)
	if _, err := io.ReadFull(kdf, derived); err != nil {
		return nil, "", fmt.Errorf("failed to derive keys: %w", err)
	}

	encKey := derived[0:32]
	macKey := derived[32:64]
	nonce := derived[64:76]

	// Create 16-byte counter: nonce(12 bytes) + zero counter(4 bytes)
	counter := make([]byte, 16)
	copy(counter, nonce)

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	stream := cipher.NewCTR(block, counter)

	encrypted := make([]byte, len(plainData))
	stream.XORKeyStream(encrypted, plainData)

	h := hmac.New(sha256.New, macKey)
	h.Write(encrypted)
	hmacSum := h.Sum(nil)

	// LINE E2EE file format: [encrypted_data][32-byte HMAC]
	result := append(encrypted, hmacSum...)

	keyMaterialB64 := base64.StdEncoding.EncodeToString(keyMaterial)

	return result, keyMaterialB64, nil
}

// encryptVideoData encrypts video data with HMAC computed on chunk hashes
func (lc *LineClient) encryptVideoData(plainData []byte) ([]byte, string, error) {
	keyMaterial := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, keyMaterial); err != nil {
		return nil, "", fmt.Errorf("failed to generate key material: %w", err)
	}

	kdf := hkdf.New(sha256.New, keyMaterial, nil, []byte("FileEncryption"))
	derived := make([]byte, 76)
	if _, err := io.ReadFull(kdf, derived); err != nil {
		return nil, "", fmt.Errorf("failed to derive keys: %w", err)
	}

	encKey := derived[0:32]
	macKey := derived[32:64]
	nonce := derived[64:76]

	counter := make([]byte, 16)
	copy(counter, nonce)

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	stream := cipher.NewCTR(block, counter)

	encrypted := make([]byte, len(plainData))
	stream.XORKeyStream(encrypted, plainData)

	// For videos: compute HMAC on chunk hashes
	chunkHashes := generateChunkHashes(encrypted)
	h := hmac.New(sha256.New, macKey)
	h.Write(chunkHashes)
	hmacSum := h.Sum(nil)

	result := append(encrypted, hmacSum...)
	keyMaterialB64 := base64.StdEncoding.EncodeToString(keyMaterial)

	return result, keyMaterialB64, nil
}

func generateThumbnail(imageData []byte) ([]byte, int, int, error) {
	img, _, err := image.Decode(bytes.NewReader(imageData))
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to decode image: %w", err)
	}

	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	maxDim := 1280
	newWidth := width
	newHeight := height

	if width > maxDim || height > maxDim {
		if width > height {
			newWidth = maxDim
			newHeight = (height * maxDim) / width
		} else {
			newHeight = maxDim
			newWidth = (width * maxDim) / height
		}
	}

	var thumbnail image.Image
	if newWidth != width || newHeight != height {
		thumbnail = image.NewRGBA(image.Rect(0, 0, newWidth, newHeight))
		draw.CatmullRom.Scale(thumbnail.(draw.Image), thumbnail.Bounds(), img, bounds, draw.Over, nil)
	} else {
		thumbnail = img
	}

	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, thumbnail, &jpeg.Options{Quality: 60}); err != nil {
		return nil, 0, 0, fmt.Errorf("failed to encode thumbnail: %w", err)
	}

	return buf.Bytes(), newWidth, newHeight, nil
}

func isAnimatedGif(data []byte) bool {
	// GIF header: "GIF89a" or "GIF87a"
	if len(data) < 6 {
		return false
	}

	if string(data[0:3]) != "GIF" {
		return false
	}

	// Count image descriptors (0x2C) which indicate frames
	frameCount := 0
	for i := 0; i < len(data)-1; i++ {
		if data[i] == 0x2C { // Image descriptor separator
			frameCount++
			if frameCount > 1 {
				return true
			}
		}
	}

	return false
}

// generates the first frame of a video and resizes it to fit within 384x384
func extractVideoThumbnail(videoData []byte) ([]byte, int, int, error) {
	tmpVideoFile, err := os.CreateTemp("", "video-*.mp4")
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to create temp video file: %w", err)
	}
	defer os.Remove(tmpVideoFile.Name())
	defer tmpVideoFile.Close()

	if _, err := tmpVideoFile.Write(videoData); err != nil {
		return nil, 0, 0, fmt.Errorf("failed to write video data: %w", err)
	}
	tmpVideoFile.Close()

	tmpThumbFile, err := os.CreateTemp("", "thumb-*.jpg")
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to create temp thumb file: %w", err)
	}
	defer os.Remove(tmpThumbFile.Name())
	tmpThumbFile.Close()

	err = ffmpeg.Input(tmpVideoFile.Name()).
		Filter("scale", ffmpeg.Args{"384:384:force_original_aspect_ratio=decrease"}).
		Output(tmpThumbFile.Name(), ffmpeg.KwArgs{
			"vframes": 1,
			"q:v":     5,
		}).
		OverWriteOutput().
		Silent(true).
		Run()

	if err != nil {
		return nil, 0, 0, fmt.Errorf("ffmpeg failed: %w", err)
	}

	thumbData, err := os.ReadFile(tmpThumbFile.Name())
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to read thumbnail: %w", err)
	}

	img, _, err := image.Decode(bytes.NewReader(thumbData))
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to decode thumbnail: %w", err)
	}

	bounds := img.Bounds()
	return thumbData, bounds.Dx(), bounds.Dy(), nil
}

// generateChunkHashes generates SHA-256 hashes for 128KB chunks of encrypted video data
// This is required by LINE for video integrity verification
func generateChunkHashes(encryptedData []byte) []byte {
	const chunkSize = 131072 // 128KB chunks
	var allHashes []byte

	for i := 0; i < len(encryptedData); i += chunkSize {
		end := i + chunkSize
		if end > len(encryptedData) {
			end = len(encryptedData)
		}

		chunk := encryptedData[i:end]
		hash := sha256.Sum256(chunk)
		allHashes = append(allHashes, hash[:]...)
	}

	return allHashes
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (lc *LineClient) isRefreshRequired(err error) bool {
	return strings.Contains(err.Error(), "\"code\":119") || strings.Contains(err.Error(), "Access token refresh required")
}

func (lc *LineClient) Connect(ctx context.Context) {
	if lc.peerKeys == nil {
		lc.peerKeys = make(map[string]peerKeyInfo)
	}
	if lc.contactCache == nil {
		lc.contactCache = make(map[string]line.Contact)
	}
	lc.reqSeqMu.Lock()
	if lc.sentReqSeqs == nil {
		lc.sentReqSeqs = make(map[int]time.Time)
	}
	lc.reqSeqMu.Unlock()

	if lc.Mid == "" {
		if meta, ok := lc.UserLogin.Metadata.(*UserLoginMetadata); ok {
			lc.Mid = meta.Mid
		}
	}
	if lc.AccessToken == "" {
		var email, password string
		if meta, ok := lc.UserLogin.Metadata.(*UserLoginMetadata); ok {
			email = meta.Email
			password = meta.Password
		}

		if email != "" && password != "" {
			lc.UserLogin.Bridge.Log.Info().Str("email", email).Msg("Attempting to login with email/password...")
			client := line.NewClient("")
			res, err := client.Login(email, password)
			if err != nil {
				lc.UserLogin.BridgeState.Send(status.BridgeState{
					StateEvent: status.StateBadCredentials,
					Error:      "line-login-failed",
					Message:    fmt.Sprintf("login failed: %v", err),
				})
				return
			}
			if res.AuthToken == "" {
				lc.UserLogin.BridgeState.Send(status.BridgeState{
					StateEvent: status.StateBadCredentials,
					Error:      "line-login-interaction-required",
					Message:    "Login requires interaction (PIN code), cannot perform in background.",
				})
				return
			}
			lc.AccessToken = client.AccessToken
			if res.Mid != "" {
				lc.Mid = res.Mid
				if meta, ok := lc.UserLogin.Metadata.(*UserLoginMetadata); ok {
					meta.Mid = res.Mid
				}
			}
			lc.UserLogin.Bridge.Log.Info().Msg("Login successful!")
		} else {
			lc.UserLogin.BridgeState.Send(status.BridgeState{
				StateEvent: status.StateBadCredentials,
				Error:      "line-missing-token",
				Message:    "access token missing and no credentials provided",
			})
			return
		}
	}

	lc.UserLogin.Bridge.Log.Info().Int("token_len", len(lc.AccessToken)).Msg("LINE client connected; notifying bridge")
	lc.UserLogin.BridgeState.Send(status.BridgeState{
		StateEvent: status.StateConnected,
	})

	// Initialize E2EE manager and load keys
	mgr, err := e2ee.NewManager()
	if err != nil {
		lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to init E2EE manager")
	} else {
		lc.E2EE = mgr
		if meta, ok := lc.UserLogin.Metadata.(*UserLoginMetadata); ok && len(meta.ExportedKeyMap) > 0 {
			if err := mgr.LoadMyKeyFromExportedMap(meta.ExportedKeyMap); err != nil {
				lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to load E2EE key from DB metadata")
			} else {
				lc.UserLogin.Bridge.Log.Info().Int("exported_keys", len(meta.ExportedKeyMap)).Msg("Loaded E2EE key from DB metadata")
			}
		}

		// Storage key is optional for runtime decrypt/encrypt; try it for file support
		client := line.NewClient(lc.AccessToken)
		ei3, err := client.GetEncryptedIdentityV3()
		if err != nil && lc.isRefreshRequired(err) {
			lc.UserLogin.Bridge.Log.Info().Msg("Access token expired, refreshing...")
			if errRefresh := lc.refreshAndSave(ctx); errRefresh == nil {
				client = line.NewClient(lc.AccessToken)
				ei3, err = client.GetEncryptedIdentityV3()
			} else {
				lc.UserLogin.Bridge.Log.Error().Err(errRefresh).Msg("Failed to refresh token")
			}
		}

		if err == nil {
			if err := mgr.InitStorage(ei3.WrappedNonce, ei3.KDFParameter1, ei3.KDFParameter2); err != nil {
				lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to init storage key")
			} else if data, err := mgr.LoadSecureDataFromFile(string(lc.UserLogin.ID)); err == nil {
				if err := mgr.LoadMyKeyFromSecureData(data); err != nil {
					lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to load E2EE key from secure data")
				}
			}
		} else {
			lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to fetch EncryptedIdentityV3")
		}
	}

	go lc.syncChats(ctx)
	go lc.pollLoop(ctx)
}

func (lc *LineClient) syncChats(ctx context.Context) {
	client := line.NewClient(lc.AccessToken)
	midsResp, err := client.GetAllChatMids(true, true)
	if err != nil && lc.isRefreshRequired(err) {
		if errRefresh := lc.refreshAndSave(ctx); errRefresh == nil {
			client = line.NewClient(lc.AccessToken)
			midsResp, err = client.GetAllChatMids(true, true)
		}
	}
	if err != nil {
		lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to fetch all chat mids")
		return
	}

	allMids := append(midsResp.MemberChatMids, midsResp.InvitedChatMids...)
	if len(allMids) == 0 {
		return
	}

	chunkSize := 20
	for i := 0; i < len(allMids); i += chunkSize {
		end := i + chunkSize
		if end > len(allMids) {
			end = len(allMids)
		}
		batch := allMids[i:end]
		chatsResp, err := client.GetChats(batch, true, true)
		if err != nil && lc.isRefreshRequired(err) {
			if errRefresh := lc.refreshAndSave(ctx); errRefresh == nil {
				client = line.NewClient(lc.AccessToken)
				chatsResp, err = client.GetChats(batch, true, true)
			}
		}
		if err != nil {
			lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to fetch batch of chats")
			continue
		}

		for _, chat := range chatsResp.Chats {
			portalKey := networkid.PortalKey{ID: makePortalID(chat.ChatMid), Receiver: lc.UserLogin.ID}

			info := lc.chatToChatInfo(&chat)
			lc.UserLogin.Bridge.QueueRemoteEvent(lc.UserLogin, &simplevent.ChatResync{
				EventMeta: simplevent.EventMeta{
					Type:      bridgev2.RemoteEventChatResync,
					PortalKey: portalKey,
					Timestamp: time.Now(),
				},
				ChatInfo: info,
			})
		}
	}
}

func (lc *LineClient) chatToChatInfo(chat *line.Chat) *bridgev2.ChatInfo {
	var avatar *bridgev2.Avatar
	if chat.PicturePath != "" {
		avatar = &bridgev2.Avatar{
			ID: networkid.AvatarID(chat.PicturePath),
			Get: func(ctx context.Context) ([]byte, error) {
				return lc.GetAvatar(ctx, networkid.AvatarID(chat.PicturePath))
			},
		}
	}

	members := []bridgev2.ChatMember{
		{
			EventSender: bridgev2.EventSender{
				IsFromMe: true,
				Sender:   networkid.UserID(lc.UserLogin.ID),
			},
			Membership: event.MembershipJoin,
			PowerLevel: ptr.Ptr(0),
		},
	}

	if chat.Extra.GroupExtra != nil {
		if chat.Extra.GroupExtra.CreatorMid == lc.Mid {
			members[0].PowerLevel = ptr.Ptr(100)
		}
		for m := range chat.Extra.GroupExtra.MemberMids {
			if m == lc.Mid || m == string(lc.UserLogin.ID) {
				continue
			}
			members = append(members, bridgev2.ChatMember{
				EventSender: bridgev2.EventSender{
					Sender: makeUserID(m),
				},
				Membership: event.MembershipJoin,
			})
		}
		for m := range chat.Extra.GroupExtra.InviteeMids {
			if m == lc.Mid || m == string(lc.UserLogin.ID) {
				continue
			}
			members = append(members, bridgev2.ChatMember{
				EventSender: bridgev2.EventSender{
					Sender: makeUserID(m),
				},
				Membership: event.MembershipInvite,
			})
		}
	}

	name := chat.ChatName
	if name == "" && chat.Extra.GroupExtra != nil {
		name = lc.generateNameFromMembers(chat.Extra.GroupExtra.MemberMids)
	}

	return &bridgev2.ChatInfo{
		Name:    &name,
		Avatar:  avatar,
		Members: &bridgev2.ChatMemberList{IsFull: true, Members: members},
	}
}

func (lc *LineClient) generateNameFromMembers(members map[string]bool) string {
	var names []string
	count := 0
	for mid := range members {
		if mid == string(lc.UserLogin.ID) || mid == lc.Mid || strings.HasPrefix(mid, "c") || strings.HasPrefix(mid, "r") {
			continue
		}
		if contact, ok := lc.contactCache[mid]; ok && contact.DisplayName != "" {
			names = append(names, contact.DisplayName)
		}
		count++
		if count >= 20 {
			break
		}
	}

	finalNames := names
	if len(names) > 3 {
		finalNames = names[:3]
	}

	if len(finalNames) == 0 {
		return ""
	}

	result := strings.Join(finalNames, ", ")
	actualMemberCount := 0
	for m := range members {
		if m != string(lc.UserLogin.ID) && m != lc.Mid && !strings.HasPrefix(m, "c") && !strings.HasPrefix(m, "r") {
			actualMemberCount++
		}
	}
	remaining := actualMemberCount - len(finalNames)
	if remaining > 0 {
		result += fmt.Sprintf(" and %d others", remaining)
	}
	return result
}

func (lc *LineClient) pollLoop(ctx context.Context) {
	var localRev int64 = 0
	client := line.NewClient(lc.AccessToken)

	lc.UserLogin.Bridge.Log.Info().Msg("Starting LINE SSE loop...")

	handler := func(eventType, data string) {
		// handle keep alives
		if eventType == "ping" || eventType == "connInfoRevision" {
			return
		}

		// handle fullsync requests
		if eventType == "fullSync" {
			lc.UserLogin.Bridge.Log.Info().Msg("Received fullSync request")

			var fsPayload struct {
				NextRevision string `json:"nextRevision"`
			}
			if err := json.Unmarshal([]byte(data), &fsPayload); err == nil && fsPayload.NextRevision != "" {
				if newRev, err := strconv.ParseInt(fsPayload.NextRevision, 10, 64); err == nil {
					lc.UserLogin.Bridge.Log.Info().Int64("old", localRev).Int64("new", newRev).Msg("Updating local revision from fullSync")

					localRev = newRev

				}
			}
			return
		}

		// handle operations
		if eventType == "operation" {
			var op line.Operation
			if err := json.Unmarshal([]byte(data), &op); err != nil {
				lc.UserLogin.Bridge.Log.Error().Err(err).Msg("Failed to unmarshal op")
				return
			}

			rev, _ := op.Revision.Int64()
			if rev > localRev {
				localRev = rev
			}

			lc.handleOperation(ctx, op)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
			err := client.ListenSSE(localRev, handler)
			if err != nil {
				if err.Error() != "EOF" {
					lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("SSE Disconnected")
					if strings.Contains(err.Error(), "SSE error: 401") || strings.Contains(err.Error(), "SSE error: 403") {
						if errRefresh := lc.refreshAndSave(ctx); errRefresh == nil {
							client = line.NewClient(lc.AccessToken)
						}
					}
				}
				time.Sleep(3 * time.Second)
			}
		}
	}
}

func (lc *LineClient) handleOperation(_ context.Context, op line.Operation) {
	// Type 25 = SEND_MESSAGE (Message sent by you from another device)
	// Type 26 = RECEIVE_MESSAGE (Message received from another user)

	if op.Type == 122 || op.Type == 121 {
		lc.UserLogin.Bridge.Log.Info().Str("chat_mid", op.Param1).Int("op_type", op.Type).Msg("Received chat update operation")
		go lc.syncSingleChat(context.Background(), op.Param1)
	}

	if op.Type == 55 {
		portalID := makePortalID(op.Param1)
		senderID := makeUserID(op.Param2)
		// Param 1 is the group id or sender id in 1:1 chats
		// Param 2 is the user who read the message

		ts, _ := op.CreatedTime.Int64()
		lc.UserLogin.Bridge.QueueRemoteEvent(lc.UserLogin, &simplevent.Receipt{
			EventMeta: simplevent.EventMeta{
				Type: bridgev2.RemoteEventReadReceipt,
				PortalKey: networkid.PortalKey{
					ID:       portalID,
					Receiver: lc.UserLogin.ID,
				},
				Timestamp: time.UnixMilli(ts),
				Sender:    bridgev2.EventSender{Sender: senderID},
			},
			ReadUpTo: time.UnixMilli(ts),
		})
	}

	if op.Type == 25 {
		lc.reqSeqMu.Lock()
		_, ok := lc.sentReqSeqs[op.ReqSeq]
		if ok {
			delete(lc.sentReqSeqs, op.ReqSeq)
			lc.reqSeqMu.Unlock()
			return
		}
		lc.reqSeqMu.Unlock()
	}

	if (op.Type == 25 || op.Type == 26) && op.Message != nil {
		lc.queueIncomingMessage(op.Message, op.Type)
	}
}

func (lc *LineClient) syncSingleChat(ctx context.Context, chatMid string) {
	client := line.NewClient(lc.AccessToken)
	chatsResp, err := client.GetChats([]string{chatMid}, true, true)
	if err != nil && lc.isRefreshRequired(err) {
		if errRefresh := lc.refreshAndSave(ctx); errRefresh == nil {
			client = line.NewClient(lc.AccessToken)
			chatsResp, err = client.GetChats([]string{chatMid}, true, true)
		}
	}
	if err != nil {
		lc.UserLogin.Bridge.Log.Warn().Err(err).Str("chat_mid", chatMid).Msg("Failed to fetch chat info")
		return
	}
	if len(chatsResp.Chats) == 0 {
		return
	}
	chat := chatsResp.Chats[0]
	portalKey := networkid.PortalKey{ID: makePortalID(chat.ChatMid), Receiver: lc.UserLogin.ID}

	if chat.ChatName == "" && chat.Extra.GroupExtra != nil {
		var missingMids []string
		for mid := range chat.Extra.GroupExtra.MemberMids {
			if _, ok := lc.contactCache[mid]; !ok && mid != string(lc.UserLogin.ID) {
				missingMids = append(missingMids, mid)
			}
		}
		if len(missingMids) > 0 {
			res, err := client.GetContactsV2(missingMids)
			if err == nil && res != nil && res.Contacts != nil {
				for mid, wrapper := range res.Contacts {
					lc.contactCache[mid] = wrapper.Contact
				}
			}
		}
	}

	info := lc.chatToChatInfo(&chat)
	lc.UserLogin.Bridge.QueueRemoteEvent(lc.UserLogin, &simplevent.ChatResync{
		EventMeta: simplevent.EventMeta{
			Type:      bridgev2.RemoteEventChatResync,
			PortalKey: portalKey,
			Timestamp: time.Now(),
		},
		ChatInfo: info,
	})
}

func (lc *LineClient) queueIncomingMessage(msg *line.Message, opType int) {
	senderID := makeUserID(msg.From)

	portalIDStr := msg.From
	// If I sent it (Type 25), the portal is the recipient (msg.To)
	if opType == 25 {
		portalIDStr = msg.To
	}
	// If it's a group (ToType 1 or 2), the portal is msg.To?
	if msg.ToType == 1 || msg.ToType == 2 {
		portalIDStr = msg.To
	}

	portalKey := networkid.PortalKey{ID: makePortalID(portalIDStr), Receiver: lc.UserLogin.ID}

	// Handle Content
	bodyText := msg.Text
	if bodyText == "" && len(msg.Chunks) > 0 {
		bodyText = "[Unable to decrypt message. Open an issue on GitHub.]"
		if lc.E2EE != nil {
			// Ensure peer keys are available before attempting decryption
			lc.ensurePeerKeyForMessage(context.Background(), msg)

			if msg.ToType == 1 || msg.ToType == 2 {
				// Group Decryption
				if len(msg.Chunks) >= 5 {
					if gkID, err := e2ee.DecodeKeyID(msg.Chunks[len(msg.Chunks)-1]); err == nil && gkID != 0 {
						if errFetch := lc.fetchAndUnwrapGroupKey(context.Background(), portalIDStr, gkID); errFetch != nil {
							lc.UserLogin.Bridge.Log.Debug().Err(errFetch).Int("key_id", gkID).Str("chat_mid", portalIDStr).Msg("Prefetch group key before decrypt failed")
						}
					}
				}
				pt, keyID, err := lc.E2EE.DecryptGroupMessage(msg, portalIDStr)
				if err == nil {
					bodyText = pt
				} else {
					lc.UserLogin.Bridge.Log.Debug().Err(err).Int("key_id", keyID).Str("chat_mid", portalIDStr).Msg("DecryptGroupMessage failed, trying to fetch key")
					if keyID != 0 {
						if errFetch := lc.fetchAndUnwrapGroupKey(context.Background(), portalIDStr, keyID); errFetch != nil {
							lc.UserLogin.Bridge.Log.Warn().Err(errFetch).Int("key_id", keyID).Str("chat_mid", portalIDStr).Msg("Failed to fetch/unwrap group key")
						} else if ptRetry, _, errRetry := lc.E2EE.DecryptGroupMessage(msg, portalIDStr); errRetry == nil {
							bodyText = ptRetry
						}
					}
				}
			} else {
				// 1-1 Decryption
				if pt, err := lc.E2EE.DecryptMessageV2(msg); err == nil {
					bodyText = pt
				} else {
					lc.UserLogin.Bridge.Log.Debug().Err(err).Msg("DecryptMessageV2 failed on first attempt")
					if ptRetry, errRetry := lc.E2EE.DecryptMessageV2(msg); errRetry == nil {
						bodyText = ptRetry
					} else {
						lc.UserLogin.Bridge.Log.Warn().Err(errRetry).Msg("DecryptMessageV2 failed on retry")
					}
				}
			}
		}
	}

	// unwrap JSON payloaad
	unwrappedText := bodyText
	if strings.HasPrefix(bodyText, "{") {
		var wrapper map[string]any
		if err := json.Unmarshal([]byte(bodyText), &wrapper); err == nil {
			if t, ok := wrapper["text"].(string); ok {
				unwrappedText = t
			}
		}
	}
	decryptedBody := bodyText

	lc.UserLogin.Bridge.QueueRemoteEvent(lc.UserLogin, &simplevent.Message[line.Message]{
		EventMeta: simplevent.EventMeta{
			Type:         bridgev2.RemoteEventMessage,
			LogContext:   func(c zerolog.Context) zerolog.Context { return c.Str("msg_id", msg.ID) },
			PortalKey:    portalKey,
			CreatePortal: true,
			Sender:       bridgev2.EventSender{Sender: senderID, IsFromMe: opType == 25},
			Timestamp:    time.Now(),
		},
		Data: *msg,
		ID:   networkid.MessageID(msg.ID),
		ConvertMessageFunc: func(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, data line.Message) (*bridgev2.ConvertedMessage, error) {
			replyRelatesTo := lc.resolveReplyRelatesTo(ctx, &data)
			// Handle Images
			if data.ContentType == 1 { // Image
				oid := data.ContentMetadata["OID"]

				if oid != "" {
					client := line.NewClient(lc.AccessToken)
					imgData, err := client.DownloadOBS(oid, data.ID)

					// Refresh token if we get a 401
					if err != nil && (strings.Contains(err.Error(), "401") || lc.isRefreshRequired(err)) {
						if errRefresh := lc.refreshAndSave(ctx); errRefresh == nil {
							client = line.NewClient(lc.AccessToken)
							imgData, err = client.DownloadOBS(oid, data.ID)
						} else {
							lc.UserLogin.Bridge.Log.Warn().Err(errRefresh).Msg("Failed to refresh token for OBS download")
						}
					}

					if err != nil {
						lc.UserLogin.Bridge.Log.Error().
							Err(err).
							Str("oid", oid).
							Str("msg_id", data.ID).
							Msg("Failed to download image from OBS")
						return nil, fmt.Errorf("failed to download image from OBS: %w", err)
					}

					// Decrypt image if it has keyMaterial (E2EE)
					if decryptedBody != "" && strings.Contains(decryptedBody, "keyMaterial") {
						var decryptInfo struct {
							KeyMaterial string `json:"keyMaterial"`
							FileName    string `json:"fileName"`
						}
						if err := json.Unmarshal([]byte(decryptedBody), &decryptInfo); err == nil && decryptInfo.KeyMaterial != "" {
							decryptedImg, err := lc.decryptImageData(imgData, decryptInfo.KeyMaterial)
							if err != nil {
								lc.UserLogin.Bridge.Log.Error().
									Err(err).
									Msg("Failed to decrypt image data")
								return nil, fmt.Errorf("failed to decrypt image data: %w", err)
							}
							imgData = decryptedImg
						}
					}

					// Upload to Matrix
					mxc, file, err := intent.UploadMedia(ctx, portal.MXID, imgData, "image.jpg", "image/jpeg")
					if err != nil {
						lc.UserLogin.Bridge.Log.Error().
							Err(err).
							Int("size_bytes", len(imgData)).
							Msg("Failed to upload image to Matrix")
						return nil, fmt.Errorf("failed to upload image to matrix: %w", err)
					}

					return &bridgev2.ConvertedMessage{
						Parts: []*bridgev2.ConvertedMessagePart{
							{
								Type: event.EventMessage,
								Content: &event.MessageEventContent{
									MsgType:   event.MsgImage,
									Body:      "image.jpg",
									URL:       mxc,
									File:      file,
									RelatesTo: replyRelatesTo,
								},
							},
						},
					}, nil
				}
			}

			if data.ContentType == 2 { // Video
				oid := data.ContentMetadata["OID"]

				if oid == "" && decryptedBody != "" && strings.Contains(decryptedBody, "OID") {
					var decryptInfo struct {
						OID         string `json:"OID"`
						KeyMaterial string `json:"keyMaterial"`
						FileName    string `json:"fileName"`
					}
					if err := json.Unmarshal([]byte(decryptedBody), &decryptInfo); err == nil && decryptInfo.OID != "" {
						oid = decryptInfo.OID
					}
				}

				if oid != "" {
					client := line.NewClient(lc.AccessToken)
					videoData, err := client.DownloadOBSWithSID(oid, data.ID, "emv")

					if err != nil && (strings.Contains(err.Error(), "401") || lc.isRefreshRequired(err)) {
						if errRefresh := lc.refreshAndSave(ctx); errRefresh == nil {
							client = line.NewClient(lc.AccessToken)
							videoData, err = client.DownloadOBSWithSID(oid, data.ID, "emv")
						} else {
							lc.UserLogin.Bridge.Log.Warn().Err(errRefresh).Msg("Failed to refresh token for OBS download")
						}
					}

					if err != nil {
						lc.UserLogin.Bridge.Log.Error().
							Err(err).
							Str("oid", oid).
							Str("msg_id", data.ID).
							Msg("Failed to download video from OBS")
						return nil, fmt.Errorf("failed to download video from OBS: %w", err)
					}

					if decryptedBody != "" && strings.Contains(decryptedBody, "keyMaterial") {
						var decryptInfo struct {
							KeyMaterial string `json:"keyMaterial"`
							FileName    string `json:"fileName"`
						}
						if err := json.Unmarshal([]byte(decryptedBody), &decryptInfo); err == nil && decryptInfo.KeyMaterial != "" {
							lc.UserLogin.Bridge.Log.Debug().
								Str("key_material_len", fmt.Sprintf("%d", len(decryptInfo.KeyMaterial))).
								Str("file_name", decryptInfo.FileName).
								Msg("Decrypting E2EE video")

							decryptedVideo, err := lc.decryptImageData(videoData, decryptInfo.KeyMaterial)
							if err != nil {
								lc.UserLogin.Bridge.Log.Error().
									Err(err).
									Msg("Failed to decrypt video data")
								return nil, fmt.Errorf("failed to decrypt video data: %w", err)
							}
							videoData = decryptedVideo
							lc.UserLogin.Bridge.Log.Info().
								Int("decrypted_size", len(videoData)).
								Msg("Successfully decrypted video")
						}
					}

					if encKM := data.ContentMetadata["ENC_KM"]; encKM != "" && len(videoData) > 32 {
						lc.UserLogin.Bridge.Log.Debug().
							Str("enc_km_preview", encKM[:min(20, len(encKM))]+"...").
							Msg("Decrypting video using ENC_KM from metadata")

						decryptedVideo, err := lc.decryptImageData(videoData, encKM)
						if err != nil {
							lc.UserLogin.Bridge.Log.Error().
								Err(err).
								Msg("Failed to decrypt video data from ENC_KM")
							return nil, fmt.Errorf("failed to decrypt video data: %w", err)
						}
						videoData = decryptedVideo
						lc.UserLogin.Bridge.Log.Info().
							Int("decrypted_size", len(videoData)).
							Msg("Successfully decrypted video from ENC_KM")
					}

					fileName := data.ContentMetadata["FILE_NAME"]

					if fileName == "" && decryptedBody != "" && strings.Contains(decryptedBody, "fileName") {
						var decryptInfo struct {
							FileName string `json:"fileName"`
						}
						if err := json.Unmarshal([]byte(decryptedBody), &decryptInfo); err == nil && decryptInfo.FileName != "" {
							fileName = decryptInfo.FileName
						}
					}

					if fileName == "" {
						fileName = "video.mp4"
					}

					mimeType := "video/mp4"
					if strings.HasSuffix(strings.ToLower(fileName), ".webm") {
						mimeType = "video/webm"
					}

					mxc, file, err := intent.UploadMedia(ctx, portal.MXID, videoData, fileName, mimeType)
					if err != nil {
						lc.UserLogin.Bridge.Log.Error().
							Err(err).
							Int("size_bytes", len(videoData)).
							Msg("Failed to upload video to Matrix")
						return nil, fmt.Errorf("failed to upload video to matrix: %w", err)
					}

					lc.UserLogin.Bridge.Log.Info().
						Str("mxc", mxc.ParseOrIgnore().String()).
						Str("file_name", fileName).
						Int("size", len(videoData)).
						Msg("Successfully uploaded video to Matrix")

					var duration int
					if durationStr := data.ContentMetadata["DURATION"]; durationStr != "" {
						if d, err := strconv.Atoi(durationStr); err == nil {
							duration = d
						}
					}

					videoInfo := &event.FileInfo{
						MimeType: mimeType,
						Size:     len(videoData),
					}
					if duration > 0 {
						videoInfo.Duration = duration
					}

					return &bridgev2.ConvertedMessage{
						Parts: []*bridgev2.ConvertedMessagePart{
							{
								Type: event.EventMessage,
								Content: &event.MessageEventContent{
									MsgType:   event.MsgVideo,
									Body:      fileName,
									URL:       mxc,
									File:      file,
									Info:      videoInfo,
									RelatesTo: replyRelatesTo,
								},
							},
						},
					}, nil
				}
			}

			// Handle File type (14)
			if data.ContentType == 14 {
				oid := data.ContentMetadata["OID"]
				if oid == "" && decryptedBody != "" && strings.Contains(decryptedBody, "fileName") {
					lc.UserLogin.Bridge.Log.Debug().Msg("File message with encrypted payload, OID in metadata")
				}

				if oid != "" {
					client := line.NewClient(lc.AccessToken)
					fileData, err := client.DownloadOBSWithSID(oid, data.ID, "emf")
					if err != nil {
						lc.UserLogin.Bridge.Log.Error().
							Err(err).
							Str("oid", oid).
							Msg("Failed to download file from OBS")
						return nil, fmt.Errorf("failed to download file from OBS: %w", err)
					}

					// Try to decrypt using keyMaterial from encrypted payload
					var fileName string
					if decryptedBody != "" && strings.Contains(decryptedBody, "keyMaterial") {
						var decryptInfo struct {
							KeyMaterial string `json:"keyMaterial"`
							FileName    string `json:"fileName"`
						}
						if err := json.Unmarshal([]byte(decryptedBody), &decryptInfo); err != nil {
							lc.UserLogin.Bridge.Log.Error().
								Err(err).
								Msg("Failed to parse file payload JSON")
							return nil, fmt.Errorf("failed to parse file payload: %w", err)
						}

						if decryptInfo.KeyMaterial != "" {
							keyPreview := decryptInfo.KeyMaterial
							if len(keyPreview) > 20 {
								keyPreview = keyPreview[:20] + "..."
							}
							lc.UserLogin.Bridge.Log.Debug().
								Str("key_material_preview", keyPreview).
								Msg("Decrypting file using keyMaterial from payload")

							decryptedFile, err := lc.decryptImageData(fileData, decryptInfo.KeyMaterial)
							if err != nil {
								lc.UserLogin.Bridge.Log.Error().
									Err(err).
									Msg("Failed to decrypt file data")
								return nil, fmt.Errorf("failed to decrypt file data: %w", err)
							}
							fileData = decryptedFile
							lc.UserLogin.Bridge.Log.Info().
								Int("decrypted_size", len(fileData)).
								Msg("Successfully decrypted file")
						}

						if decryptInfo.FileName != "" {
							fileName = decryptInfo.FileName
						}
					}

					if fileName == "" {
						fileName = data.ContentMetadata["FILE_NAME"]
					}

					if fileName == "" {
						fileName = "file.bin"
					}

					// Detect MIME type from file extension
					mimeType := "application/octet-stream"
					if strings.HasSuffix(strings.ToLower(fileName), ".pdf") {
						mimeType = "application/pdf"
					}

					mxc, file, err := intent.UploadMedia(ctx, portal.MXID, fileData, fileName, mimeType)
					if err != nil {
						lc.UserLogin.Bridge.Log.Error().
							Err(err).
							Int("size_bytes", len(fileData)).
							Msg("Failed to upload file to Matrix")
						return nil, fmt.Errorf("failed to upload file to matrix: %w", err)
					}

					lc.UserLogin.Bridge.Log.Info().
						Str("mxc", mxc.ParseOrIgnore().String()).
						Str("file_name", fileName).
						Int("size", len(fileData)).
						Msg("Successfully uploaded file to Matrix")

					return &bridgev2.ConvertedMessage{
						Parts: []*bridgev2.ConvertedMessagePart{
							{
								Type: event.EventMessage,
								Content: &event.MessageEventContent{
									MsgType: event.MsgFile,
									Body:    fileName,
									URL:     mxc,
									File:    file,
									Info: &event.FileInfo{
										MimeType: mimeType,
										Size:     len(fileData),
									},
									RelatesTo: replyRelatesTo,
								},
							},
						},
					}, nil
				}
			}

			// Handle Sticker (7)
			if data.ContentType == 7 {
				stkID := data.ContentMetadata["STKID"]
				stkTxt := data.ContentMetadata["STKTXT"]
				stkOpt := data.ContentMetadata["STKOPT"]
				if stkTxt == "" {
					stkTxt = "[Sticker]"
				}

				if stkID != "" {
					var url string
					if strings.Contains(stkOpt, "A") {
						url = fmt.Sprintf("https://stickershop.line-scdn.net/stickershop/v1/sticker/%s/android/sticker_animation.png", stkID)
					} else {
						url = fmt.Sprintf("https://stickershop.line-scdn.net/stickershop/v1/sticker/%s/android/sticker.png", stkID)
					}

					resp, err := lc.HTTPClient.Get(url)
					// If animated fetch fails (e.g. 404), fallback to static if we tried animation
					if (err != nil || resp.StatusCode != 200) && strings.Contains(stkOpt, "A") {
						if resp != nil {
							resp.Body.Close()
						}
						url = fmt.Sprintf("https://stickershop.line-scdn.net/stickershop/v1/sticker/%s/android/sticker.png", stkID)
						resp, err = lc.HTTPClient.Get(url)
					}

					if err != nil {
						lc.UserLogin.Bridge.Log.Warn().Err(err).Str("stk_id", stkID).Msg("Failed to download sticker")
					} else if resp.StatusCode != 200 {
						lc.UserLogin.Bridge.Log.Warn().Int("status_code", resp.StatusCode).Str("stk_id", stkID).Msg("Failed to download sticker")
						resp.Body.Close()
					} else {
						defer resp.Body.Close()
						stkData, err := io.ReadAll(resp.Body)
						if err != nil {
							lc.UserLogin.Bridge.Log.Warn().Err(err).Str("stk_id", stkID).Msg("Failed to read sticker body")
						} else {
							mxc, file, err := intent.UploadMedia(ctx, portal.MXID, stkData, "sticker.png", "image/png")
							if err != nil {
								lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to upload sticker to Matrix")
							} else {
								return &bridgev2.ConvertedMessage{
									Parts: []*bridgev2.ConvertedMessagePart{
										{
											Type: event.EventMessage,
											Content: &event.MessageEventContent{
												MsgType: event.MsgFile,
												Body:    "sticker.png",
												URL:     mxc,
												File:    file,
												Info: &event.FileInfo{
													MimeType: "image/png",
													Size:     len(stkData),
												},
												RelatesTo: replyRelatesTo,
											},
										},
									},
								}, nil
							}
						}
					}
				}

				// Fallback to text if download/upload fails
				return &bridgev2.ConvertedMessage{
					Parts: []*bridgev2.ConvertedMessagePart{
						{
							Type: event.EventMessage,
							Content: &event.MessageEventContent{
								MsgType:   event.MsgText,
								Body:      stkTxt,
								RelatesTo: replyRelatesTo,
							},
						},
					},
				}, nil
			}

			// Default to Text
			return &bridgev2.ConvertedMessage{
				Parts: []*bridgev2.ConvertedMessagePart{
					{
						Type: event.EventMessage,
						Content: &event.MessageEventContent{
							MsgType:   event.MsgText,
							Body:      unwrappedText,
							RelatesTo: replyRelatesTo,
						},
					},
				},
			}, nil
		},
	})
}

func (lc *LineClient) Disconnect() {}

func (lc *LineClient) HandleMatrixReadReceipt(ctx context.Context, read *bridgev2.MatrixReadReceipt) error {
	if read.ReadUpTo.IsZero() && read.EventID == "" {
		return nil
	}

	targetID := string(read.EventID)
	if read.EventID != "" {
		msg, err := lc.UserLogin.Bridge.DB.Message.GetPartByMXID(ctx, read.EventID)
		if err == nil && msg != nil && msg.ID != "" {
			targetID = string(msg.ID)
		}
	}

	if targetID == "" || strings.HasPrefix(targetID, "$") {
		return nil
	}

	client := line.NewClient(lc.AccessToken)
	return client.SendChatChecked(string(read.Portal.ID), targetID)
}

func (lc *LineClient) IsLoggedIn() bool { return lc.AccessToken != "" }

func (lc *LineClient) LogoutRemote(ctx context.Context) {}

func (lc *LineClient) GetCapabilities(ctx context.Context, portal *bridgev2.Portal) *event.RoomFeatures {
	return &event.RoomFeatures{
		MaxTextLength: 5000,
		File: event.FileFeatureMap{
			event.MsgImage: {
				MimeTypes: map[string]event.CapabilitySupportLevel{
					"image/jpeg": event.CapLevelFullySupported,
					"image/png":  event.CapLevelFullySupported,
					"image/gif":  event.CapLevelFullySupported,
					"image/webp": event.CapLevelFullySupported,
				},
			},
			event.MsgFile: {
				MimeTypes: map[string]event.CapabilitySupportLevel{
					"image/gif": event.CapLevelFullySupported,
					"*/*":       event.CapLevelFullySupported,
				},
			},
			event.MsgVideo: {
				MimeTypes: map[string]event.CapabilitySupportLevel{
					"video/mp4":  event.CapLevelFullySupported,
					"video/webm": event.CapLevelFullySupported,
				},
			},
			event.MsgAudio: {
				MimeTypes: map[string]event.CapabilitySupportLevel{
					"audio/mpeg": event.CapLevelFullySupported,
					"audio/ogg":  event.CapLevelFullySupported,
					"audio/mp4":  event.CapLevelFullySupported,
				},
			},
		},
	}
}

func makeUserID(userID string) networkid.UserID { return networkid.UserID(userID) }

func makePortalID(userID string) networkid.PortalID { return networkid.PortalID(userID) }

func (lc *LineClient) IsThisUser(ctx context.Context, userID networkid.UserID) bool {
	return userID == networkid.UserID(lc.UserLogin.ID)
}

func (lc *LineClient) GetChatInfo(ctx context.Context, portal *bridgev2.Portal) (*bridgev2.ChatInfo, error) {
	mid := string(portal.ID)
	lowerMid := strings.ToLower(mid)
	if strings.HasPrefix(lowerMid, "c") || strings.HasPrefix(lowerMid, "r") {
		client := line.NewClient(lc.AccessToken)
		res, err := client.GetChats([]string{mid}, true, true)
		if err != nil && lc.isRefreshRequired(err) {
			if errRefresh := lc.refreshAndSave(ctx); errRefresh == nil {
				client = line.NewClient(lc.AccessToken)
				res, err = client.GetChats([]string{mid}, true, true)
			}
		}
		if err != nil {
			return nil, err
		}
		if len(res.Chats) == 0 {
			return nil, fmt.Errorf("chat not found")
		}
		return lc.chatToChatInfo(&res.Chats[0]), nil
	}

	contact := lc.getContact(string(portal.ID))
	var avatar *bridgev2.Avatar
	if contact.PicturePath != "" {
		avatar = &bridgev2.Avatar{
			ID: networkid.AvatarID(contact.PicturePath),
			Get: func(ctx context.Context) ([]byte, error) {
				return lc.GetAvatar(ctx, networkid.AvatarID(contact.PicturePath))
			},
		}
	}
	return &bridgev2.ChatInfo{
		Name:   &contact.DisplayName,
		Avatar: avatar,
		Members: &bridgev2.ChatMemberList{
			IsFull: true,
			Members: []bridgev2.ChatMember{
				{
					EventSender: bridgev2.EventSender{
						IsFromMe: true,
						Sender:   networkid.UserID(lc.UserLogin.ID),
					},
					Membership: event.MembershipJoin,
					PowerLevel: ptr.Ptr(100),
				},
				{
					EventSender: bridgev2.EventSender{
						Sender: networkid.UserID(portal.ID),
					},
					Membership: event.MembershipJoin,
					PowerLevel: ptr.Ptr(0),
				},
			},
		},
	}, nil
}

func (lc *LineClient) GetUserInfo(ctx context.Context, ghost *bridgev2.Ghost) (*bridgev2.UserInfo, error) {
	contact := lc.getContact(string(ghost.ID))
	var avatar *bridgev2.Avatar
	if contact.PicturePath != "" {
		avatar = &bridgev2.Avatar{
			ID: networkid.AvatarID(contact.PicturePath),
			Get: func(ctx context.Context) ([]byte, error) {
				return lc.GetAvatar(ctx, networkid.AvatarID(contact.PicturePath))
			},
		}
	}
	return &bridgev2.UserInfo{
		Identifiers: []string{string(ghost.ID)},
		Name:        &contact.DisplayName,
		Avatar:      avatar,
	}, nil
}

func (lc *LineClient) getContact(mid string) line.Contact {
	if contact, ok := lc.contactCache[mid]; ok {
		return contact
	}
	client := line.NewClient(lc.AccessToken)
	res, err := client.GetContactsV2([]string{mid})
	if err != nil && lc.isRefreshRequired(err) {
		if errRefresh := lc.refreshAndSave(context.TODO()); errRefresh == nil {
			client = line.NewClient(lc.AccessToken)
			res, err = client.GetContactsV2([]string{mid})
		}
	}
	if err == nil && res != nil && res.Contacts != nil {
		if wrapper, ok := res.Contacts[mid]; ok {
			lc.contactCache[mid] = wrapper.Contact
			return wrapper.Contact
		}
	}
	return line.Contact{Mid: mid, DisplayName: mid}
}

type peerKeyInfo struct {
	raw int
	pub string
}

func (lc *LineClient) midOrFallback() string {
	if lc.Mid != "" {
		return lc.Mid
	}
	return string(lc.UserLogin.ID)
}

func guessToType(mid string) int {
	if strings.HasPrefix(strings.ToLower(mid), "c") {
		return 2 // GROUP
	}
	if strings.HasPrefix(strings.ToLower(mid), "r") {
		return 1 // ROOM
	}
	return 0 // USER
}

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
		return
	}
	peerRaw := senderKeyID
	if senderKeyID == myRaw {
		peerRaw = receiverKeyID
	}
	if peerRaw == 0 || peerRaw == myRaw {
		return
	}
	if lc.E2EE.HasPeerPublicKey(peerRaw) {
		return
	}
	if _, _, err := lc.ensurePeerKeyByID(ctx, msg.From, peerRaw); err != nil {
		if _, _, err2 := lc.ensurePeerKey(ctx, msg.From); err2 != nil {
			lc.UserLogin.Bridge.Log.Warn().Err(err).Err(err2).Str("peer", msg.From).Int("key_id", peerRaw).Msg("Failed to fetch peer key for decrypt")
		}
	}
}

// resolveReplyRelatesTo looks up the Matrix event ID for a replied-to LINE message.
func (lc *LineClient) resolveReplyRelatesTo(ctx context.Context, data *line.Message) *event.RelatesTo {
	if data == nil {
		return nil
	}

	relatedID := data.RelatedMessageID
	if relatedID == "" && data.ContentMetadata != nil {
		relatedID = data.ContentMetadata["message_relation_server_message_id"]
	}

	if relatedID == "" {
		return nil
	}

	if data.MessageRelationType != 0 && data.MessageRelationType != 3 {
		return nil
	}

	dbMsg, err := lc.UserLogin.Bridge.DB.Message.GetPartByID(ctx, lc.UserLogin.ID, networkid.MessageID(relatedID), "")
	if err != nil {
		lc.UserLogin.Bridge.Log.Debug().Err(err).Str("related_msg_id", relatedID).Msg("Failed to lookup reply target")
		return nil
	}
	if dbMsg == nil || dbMsg.MXID == "" {
		lc.UserLogin.Bridge.Log.Debug().Str("related_msg_id", relatedID).Msg("No Matrix event found for reply target")
		return nil
	}

	return &event.RelatesTo{InReplyTo: &event.InReplyTo{EventID: dbMsg.MXID}}
}

func (lc *LineClient) HandleMatrixMessage(ctx context.Context, msg *bridgev2.MatrixMessage) (*bridgev2.MatrixMessageResponse, error) {
	if lc.E2EE == nil {
		return nil, fmt.Errorf("E2EE not initialized; cannot send")
	}

	client := line.NewClient(lc.AccessToken)
	portalMid := string(msg.Portal.ID)
	fromMid := lc.midOrFallback()

	var chunks []string
	var err error
	contentType := 0
	contentMetadata := map[string]string{
		"e2eeVersion": "2",
	}

	var payload []byte

	switch msg.Content.MsgType {
	case event.MsgText:
		contentType = 0
		// For groups, EncryptGroupMessage wraps in {"text": ...}
		// For 1:1, we need JSON for EncryptMessageV2Raw
		payload, err = json.Marshal(map[string]string{"text": msg.Content.Body})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal text payload: %w", err)
		}

	case event.MsgImage:
		data, err := lc.UserLogin.Bridge.Bot.DownloadMedia(ctx, msg.Content.URL, msg.Content.File)
		if err != nil {
			return nil, fmt.Errorf("failed to download media from matrix: %w", err)
		}

		mimeType := msg.Content.Info.MimeType
		isGif := mimeType == "image/gif"
		isAnimated := isGif && isAnimatedGif(data)

		extension := "jpg"
		if isGif {
			extension = "gif"
		} else if mimeType == "image/png" {
			extension = "png"
		}

		encryptedData, keyMaterialB64, err := lc.encryptFileData(data)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt image data: %w", err)
		}

		oid, err := client.UploadOBS(encryptedData)
		if err != nil {
			return nil, fmt.Errorf("failed to upload encrypted image to OBS: %w", err)
		}

		thumbnailData, thumbWidth, thumbHeight, err := generateThumbnail(data)
		if err != nil {
			lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to generate thumbnail, continuing without it")
		} else {
			keyMaterial, _ := base64.StdEncoding.DecodeString(keyMaterialB64)

			// Derive keys using HKDF
			kdf := hkdf.New(sha256.New, keyMaterial, nil, []byte("FileEncryption"))
			derived := make([]byte, 76)
			io.ReadFull(kdf, derived)

			encKey := derived[0:32]
			macKey := derived[32:64]
			nonce := derived[64:76]

			counter := make([]byte, 16)
			copy(counter, nonce)

			block, _ := aes.NewCipher(encKey)
			stream := cipher.NewCTR(block, counter)

			encryptedThumb := make([]byte, len(thumbnailData))
			stream.XORKeyStream(encryptedThumb, thumbnailData)

			h := hmac.New(sha256.New, macKey)
			h.Write(encryptedThumb)
			encryptedThumbWithHMAC := append(encryptedThumb, h.Sum(nil)...)

			// Upload preview
			previewOID := fmt.Sprintf("%s__ud-preview", oid)
			if err := client.UploadOBSWithOID(encryptedThumbWithHMAC, previewOID); err != nil {
				lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to upload preview, continuing without it")
			} else {
				mediaThumbInfo := map[string]interface{}{
					"width":  thumbWidth,
					"height": thumbHeight,
				}
				if thumbInfoJSON, err := json.Marshal(mediaThumbInfo); err == nil {
					contentMetadata["MEDIA_THUMB_INFO"] = string(thumbInfoJSON)
				}

				lc.UserLogin.Bridge.Log.Info().
					Str("preview_oid", previewOID).
					Int("thumb_size", len(thumbnailData)).
					Int("thumb_width", thumbWidth).
					Int("thumb_height", thumbHeight).
					Msg("Uploaded preview thumbnail")
			}
		}

		// metadata
		contentType = 1 // Image
		contentMetadata["OID"] = oid
		contentMetadata["SID"] = "emi" // source ID for LINE images
		contentMetadata["FILE_SIZE"] = fmt.Sprintf("%d", len(encryptedData))
		contentMetadata["contentType"] = "1"

		// Add encryption key material to metadata (ENC_KM)
		contentMetadata["ENC_KM"] = keyMaterialB64

		// Add file name
		fileName := msg.Content.Body
		if fileName == "" {
			if isGif {
				fileName = "animation.gif"
			} else {
				fileName = "image.jpg"
			}
		}
		contentMetadata["FILE_NAME"] = fileName

		// Add MEDIA_CONTENT_INFO for proper display
		mediaContentInfo := map[string]interface{}{
			"category":  "original",
			"fileSize":  len(encryptedData),
			"extension": extension,
		}

		// Add animated flag for GIFs
		if isAnimated {
			mediaContentInfo["animated"] = true
		}

		if mediaInfoJSON, err := json.Marshal(mediaContentInfo); err == nil {
			contentMetadata["MEDIA_CONTENT_INFO"] = string(mediaInfoJSON)
		}

		payload = []byte("{}")

	case event.MsgFile:
		// Generic files
		data, err := lc.UserLogin.Bridge.Bot.DownloadMedia(ctx, msg.Content.URL, msg.Content.File)
		if err != nil {
			return nil, fmt.Errorf("failed to download file from matrix: %w", err)
		}

		// Encrypt the file data
		encryptedData, keyMaterialB64, err := lc.encryptFileData(data)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt file data: %w", err)
		}

		// Upload encrypted file to LINE OBS with emf SID
		oid, err := client.UploadOBSWithSID(encryptedData, "emf")
		if err != nil {
			return nil, fmt.Errorf("failed to upload encrypted file to OBS: %w", err)
		}

		// Prepare Metadata
		contentType = 14 // File
		contentMetadata["OID"] = oid
		contentMetadata["SID"] = "emf"                              // File SID
		contentMetadata["FILE_SIZE"] = fmt.Sprintf("%d", len(data)) // Original unencrypted size
		contentMetadata["contentType"] = "14"

		fileName := msg.Content.Body
		if fileName == "" {
			fileName = "file.bin"
		}
		contentMetadata["FILE_NAME"] = fileName

		// For files, encryption key and filename go in the E2EE encrypted payload
		filePayload := map[string]string{
			"keyMaterial": keyMaterialB64,
			"fileName":    fileName,
		}
		payloadBytes, _ := json.Marshal(filePayload)
		payload = payloadBytes

		lc.UserLogin.Bridge.Log.Info().
			Str("oid", oid).
			Str("file_name", fileName).
			Int("encrypted_size", len(encryptedData)).
			Int("original_size", len(data)).
			Msg("Prepared E2EE file message")

	case event.MsgVideo:
		data, err := lc.UserLogin.Bridge.Bot.DownloadMedia(ctx, msg.Content.URL, msg.Content.File)
		if err != nil {
			return nil, fmt.Errorf("failed to download video from matrix: %w", err)
		}

		encryptedData, keyMaterialB64, err := lc.encryptVideoData(data)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt video data: %w", err)
		}

		oid, err := client.UploadOBSWithSID(encryptedData, "emv")
		if err != nil {
			return nil, fmt.Errorf("failed to upload encrypted video to OBS: %w", err)
		}

		chunkHashes := generateChunkHashes(encryptedData[:len(encryptedData)-32]) // Exclude HMAC
		if len(chunkHashes) > 0 {
			hashOID := fmt.Sprintf("%s__ud-hash", oid)
			if err := client.UploadOBSWithOIDAndSID(chunkHashes, hashOID, "emv"); err != nil {
				lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to upload video hash, continuing without it")
			} else {
				lc.UserLogin.Bridge.Log.Info().
					Str("hash_oid", hashOID).
					Int("hash_size", len(chunkHashes)).
					Msg("Uploaded video chunk hashes")
			}
		}

		thumbnailData, thumbWidth, thumbHeight, err := extractVideoThumbnail(data)
		if err != nil {
			lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to extract video thumbnail, using placeholder")
			thumbWidth = 384
			thumbHeight = 384
			placeholderImg := image.NewRGBA(image.Rect(0, 0, thumbWidth, thumbHeight))
			var thumbBuf bytes.Buffer
			jpeg.Encode(&thumbBuf, placeholderImg, &jpeg.Options{Quality: 30})
			thumbnailData = thumbBuf.Bytes()
		}

		if len(thumbnailData) > 0 {
			keyMaterial, _ := base64.StdEncoding.DecodeString(keyMaterialB64)
			kdf := hkdf.New(sha256.New, keyMaterial, nil, []byte("FileEncryption"))
			derived := make([]byte, 76)
			io.ReadFull(kdf, derived)

			encKey := derived[0:32]
			macKey := derived[32:64]
			nonce := derived[64:76]

			counter := make([]byte, 16)
			copy(counter, nonce)

			block, _ := aes.NewCipher(encKey)
			stream := cipher.NewCTR(block, counter)

			encryptedThumb := make([]byte, len(thumbnailData))
			stream.XORKeyStream(encryptedThumb, thumbnailData)

			h := hmac.New(sha256.New, macKey)
			h.Write(encryptedThumb)
			encryptedThumbWithHMAC := append(encryptedThumb, h.Sum(nil)...)

			previewOID := fmt.Sprintf("%s__ud-preview", oid)
			if err := client.UploadOBSWithOIDAndSID(encryptedThumbWithHMAC, previewOID, "emv"); err != nil {
				lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to upload video preview, continuing without it")
			} else {
				mediaThumbInfo := map[string]interface{}{
					"width":  thumbWidth,
					"height": thumbHeight,
				}
				if thumbInfoJSON, err := json.Marshal(mediaThumbInfo); err == nil {
					contentMetadata["MEDIA_THUMB_INFO"] = string(thumbInfoJSON)
				}

				lc.UserLogin.Bridge.Log.Info().
					Str("preview_oid", previewOID).
					Int("preview_size", len(encryptedThumbWithHMAC)).
					Int("thumb_width", thumbWidth).
					Int("thumb_height", thumbHeight).
					Msg("Uploaded video preview placeholder")
			}
		}

		contentType = 2 // Video
		contentMetadata["OID"] = oid
		contentMetadata["SID"] = "emv"                              // Video SID
		contentMetadata["FILE_SIZE"] = fmt.Sprintf("%d", len(data)) // Original unencrypted size
		contentMetadata["contentType"] = "2"
		contentMetadata["ENC_KM"] = keyMaterialB64 // Required for OBS access

		// Add duration if available (in milliseconds)
		if msg.Content.Info.Duration > 0 {
			contentMetadata["DURATION"] = fmt.Sprintf("%d", msg.Content.Info.Duration)
		}

		//Empty payload like images
		payload = []byte("{}")

		lc.UserLogin.Bridge.Log.Info().
			Str("oid", oid).
			Str("enc_km", keyMaterialB64[:20]+"...").
			Int("encrypted_size", len(encryptedData)).
			Msg("Prepared E2EE video message")

	default:
		return nil, fmt.Errorf("message type %s not implemented", msg.Content.MsgType)
	}

	lowerPortalID := strings.ToLower(portalMid)
	isGroup := strings.HasPrefix(lowerPortalID, "c") || strings.HasPrefix(lowerPortalID, "r")

	if isGroup {
		if errFetch := lc.fetchAndUnwrapGroupKey(ctx, portalMid, 0); errFetch != nil {
			lc.UserLogin.Bridge.Log.Debug().Err(errFetch).Str("chat_mid", portalMid).Msg("fetchAndUnwrapGroupKey before encrypt failed")
		}
		if contentType != 0 {
			chunks, err = lc.E2EE.EncryptGroupMessageRaw(portalMid, fromMid, contentType, payload)
		} else {
			chunks, err = lc.E2EE.EncryptGroupMessage(portalMid, fromMid, msg.Content.Body)
		}
		if err != nil {
			if errFetch := lc.fetchAndUnwrapGroupKey(ctx, portalMid, 0); errFetch == nil {
				if contentType != 0 {
					chunks, err = lc.E2EE.EncryptGroupMessageRaw(portalMid, fromMid, contentType, payload)
				} else {
					chunks, err = lc.E2EE.EncryptGroupMessage(portalMid, fromMid, msg.Content.Body)
				}
			}
		}
	} else {
		// 1-1 Encryption
		myRaw, myKeyID, err := lc.E2EE.MyKeyIDs()
		if err != nil {
			return nil, fmt.Errorf("missing own E2EE key: %w", err)
		}
		peerRaw, peerPub, err := lc.ensurePeerKey(ctx, portalMid)
		if err != nil {
			return nil, fmt.Errorf("failed to get peer key: %w", err)
		}

		chunks, _ = lc.E2EE.EncryptMessageV2Raw(portalMid, fromMid, myKeyID, peerPub, myRaw, peerRaw, contentType, payload)
	}

	if err != nil {
		return nil, fmt.Errorf("encrypt failed: %w", err)
	}

	now := time.Now().UnixMilli()
	lineMsg := &line.Message{
		ID:              fmt.Sprintf("local-%d", now),
		From:            lc.midOrFallback(),
		To:              portalMid,
		ToType:          guessToType(portalMid),
		SessionID:       0,
		CreatedTime:     json.Number(strconv.FormatInt(now, 10)),
		ContentType:     contentType,
		HasContent:      contentType != 0, // True for images
		ContentMetadata: contentMetadata,
		Chunks:          chunks,
	}

	if msg.ReplyTo != nil {
		dbMsg, err := lc.UserLogin.Bridge.DB.Message.GetPartByMXID(ctx, id.EventID(msg.ReplyTo.ID))
		if err == nil && dbMsg != nil && dbMsg.ID != "" {
			lineMsg.RelatedMessageID = string(dbMsg.ID)
			lineMsg.MessageRelationType = 3
			lineMsg.RelatedMessageServiceCode = 1
		} else {
			lc.UserLogin.Bridge.Log.Warn().Str("reply_to_mxid", string(msg.ReplyTo.ID)).Msg("Failed to resolve reply target to LINE ID")
		}
	}

	reqSeq := int(now % 1_000_000_000)
	lc.reqSeqMu.Lock()
	if lc.sentReqSeqs == nil {
		lc.sentReqSeqs = make(map[int]time.Time)
	}
	lc.sentReqSeqs[reqSeq] = time.Now()
	lc.reqSeqMu.Unlock()

	sentMsg, err := client.SendMessage(int64(reqSeq), lineMsg)
	if err != nil {
		return nil, err
	}

	return &bridgev2.MatrixMessageResponse{
		DB: &database.Message{
			ID:        networkid.MessageID(sentMsg.ID),
			SenderID:  makeUserID(string(lc.UserLogin.ID)),
			Timestamp: time.UnixMilli(now),
		},
	}, nil
}

var _ bridgev2.IdentifierResolvingNetworkAPI = (*LineClient)(nil)

func (lc *LineClient) ResolveIdentifier(ctx context.Context, identifier string, createChat bool) (*bridgev2.ResolveIdentifierResponse, error) {
	userID := makeUserID(strings.TrimSpace(identifier))
	portalID := networkid.PortalKey{ID: makePortalID(string(userID)), Receiver: lc.UserLogin.ID}
	ghost, err := lc.UserLogin.Bridge.GetGhostByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get ghost: %w", err)
	}
	portal, err := lc.UserLogin.Bridge.GetPortalByKey(ctx, portalID)
	if err != nil {
		return nil, fmt.Errorf("failed to get portal: %w", err)
	}
	ghostInfo, _ := lc.GetUserInfo(ctx, ghost)
	portalInfo, _ := lc.GetChatInfo(ctx, portal)
	return &bridgev2.ResolveIdentifierResponse{
		Ghost:    ghost,
		UserID:   userID,
		UserInfo: ghostInfo,
		Chat:     &bridgev2.CreateChatResponse{Portal: portal, PortalKey: portalID, PortalInfo: portalInfo},
	}, nil
}

func (lc *LineClient) GetAvatar(ctx context.Context, id networkid.AvatarID) ([]byte, error) {
	url := fmt.Sprintf("https://profile.line-scdn.net%s", id)
	resp, err := lc.HTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
