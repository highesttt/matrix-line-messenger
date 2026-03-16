package connector

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"

	"github.com/highesttt/matrix-line-messenger/pkg/line"
)

func (lc *LineClient) HandleMatrixMessage(ctx context.Context, msg *bridgev2.MatrixMessage) (*bridgev2.MatrixMessageResponse, error) {
	if lc.E2EE == nil {
		return nil, fmt.Errorf("E2EE not initialized; cannot send")
	}

	client := line.NewClient(lc.AccessToken)
	portalMid := string(msg.Portal.ID)
	fromMid := lc.midOrFallback()

	var chunks []string
	var err error
	contentType := int(ContentText)
	contentMetadata := map[string]string{
		"e2eeVersion": "2",
	}

	var payload []byte

	switch msg.Content.MsgType {
	case event.MsgText:
		contentType = int(ContentText)
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
		contentType = int(ContentImage)
		contentMetadata["OID"] = oid
		contentMetadata["SID"] = "emi" // source ID for LINE images
		contentMetadata["FILE_SIZE"] = fmt.Sprintf("%d", len(encryptedData))
		contentMetadata["contentType"] = fmt.Sprintf("%d", ContentImage)

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
		contentType = int(ContentFile)
		contentMetadata["OID"] = oid
		contentMetadata["SID"] = "emf"                              // File SID
		contentMetadata["FILE_SIZE"] = fmt.Sprintf("%d", len(data)) // Original unencrypted size
		contentMetadata["contentType"] = fmt.Sprintf("%d", ContentFile)

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

		contentType = int(ContentVideo)
		contentMetadata["OID"] = oid
		contentMetadata["SID"] = "emv"                              // Video SID
		contentMetadata["FILE_SIZE"] = fmt.Sprintf("%d", len(data)) // Original unencrypted size
		contentMetadata["contentType"] = fmt.Sprintf("%d", ContentVideo)
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
		if contentType != int(ContentText) {
			chunks, err = lc.E2EE.EncryptGroupMessageRaw(portalMid, fromMid, contentType, payload)
		} else {
			chunks, err = lc.E2EE.EncryptGroupMessage(portalMid, fromMid, msg.Content.Body)
		}
		if err != nil {
			if errFetch := lc.fetchAndUnwrapGroupKey(ctx, portalMid, 0); errFetch != nil {
				return nil, wrapLetterSealingSendError(portalMid, true, errFetch)
			}
			if contentType != int(ContentText) {
				chunks, err = lc.E2EE.EncryptGroupMessageRaw(portalMid, fromMid, contentType, payload)
			} else {
				chunks, err = lc.E2EE.EncryptGroupMessage(portalMid, fromMid, msg.Content.Body)
			}
		}
	} else {
		// 1-1 Encryption
		myRaw, myKeyID, errKey := lc.E2EE.MyKeyIDs()
		if errKey != nil {
			return nil, fmt.Errorf("missing own E2EE key: %w", errKey)
		}
		peerRaw, peerPub, errPeer := lc.ensurePeerKey(ctx, portalMid)
		if errPeer != nil {
			return nil, wrapLetterSealingSendError(portalMid, false, fmt.Errorf("failed to get peer key: %w", errPeer))
		}

		chunks, err = lc.E2EE.EncryptMessageV2Raw(portalMid, fromMid, myKeyID, peerPub, myRaw, peerRaw, contentType, payload)
	}

	if err != nil {
		return nil, wrapLetterSealingSendError(portalMid, isGroup, fmt.Errorf("encrypt failed: %w", err))
	}

	now := time.Now().UnixMilli()
	lineMsg := &line.Message{
		ID:              fmt.Sprintf("local-%d", now),
		From:            lc.midOrFallback(),
		To:              portalMid,
		ToType:          int(guessToType(portalMid)),
		SessionID:       0,
		CreatedTime:     json.Number(strconv.FormatInt(now, 10)),
		ContentType:     contentType,
		HasContent:      contentType != int(ContentText), // True for images
		ContentMetadata: contentMetadata,
		Chunks:          chunks,
	}

	var relatedMsg *database.Message

	if msg.ReplyTo != nil {
		relatedMsg = msg.ReplyTo
	} else if msg.Content.RelatesTo != nil && msg.Content.RelatesTo.InReplyTo != nil {
		replyToMXID := msg.Content.RelatesTo.InReplyTo.EventID
		if replyToMXID != "" {
			dbMsg, err := lc.UserLogin.Bridge.DB.Message.GetPartByMXID(ctx, replyToMXID)
			if err == nil && dbMsg != nil {
				relatedMsg = dbMsg
			}
		}
	}

	if relatedMsg != nil && relatedMsg.ID != "" && !strings.HasPrefix(string(relatedMsg.ID), "local-") {
		lineMsg.RelatedMessageID = string(relatedMsg.ID)
		lineMsg.MessageRelationType = 3
		lineMsg.RelatedMessageServiceCode = 1
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

func (lc *LineClient) HandleMatrixMessageRemove(ctx context.Context, msg *bridgev2.MatrixMessageRemove) error {
	client := line.NewClient(lc.AccessToken)

	reqSeq := int(time.Now().UnixMilli() % 1_000_000_000)
	lc.reqSeqMu.Lock()
	if lc.sentReqSeqs == nil {
		lc.sentReqSeqs = make(map[int]time.Time)
	}
	lc.sentReqSeqs[reqSeq] = time.Now()
	lc.reqSeqMu.Unlock()

	return client.UnsendMessage(int64(reqSeq), string(msg.TargetMessage.ID))
}

func (lc *LineClient) HandleMatrixLeaveRoom(ctx context.Context, portal *bridgev2.Portal) error {
	client := line.NewClient(lc.AccessToken)

	reqSeq := int(time.Now().UnixMilli() % 1_000_000_000)
	lc.reqSeqMu.Lock()
	if lc.sentReqSeqs == nil {
		lc.sentReqSeqs = make(map[int]time.Time)
	}
	lc.sentReqSeqs[reqSeq] = time.Now()
	lc.reqSeqMu.Unlock()

	return client.SendChatRemoved(int64(reqSeq), string(portal.ID), "0", 0)
}
