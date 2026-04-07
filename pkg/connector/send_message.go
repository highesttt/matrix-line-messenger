package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	"strconv"
	"strings"
	"time"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"

	"github.com/highesttt/matrix-line-messenger/pkg/line"
)

func (lc *LineClient) HandleMatrixMessage(ctx context.Context, msg *bridgev2.MatrixMessage) (*bridgev2.MatrixMessageResponse, error) {
	client := line.NewClient(lc.AccessToken)
	portalMid := string(msg.Portal.ID)
	fromMid := lc.midOrFallback()

	lowerPortalID := strings.ToLower(portalMid)
	isGroup := strings.HasPrefix(lowerPortalID, "c") || strings.HasPrefix(lowerPortalID, "r")

	if lc.E2EE == nil {
		return nil, fmt.Errorf("E2EE not initialized; cannot send")
	}

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

		contentType = int(ContentImage)

		{
			uploadData, keyMaterialB64, err := lc.encryptFileData(data)
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt image data: %w", err)
			}

			oid, err := client.UploadOBS(uploadData)
			if err != nil {
				return nil, fmt.Errorf("failed to upload image to OBS: %w", err)
			}

			thumbnailData, thumbWidth, thumbHeight, err := generateThumbnail(data)
			if err != nil {
				lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to generate thumbnail, continuing without it")
			} else if thumbToUpload, err := encryptThumbnail(thumbnailData, keyMaterialB64); err != nil {
				lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to encrypt thumbnail, continuing without it")
			} else {
				previewOID := fmt.Sprintf("%s__ud-preview", oid)
				if err := client.UploadOBSWithOID(thumbToUpload, previewOID); err != nil {
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

			contentMetadata["OID"] = oid
			contentMetadata["SID"] = "emi"
			contentMetadata["FILE_SIZE"] = fmt.Sprintf("%d", len(uploadData))
			contentMetadata["contentType"] = fmt.Sprintf("%d", ContentImage)
			contentMetadata["ENC_KM"] = keyMaterialB64

			fileName := msg.Content.GetFileName()
			if fileName == "" {
				fileName = "image." + extension
			}
			contentMetadata["FILE_NAME"] = fileName

			mediaContentInfo := map[string]interface{}{
				"category":  "original",
				"fileSize":  len(uploadData),
				"extension": extension,
			}
			if isAnimated {
				mediaContentInfo["animated"] = true
			}
			if mediaInfoJSON, err := json.Marshal(mediaContentInfo); err == nil {
				contentMetadata["MEDIA_CONTENT_INFO"] = string(mediaInfoJSON)
			}

			imgPayload := map[string]string{"keyMaterial": keyMaterialB64}
			payload, _ = json.Marshal(imgPayload)
		}

	case event.MsgFile:
		data, err := lc.UserLogin.Bridge.Bot.DownloadMedia(ctx, msg.Content.URL, msg.Content.File)
		if err != nil {
			return nil, fmt.Errorf("failed to download file from matrix: %w", err)
		}

		contentType = int(ContentFile)

		fileName := msg.Content.GetFileName()
		if fileName == "" {
			fileName = "file.bin"
		}
		contentMetadata["FILE_NAME"] = fileName
		contentMetadata["FILE_SIZE"] = fmt.Sprintf("%d", len(data))
		contentMetadata["contentType"] = fmt.Sprintf("%d", ContentFile)

		uploadData, keyMaterialB64, err := lc.encryptFileData(data)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt file data: %w", err)
		}

		oid, err := client.UploadOBSWithSID(uploadData, "emf")
		if err != nil {
			return nil, fmt.Errorf("failed to upload file to OBS: %w", err)
		}

		contentMetadata["OID"] = oid
		contentMetadata["SID"] = "emf"
		contentMetadata["ENC_KM"] = keyMaterialB64

		filePayload := map[string]string{
			"keyMaterial": keyMaterialB64,
			"fileName":    fileName,
		}
		payloadBytes, _ := json.Marshal(filePayload)
		payload = payloadBytes

		lc.UserLogin.Bridge.Log.Info().
			Str("oid", oid).
			Str("file_name", fileName).
			Int("upload_size", len(uploadData)).
			Int("original_size", len(data)).
			Msg("Prepared file message")

	case event.MsgVideo:
		data, err := lc.UserLogin.Bridge.Bot.DownloadMedia(ctx, msg.Content.URL, msg.Content.File)
		if err != nil {
			return nil, fmt.Errorf("failed to download video from matrix: %w", err)
		}

		contentType = int(ContentVideo)
		contentMetadata["FILE_SIZE"] = fmt.Sprintf("%d", len(data))
		contentMetadata["contentType"] = fmt.Sprintf("%d", ContentVideo)

		if msg.Content.Info.Duration > 0 {
			contentMetadata["DURATION"] = fmt.Sprintf("%d", msg.Content.Info.Duration)
		}

		{
			uploadData, keyMaterialB64, err := lc.encryptVideoData(data)
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt video data: %w", err)
			}

			oid, err := client.UploadOBSWithSID(uploadData, "emv")
			if err != nil {
				return nil, fmt.Errorf("failed to upload video to OBS: %w", err)
			}

			chunkHashes := generateChunkHashes(uploadData[:len(uploadData)-32])
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
				if thumbToUpload, err := encryptThumbnail(thumbnailData, keyMaterialB64); err != nil {
					lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to encrypt video thumbnail, continuing without it")
				} else {
					previewOID := fmt.Sprintf("%s__ud-preview", oid)
					if err := client.UploadOBSWithOIDAndSID(thumbToUpload, previewOID, "emv"); err != nil {
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
							Int("preview_size", len(thumbToUpload)).
							Int("thumb_width", thumbWidth).
							Int("thumb_height", thumbHeight).
							Msg("Uploaded video preview")
					}
				}
			}

			contentMetadata["OID"] = oid
			contentMetadata["SID"] = "emv"
			contentMetadata["ENC_KM"] = keyMaterialB64

			vidPayload := map[string]string{"keyMaterial": keyMaterialB64}
			payload, _ = json.Marshal(vidPayload)

			lc.UserLogin.Bridge.Log.Info().
				Str("oid", oid).
				Int("upload_size", len(uploadData)).
				Msg("Prepared video message")
		}

	case event.MsgAudio:
		data, err := lc.UserLogin.Bridge.Bot.DownloadMedia(ctx, msg.Content.URL, msg.Content.File)
		if err != nil {
			return nil, fmt.Errorf("failed to download audio from matrix: %w", err)
		}

		contentType = int(ContentAudio)
		contentMetadata["FILE_SIZE"] = fmt.Sprintf("%d", len(data))
		contentMetadata["contentType"] = fmt.Sprintf("%d", ContentAudio)

		if msg.Content.Info != nil && msg.Content.Info.Duration > 0 {
			contentMetadata["DURATION"] = fmt.Sprintf("%d", msg.Content.Info.Duration)
			contentMetadata["AUDLEN"] = fmt.Sprintf("%d", msg.Content.Info.Duration)
		}

		uploadData, keyMaterialB64, err := lc.encryptFileData(data)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt audio data: %w", err)
		}

		oid, err := client.UploadOBSWithSID(uploadData, "ema")
		if err != nil {
			return nil, fmt.Errorf("failed to upload audio to OBS: %w", err)
		}

		contentMetadata["OID"] = oid
		contentMetadata["SID"] = "ema"
		contentMetadata["ENC_KM"] = keyMaterialB64

		audioPayload := map[string]string{"keyMaterial": keyMaterialB64}
		payload, _ = json.Marshal(audioPayload)

		lc.UserLogin.Bridge.Log.Info().
			Str("oid", oid).
			Int("upload_size", len(uploadData)).
			Msg("Prepared audio message")

	default:
		return nil, fmt.Errorf("message type %s not implemented", msg.Content.MsgType)
	}

	// Encryption phase
	if isGroup {
		if errFetch := lc.fetchAndUnwrapGroupKey(ctx, portalMid, 0); errFetch != nil {
			lc.UserLogin.Bridge.Log.Debug().Err(errFetch).Str("chat_mid", portalMid).Msg("fetchAndUnwrapGroupKey before encrypt failed")
		}
		if contentType != int(ContentText) {
			chunks, err = lc.E2EE.EncryptGroupMessageRaw(portalMid, fromMid, contentType, payload)
		} else {
			chunks, err = lc.E2EE.EncryptGroupMessage(portalMid, fromMid, msg.Content.Body)
		}
		if err != nil {
			if errFetch := lc.fetchAndUnwrapGroupKey(ctx, portalMid, 0); errFetch == nil {
				if contentType != int(ContentText) {
					chunks, err = lc.E2EE.EncryptGroupMessageRaw(portalMid, fromMid, contentType, payload)
				} else {
					chunks, err = lc.E2EE.EncryptGroupMessage(portalMid, fromMid, msg.Content.Body)
				}
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
			return nil, fmt.Errorf("failed to get peer key: %w", errPeer)
		}

		chunks, err = lc.E2EE.EncryptMessageV2Raw(portalMid, fromMid, myKeyID, peerPub, myRaw, peerRaw, contentType, payload)
	}

	if err != nil {
		return nil, fmt.Errorf("encrypt failed: %w", err)
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
		HasContent:      contentType != int(ContentText),
		ContentMetadata: contentMetadata,
	}

	lineMsg.Chunks = chunks

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
