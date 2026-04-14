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

	// Determine whether we need to send as plain text (peer/group has Letter Sealing off).
	plainText := false
	if lc.E2EE == nil {
		plainText = true
		lc.UserLogin.Bridge.Log.Warn().Msg("E2EE not initialized, sending as plain text")
	} else if isGroup {
		if lc.isGroupNoE2EE(portalMid) {
			plainText = true
		}
	} else {
		// 1:1 — probe peer key to determine E2EE support
		_, _, errPeer := lc.ensurePeerKey(ctx, portalMid)
		if errPeer != nil && line.IsNoUsableE2EEPublicKey(errPeer) {
			plainText = true
		} else if errPeer != nil {
			return nil, fmt.Errorf("failed to get peer key: %w", errPeer)
		}
	}

	var chunks []string
	var err error
	contentType := int(ContentText)
	contentMetadata := map[string]string{}
	if !plainText {
		contentMetadata["e2eeVersion"] = "2"
	}

	// For non-text messages, check with the server whether to use E2EE or plain media upload.
	// This must happen before media processing since it affects the upload path.
	useE2EEMedia := !plainText
	if useE2EEMedia && msg.Content.MsgType != event.MsgText {
		mediaContentType := contentTypeForMsgType(msg.Content.MsgType)
		if !lc.shouldUseE2EEMediaFlow(portalMid, mediaContentType) {
			lc.UserLogin.Bridge.Log.Info().
				Str("portal", portalMid).
				Int("content_type", mediaContentType).
				Msg("Server indicates plain media flow for this chat")
			useE2EEMedia = false
			plainText = true
			delete(contentMetadata, "e2eeVersion")
		}
	}

	// For plain text, we set lineMsg.Text directly; payload is used only for E2EE.
	var payload []byte
	var plainTextBody string // used when plainText == true for text messages

	// For plain media: we send the message first, then upload media to r/talk/m/{msgId}.
	var plainMediaData []byte // raw media data to upload after sending

	// For group chats, save original data in case E2EE encryption fails and we fall back to plain.
	var originalMediaData []byte

	switch msg.Content.MsgType {
	case event.MsgText:
		contentType = int(ContentText)
		if plainText {
			plainTextBody = msg.Content.Body
		} else {
			payload, err = json.Marshal(map[string]string{"text": msg.Content.Body})
			if err != nil {
				return nil, fmt.Errorf("failed to marshal text payload: %w", err)
			}
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

		if plainText {
			// Plain media: save data for post-send upload to r/talk/m/{msgId}
			plainMediaData = data

			_, thumbWidth, thumbHeight, err := generateThumbnail(data)
			if err != nil {
				lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to generate thumbnail, continuing without it")
			} else {
				mediaThumbInfo := map[string]interface{}{
					"width":  thumbWidth,
					"height": thumbHeight,
				}
				if thumbInfoJSON, err := json.Marshal(mediaThumbInfo); err == nil {
					contentMetadata["MEDIA_THUMB_INFO"] = string(thumbInfoJSON)
				}
			}

			contentMetadata["FILE_SIZE"] = fmt.Sprintf("%d", len(data))
			contentMetadata["contentType"] = fmt.Sprintf("%d", ContentImage)

			fileName := msg.Content.GetFileName()
			if fileName == "" {
				fileName = "image." + extension
			}
			contentMetadata["FILE_NAME"] = fileName

			mediaContentInfo := map[string]interface{}{
				"category":  "original",
				"fileSize":  len(data),
				"extension": extension,
			}
			if isAnimated {
				mediaContentInfo["animated"] = true
			}
			if mediaInfoJSON, err := json.Marshal(mediaContentInfo); err == nil {
				contentMetadata["MEDIA_CONTENT_INFO"] = string(mediaInfoJSON)
			}
		} else {
			// E2EE: encrypt, upload to OBS first, send with OID
			// Save original data for potential group E2EE fallback
			if isGroup {
				originalMediaData = data
			}

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

		if plainText {
			// Plain media: save data for post-send upload
			plainMediaData = data

			lc.UserLogin.Bridge.Log.Info().
				Str("file_name", fileName).
				Bool("plain_text", plainText).
				Int("original_size", len(data)).
				Msg("Prepared plain file message")
		} else {
			if isGroup {
				originalMediaData = data
			}

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
				Bool("plain_text", plainText).
				Int("upload_size", len(uploadData)).
				Int("original_size", len(data)).
				Msg("Prepared file message")
		}

	case event.MsgVideo:
		data, err := lc.UserLogin.Bridge.Bot.DownloadMedia(ctx, msg.Content.URL, msg.Content.File)
		if err != nil {
			return nil, fmt.Errorf("failed to download video from matrix: %w", err)
		}

		// Beeper sends GIFs as MsgVideo with fi.mau.gif=true — treat as animated image
		if msg.Content.Info != nil && msg.Content.Info.MauGIF {
			// Convert video (mp4/webm) to actual GIF format for LINE
			if !isAnimatedGif(data) {
				gifData, convErr := convertVideoToGIF(data)
				if convErr != nil {
					return nil, fmt.Errorf("failed to convert video to GIF: %w", convErr)
				}
				data = gifData
				lc.UserLogin.Bridge.Log.Info().
					Int("gif_size", len(data)).
					Msg("Converted video to GIF for LINE")
			}

			contentType = int(ContentImage)

			fileName := msg.Content.GetFileName()
			if fileName == "" {
				fileName = "image.gif"
			}
			contentMetadata["FILE_NAME"] = fileName
			contentMetadata["FILE_SIZE"] = fmt.Sprintf("%d", len(data))
			contentMetadata["contentType"] = fmt.Sprintf("%d", ContentImage)

			mediaContentInfo := map[string]interface{}{
				"category":  "original",
				"fileSize":  len(data),
				"extension": "gif",
				"animated":  true,
			}
			if mediaInfoJSON, err := json.Marshal(mediaContentInfo); err == nil {
				contentMetadata["MEDIA_CONTENT_INFO"] = string(mediaInfoJSON)
			}

			if plainText {
				plainMediaData = data

				_, thumbWidth, thumbHeight, err := generateThumbnail(data)
				if err != nil {
					lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to generate GIF thumbnail dimensions, continuing without it")
				} else {
					mediaThumbInfo := map[string]interface{}{
						"width":  thumbWidth,
						"height": thumbHeight,
					}
					if thumbInfoJSON, err := json.Marshal(mediaThumbInfo); err == nil {
						contentMetadata["MEDIA_THUMB_INFO"] = string(thumbInfoJSON)
					}
				}
			} else {
				if isGroup {
					originalMediaData = data
				}

				uploadData, keyMaterialB64, err := lc.encryptFileData(data)
				if err != nil {
					return nil, fmt.Errorf("failed to encrypt GIF data: %w", err)
				}

				oid, err := client.UploadOBS(uploadData)
				if err != nil {
					return nil, fmt.Errorf("failed to upload GIF to OBS: %w", err)
				}

				thumbnailData, thumbWidth, thumbHeight, err := generateThumbnail(data)
				if err != nil {
					lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to generate GIF thumbnail, continuing without it")
				} else if thumbToUpload, err := encryptThumbnail(thumbnailData, keyMaterialB64); err != nil {
					lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to encrypt GIF thumbnail, continuing without it")
				} else {
					previewOID := fmt.Sprintf("%s__ud-preview", oid)
					if err := client.UploadOBSWithOID(thumbToUpload, previewOID); err != nil {
						lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to upload GIF preview, continuing without it")
					} else {
						mediaThumbInfo := map[string]interface{}{
							"width":  thumbWidth,
							"height": thumbHeight,
						}
						if thumbInfoJSON, err := json.Marshal(mediaThumbInfo); err == nil {
							contentMetadata["MEDIA_THUMB_INFO"] = string(thumbInfoJSON)
						}
					}
				}

				contentMetadata["OID"] = oid
				contentMetadata["SID"] = "emi"
				contentMetadata["ENC_KM"] = keyMaterialB64

				imgPayload := map[string]string{"keyMaterial": keyMaterialB64}
				payload, _ = json.Marshal(imgPayload)
			}
			break
		}

		contentType = int(ContentVideo)
		contentMetadata["FILE_SIZE"] = fmt.Sprintf("%d", len(data))
		contentMetadata["contentType"] = fmt.Sprintf("%d", ContentVideo)

		if msg.Content.Info.Duration > 0 {
			contentMetadata["DURATION"] = fmt.Sprintf("%d", msg.Content.Info.Duration)
		}

		if plainText {
			// Plain media: save data for post-send upload
			plainMediaData = data

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
				mediaThumbInfo := map[string]interface{}{
					"width":  thumbWidth,
					"height": thumbHeight,
				}
				if thumbInfoJSON, err := json.Marshal(mediaThumbInfo); err == nil {
					contentMetadata["MEDIA_THUMB_INFO"] = string(thumbInfoJSON)
				}
			}

			lc.UserLogin.Bridge.Log.Info().
				Bool("plain_text", plainText).
				Int("original_size", len(data)).
				Msg("Prepared plain video message")
		} else {
			if isGroup {
				originalMediaData = data
			}

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
				Bool("plain_text", plainText).
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

		if plainText {
			plainMediaData = data
		} else {
			if isGroup {
				originalMediaData = data
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
		}

	default:
		return nil, fmt.Errorf("message type %s not implemented", msg.Content.MsgType)
	}

	// Encryption phase — skip entirely for plain text
	if !plainText {
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
				} else if line.IsNoUsableE2EEGroupKey(errFetch) || line.IsNoUsableE2EEGroupKey(err) {
					// Group has no E2EE keys — fall back to plain text
					lc.markGroupNoE2EE(portalMid)
					lc.UserLogin.Bridge.Log.Info().Str("chat_mid", portalMid).Msg("Group has no E2EE keys, falling back to plain text")
					plainText = true
					chunks = nil
					err = nil
					delete(contentMetadata, "e2eeVersion")
					if contentType == int(ContentText) {
						plainTextBody = msg.Content.Body
					} else {
						// Media was uploaded to E2EE endpoint — need to re-upload via plain after sending
						delete(contentMetadata, "OID")
						delete(contentMetadata, "SID")
						delete(contentMetadata, "ENC_KM")
						plainMediaData = originalMediaData
					}
				}
			}
		} else {
			// 1-1 Encryption (peer key already fetched above)
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
	}

	if plainText {
		lc.UserLogin.Bridge.Log.Info().Str("portal", portalMid).Int("content_type", contentType).Msg("Sending plain text message (no E2EE)")
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

	if plainText {
		lineMsg.Text = plainTextBody
	} else {
		lineMsg.Chunks = chunks
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

	// For plain media: upload media to r/talk/m/{serverMessageId} after sending
	if plainText && plainMediaData != nil && sentMsg.ID != "" {
		obsType := "image"
		switch contentType {
		case int(ContentVideo):
			obsType = "video"
		case int(ContentAudio):
			obsType = "audio"
		case int(ContentFile):
			obsType = "file"
		}

		if err := client.UploadOBSPlain(plainMediaData, sentMsg.ID, obsType, contentMetadata["FILE_NAME"]); err != nil {
			return nil, fmt.Errorf("failed to upload plain media to OBS: %w", err)
		}
		lc.UserLogin.Bridge.Log.Info().
			Str("message_id", sentMsg.ID).
			Str("obs_type", obsType).
			Int("media_size", len(plainMediaData)).
			Msg("Uploaded plain media after sending")

		// Skip plain thumbnail upload — LINE generates thumbnails server-side
		// for media uploaded to the r/talk/m/ endpoint.
	}

	return &bridgev2.MatrixMessageResponse{
		DB: &database.Message{
			ID:        networkid.MessageID(sentMsg.ID),
			SenderID:  makeUserID(string(lc.UserLogin.ID)),
			Timestamp: time.UnixMilli(now),
		},
	}, nil
}

func contentTypeForMsgType(msgType event.MessageType) int {
	switch msgType {
	case event.MsgImage:
		return int(ContentImage)
	case event.MsgVideo:
		return int(ContentVideo)
	case event.MsgAudio:
		return int(ContentAudio)
	case event.MsgFile:
		return int(ContentFile)
	default:
		return int(ContentText)
	}
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

	err := client.UnsendMessage(int64(reqSeq), string(msg.TargetMessage.ID))
	if err != nil && strings.Contains(err.Error(), "message too old") {
		return bridgev2.WrapErrorInStatus(fmt.Errorf("message too old to unsend on LINE (24h limit)")).
			WithStatus(event.MessageStatusFail).
			WithErrorReason(event.MessageStatusTooOld).
			WithIsCertain(true).
			WithSendNotice(true)
	}
	return err
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
