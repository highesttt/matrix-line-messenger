package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/simplevent"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/highesttt/matrix-line-messenger/pkg/e2ee"
	"github.com/highesttt/matrix-line-messenger/pkg/line"
)

func (lc *LineClient) queueIncomingMessage(msg *line.Message, opType int) {
	senderID := makeUserID(msg.From)

	portalIDStr := msg.From
	// If I sent it (Type 25), the portal is the recipient (msg.To)
	if OperationType(opType) == OpSendMessage {
		portalIDStr = msg.To
	}
	// If it's a group (ToType 1 or 2), the portal is msg.To
	if ToType(msg.ToType) == ToRoom || ToType(msg.ToType) == ToGroup {
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

			if ToType(msg.ToType) == ToRoom || ToType(msg.ToType) == ToGroup {
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
					if _, _, errKey := lc.E2EE.MyKeyIDs(); errKey != nil {
						lc.UserLogin.Bridge.Log.Error().Msg("E2EE own key not loaded — cannot decrypt any messages. Re-login required.")
					} else {
						peerMid := msg.From
						if peerMid == lc.Mid || peerMid == string(lc.UserLogin.ID) {
							peerMid = msg.To
						}
						if _, _, errPeer := lc.ensurePeerKey(context.Background(), peerMid); errPeer != nil {
							lc.UserLogin.Bridge.Log.Warn().Err(errPeer).Str("peer", peerMid).Msg("Failed to force-fetch peer key for retry")
						}
						if ptRetry, errRetry := lc.E2EE.DecryptMessageV2(msg); errRetry == nil {
							bodyText = ptRetry
						} else {
							lc.UserLogin.Bridge.Log.Warn().Err(errRetry).Msg("DecryptMessageV2 failed on retry")
						}
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

	var ts time.Time
	if tsInt, err := msg.CreatedTime.Int64(); err != nil {
		lc.UserLogin.Bridge.Log.Warn().
			Err(err).
			Str("msg_id", msg.ID).
			Msg("Failed to convert message CreatedTime to int64, using current time")
		ts = time.Now()
	} else {
		ts = time.UnixMilli(tsInt)
		if ts.IsZero() {
			ts = time.Now()
		}
	}

	lc.UserLogin.Bridge.QueueRemoteEvent(lc.UserLogin, &simplevent.Message[line.Message]{
		EventMeta: simplevent.EventMeta{
			Type:         bridgev2.RemoteEventMessage,
			LogContext:   func(c zerolog.Context) zerolog.Context { return c.Str("msg_id", msg.ID) },
			PortalKey:    portalKey,
			CreatePortal: true,
			Sender:       bridgev2.EventSender{Sender: senderID, IsFromMe: OperationType(opType) == OpSendMessage},
			Timestamp:    ts,
		},
		Data: *msg,
		ID:   networkid.MessageID(msg.ID),
		ConvertMessageFunc: func(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, data line.Message) (*bridgev2.ConvertedMessage, error) {
			replyRelatesTo := lc.resolveReplyRelatesTo(ctx, &data)
			// Handle Images
			client := line.NewClient(lc.AccessToken)
			if ContentType(data.ContentType) == ContentImage {
				oid := data.ContentMetadata["OID"]

				if oid != "" {
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

			if ContentType(data.ContentType) == ContentVideo {
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

			// Handle File type
			if ContentType(data.ContentType) == ContentFile {
				oid := data.ContentMetadata["OID"]
				if oid == "" && decryptedBody != "" && strings.Contains(decryptedBody, "fileName") {
					lc.UserLogin.Bridge.Log.Debug().Msg("File message with encrypted payload, OID in metadata")
				}

				if oid != "" {
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

			// Handle Sticker
			if ContentType(data.ContentType) == ContentSticker {
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
							if strings.Contains(stkOpt, "A") {
								stkData = forceAPNGLoop(stkData)
							}
							mxc, file, err := intent.UploadMedia(ctx, portal.MXID, stkData, "sticker.png", "image/png")
							if err != nil {
								lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to upload sticker to Matrix")
							} else {
								return &bridgev2.ConvertedMessage{
									Parts: []*bridgev2.ConvertedMessagePart{
										{
											Type: event.EventMessage,
											Content: &event.MessageEventContent{
												MsgType: event.MsgImage,
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
			content := &event.MessageEventContent{
				MsgType:   event.MsgText,
				Body:      unwrappedText,
				RelatesTo: replyRelatesTo,
			}

			urlRegex := regexp.MustCompile(`(https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(/[^\s]*)?`)
			if match := urlRegex.FindString(unwrappedText); match != "" {
				match = strings.TrimRight(match, ".,;:!?")
				requestURL := match
				if !strings.HasPrefix(match, "http") {
					requestURL = "https://" + match
				}
				if info, err := client.GetPageInfo(requestURL); err == nil {
					preview := &event.BeeperLinkPreview{
						MatchedURL: match,
						LinkPreview: event.LinkPreview{
							Title:        info.Title,
							Description:  info.Summary,
							CanonicalURL: info.Domain,
						},
					}
					if info.Image != "" && info.Obs.CDN != "" {
						preview.ImageURL = id.ContentURIString(info.Obs.CDN + info.Image)
					}
					content.BeeperLinkPreviews = []*event.BeeperLinkPreview{preview}
				}
			}

			return &bridgev2.ConvertedMessage{
				Parts: []*bridgev2.ConvertedMessagePart{
					{
						Type:    event.EventMessage,
						Content: content,
					},
				},
			}, nil
		},
	})
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
