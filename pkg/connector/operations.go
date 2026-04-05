package connector

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/simplevent"
	"maunium.net/go/mautrix/id"

	"github.com/highesttt/matrix-line-messenger/pkg/line"
)

func (lc *LineClient) handleOperation(ctx context.Context, op line.Operation) {
	// Type 25 = SEND_MESSAGE (Message sent by you from another device)
	// Type 26 = RECEIVE_MESSAGE (Message received from another user)

	if OperationType(op.Type) == OpContactUpdate {
		mid := op.Param1
		delete(lc.contactCache, mid)
		contact := lc.getContact(ctx, mid)
		name := contact.EffectiveDisplayName()
		lc.UserLogin.Bridge.Log.Info().Str("mid", mid).Str("name", name).Msg("Contact updated")
		ghost, err := lc.UserLogin.Bridge.GetGhostByID(ctx, makeUserID(mid))
		if err == nil && ghost != nil {
			ghost.UpdateInfo(ctx, &bridgev2.UserInfo{
				Identifiers: []string{mid},
				Name:        &name,
			})
		}
		// Also update the DM portal room name
		var avatar *bridgev2.Avatar
		if contact.PicturePath != "" {
			picturePath := contact.PicturePath
			avatar = &bridgev2.Avatar{
				ID: networkid.AvatarID(picturePath),
				Get: func(ctx context.Context) ([]byte, error) {
					return lc.GetAvatar(ctx, networkid.AvatarID(picturePath))
				},
			}
		}
		dmType := database.RoomTypeDM
		portalKey := networkid.PortalKey{ID: makePortalID(mid), Receiver: lc.UserLogin.ID}
		lc.UserLogin.Bridge.QueueRemoteEvent(lc.UserLogin, &simplevent.ChatResync{
			EventMeta: simplevent.EventMeta{
				Type:      bridgev2.RemoteEventChatResync,
				PortalKey: portalKey,
				Timestamp: time.Now(),
			},
			ChatInfo: &bridgev2.ChatInfo{
				Type:   &dmType,
				Name:   &name,
				Avatar: avatar,
			},
		})
		return
	}

	if OperationType(op.Type) == OpChatUpdate2 || OperationType(op.Type) == OpChatUpdate {
		lc.UserLogin.Bridge.Log.Info().Str("chat_mid", op.Param1).Int("op_type", op.Type).Msg("Received chat update operation")
		go lc.syncSingleChat(context.Background(), op)
	}

	if OperationType(op.Type) == OpReadReceipt {
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

	if OperationType(op.Type) == OpUnsendLocal || OperationType(op.Type) == OpUnsendRemote {
		chatMid := op.Param1
		msgID := op.Param2
		lc.UserLogin.Bridge.Log.Info().Str("msg_id", msgID).Str("chat_mid", chatMid).Int("op_type", op.Type).Msg("Received unsend operation")

		ts, _ := op.CreatedTime.Int64()
		lc.UserLogin.Bridge.QueueRemoteEvent(lc.UserLogin, &simplevent.MessageRemove{
			EventMeta: simplevent.EventMeta{
				Type:      bridgev2.RemoteEventMessageRemove,
				PortalKey: networkid.PortalKey{ID: makePortalID(chatMid), Receiver: lc.UserLogin.ID},
				Timestamp: time.UnixMilli(ts),
			},
			TargetMessage: networkid.MessageID(msgID),
		})
	}

	if OperationType(op.Type) == OpReaction {
		go func() {
			param2, err := line.ParseReactionParam2(op.Param2)
			if err != nil {
				lc.UserLogin.Bridge.Log.Error().Err(err).Msg("Failed to parse reaction param2")
				return
			}
			if param2.Curr == nil || param2.Curr.PaidReactionType == nil {
				lc.UserLogin.Bridge.Log.Error().Msg("No current reaction or paid reaction type found")
				return
			}

			prt := param2.Curr.PaidReactionType
			url := fmt.Sprintf("https://stickershop.line-scdn.net/sticonshop/v1/sticon/%s/android/%s.png", prt.ProductID, prt.EmojiID)

			resp, err := lc.HTTPClient.Get(url)
			if err != nil {
				lc.UserLogin.Bridge.Log.Error().Err(err).Str("url", url).Msg("Failed to download reaction image")
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				lc.UserLogin.Bridge.Log.Error().Int("status_code", resp.StatusCode).Str("url", url).Msg("Failed to download reaction image: bad status code")
				return
			}

			data, err := io.ReadAll(resp.Body)
			if err != nil {
				lc.UserLogin.Bridge.Log.Error().Err(err).Msg("Failed to read reaction image body")
				return
			}

			mimeType := resp.Header.Get("Content-Type")
			if mimeType == "" {
				mimeType = "image/png"
			}

			senderID := makeUserID(op.Param3)
			ghost, err := lc.UserLogin.Bridge.GetGhostByID(ctx, senderID)
			if err != nil {
				lc.UserLogin.Bridge.Log.Error().Err(err).Msg("Failed to get ghost for reaction sender")
				return
			}

			portalKey := networkid.PortalKey{ID: makePortalID(param2.ChatMid), Receiver: lc.UserLogin.ID}
			portal, err := lc.UserLogin.Bridge.GetPortalByKey(ctx, portalKey)
			if err != nil || portal == nil {
				lc.UserLogin.Bridge.Log.Error().Err(err).Str("chat_mid", param2.ChatMid).Msg("Failed to get portal for reaction")
				return
			}

			if portal.MXID == "" {
				lc.UserLogin.Bridge.Log.Error().Msg("Portal MXID is empty, cannot upload media")
				return
			}

			mxc, uploadedFile, err := ghost.Intent.UploadMedia(ctx, "", data, "reaction.png", mimeType)
			if err != nil {
				lc.UserLogin.Bridge.Log.Error().Err(err).Int("data_len", len(data)).Msg("Failed to upload reaction image to Matrix")
				return
			}
			if mxc == "" && uploadedFile != nil && uploadedFile.URL != "" {
				mxc = id.ContentURIString(uploadedFile.URL)
			}
			if mxc == "" {
				lc.UserLogin.Bridge.Log.Error().Interface("uploaded_file", uploadedFile).Msg("UploadMedia returned empty MXC URI")
				return
			}

			ts, _ := op.CreatedTime.Int64()
			lc.UserLogin.Bridge.QueueRemoteEvent(lc.UserLogin, &simplevent.Reaction{
				EventMeta: simplevent.EventMeta{
					Type:      bridgev2.RemoteEventReaction,
					PortalKey: portalKey,
					Timestamp: time.UnixMilli(ts),
					Sender:    bridgev2.EventSender{Sender: senderID},
				},
				TargetMessage: networkid.MessageID(op.Param1),
				Emoji:         string(mxc),
			})
		}()
	}

	if OperationType(op.Type) == OpSendMessage {
		lc.reqSeqMu.Lock()
		_, ok := lc.sentReqSeqs[op.ReqSeq]
		if ok {
			delete(lc.sentReqSeqs, op.ReqSeq)
			lc.reqSeqMu.Unlock()
			return
		}
		lc.reqSeqMu.Unlock()
	}

	if (OperationType(op.Type) == OpSendMessage || OperationType(op.Type) == OpReceiveMessage) && op.Message != nil {
		// Handle group rename system messages (contentType=18, LOC_KEY="C_PN")
		if op.Message.ContentType == 18 {
			if op.Message.ContentMetadata != nil && op.Message.ContentMetadata["LOC_KEY"] == "C_PN" {
				lc.handleGroupRename(op)
			}
			return
		}
		lc.queueIncomingMessage(op.Message, op.Type)
		return
	}

	lc.UserLogin.Bridge.Log.Debug().
		Int("op_type", op.Type).
		Str("param1", op.Param1).
		Str("param2", op.Param2).
		Str("param3", op.Param3).
		Msg("Unhandled SSE operation")
}

func (lc *LineClient) syncSingleChat(ctx context.Context, op line.Operation) {
	chatMid := op.Param1
	var chatsResp *line.GetChatsResponse
	_, err := lc.callWithRecovery(ctx, func(c *line.Client) error {
		var e error
		chatsResp, e = c.GetChats([]string{chatMid}, true, true)
		return e
	})
	if err != nil {
		lc.UserLogin.Bridge.Log.Warn().Err(err).Str("chat_mid", chatMid).Msg("Failed to fetch chat info")
		return
	}
	if len(chatsResp.Chats) == 0 {
		return
	}
	chat := chatsResp.Chats[0]
	portalKey := networkid.PortalKey{ID: makePortalID(chat.ChatMid), Receiver: lc.UserLogin.ID}

	var avatar *bridgev2.Avatar
	if chat.PicturePath != "" {
		avatar = &bridgev2.Avatar{
			ID: networkid.AvatarID(chat.PicturePath),
			Get: func(ctx context.Context) ([]byte, error) {
				return lc.GetAvatar(ctx, networkid.AvatarID(chat.PicturePath))
			},
		}
	}

	// Use ChatInfoChange to only update avatar (and other non-name metadata).
	// Name updates are handled by handleGroupRename from contentType=18 messages,
	// which has the correct new name from LOC_ARGS.
	// No sender is set on either event to avoid ghost creation/invite issues.
	lc.UserLogin.Bridge.QueueRemoteEvent(lc.UserLogin, &simplevent.ChatInfoChange{
		EventMeta: simplevent.EventMeta{
			Type:      bridgev2.RemoteEventChatInfoChange,
			PortalKey: portalKey,
			Timestamp: time.Now(),
		},
		ChatInfoChange: &bridgev2.ChatInfoChange{
			ChatInfo: &bridgev2.ChatInfo{
				Avatar: avatar,
			},
		},
	})
}

func (lc *LineClient) handleGroupRename(op line.Operation) {
	msg := op.Message
	locArgs := msg.ContentMetadata["LOC_ARGS"]
	// LOC_ARGS format: "<renamer_mid>\x1e<new_name>"
	parts := strings.SplitN(locArgs, "\x1e", 2)
	if len(parts) < 2 || parts[1] == "" {
		return
	}
	newName := parts[1]

	portalKey := networkid.PortalKey{ID: makePortalID(msg.To), Receiver: lc.UserLogin.ID}

	ts, _ := msg.CreatedTime.Int64()
	if ts == 0 {
		ts = time.Now().UnixMilli()
	}

	lc.UserLogin.Bridge.Log.Debug().
		Str("new_name", newName).
		Str("chat_mid", msg.To).
		Str("from", msg.From).
		Msg("Handling group rename")

	lc.UserLogin.Bridge.QueueRemoteEvent(lc.UserLogin, &simplevent.ChatInfoChange{
		EventMeta: simplevent.EventMeta{
			Type:      bridgev2.RemoteEventChatInfoChange,
			PortalKey: portalKey,
			Timestamp: time.UnixMilli(ts),
		},
		ChatInfoChange: &bridgev2.ChatInfoChange{
			ChatInfo: &bridgev2.ChatInfo{
				Name: &newName,
			},
		},
	})
}
