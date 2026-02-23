package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"go.mau.fi/util/ptr"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/simplevent"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/highesttt/matrix-line-messenger/pkg/line"
)

func (lc *LineClient) prefetchMessages(ctx context.Context) {
	client := line.NewClient(lc.AccessToken)
	opts := line.MessageBoxesOptions{
		ActiveOnly:                     true,
		MessageBoxCountLimit:           100,
		WithUnreadCount:                true,
		LastMessagesPerMessageBoxCount: 0,
	}

	res, err := client.GetMessageBoxes(opts)
	if err != nil && lc.isRefreshRequired(err) {
		if errRefresh := lc.refreshAndSave(ctx); errRefresh == nil {
			client = line.NewClient(lc.AccessToken)
			res, err = client.GetMessageBoxes(opts)
		}
	}
	if err != nil {
		lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to prefetch message boxes")
		return
	}

	for _, box := range res.MessageBoxes {
		// Fetch recent messages for all active chats to ensure history is populated
		msgs, err := client.GetRecentMessagesV2(box.ID, 50)
		if err != nil {
			lc.UserLogin.Bridge.Log.Warn().Err(err).Str("chat_mid", box.ID).Msg("Failed to fetch recent messages")
			continue
		}

		// Reverse messages to process oldest first
		for i := len(msgs) - 1; i >= 0; i-- {
			msg := msgs[i]

			existing, err := lc.UserLogin.Bridge.DB.Message.GetPartByID(ctx, lc.UserLogin.ID, networkid.MessageID(msg.ID), "")
			if err == nil && existing != nil {
				continue
			}

			opType := OpReceiveMessage
			if msg.From == lc.Mid {
				opType = OpSendMessage
			}
			lc.queueIncomingMessage(msg, int(opType))
		}
	}
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

	ct := database.RoomTypeGroupDM
	if chat.Extra.GroupExtra == nil {
		ct = database.RoomTypeDM
	}

	return &bridgev2.ChatInfo{
		Type:    &ct,
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
	rev, err := client.GetLastOpRevision()
	if err != nil && lc.isRefreshRequired(err) {
		if errRefresh := lc.refreshAndSave(ctx); errRefresh == nil {
			client = line.NewClient(lc.AccessToken)
			rev, err = client.GetLastOpRevision()
		} else {
			lc.UserLogin.Bridge.Log.Warn().Err(errRefresh).Msg("Failed to refresh token for getLastOpRevision")
		}
	}
	if err != nil {
		lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to get last op revision")
	} else {
		localRev = rev
		lc.UserLogin.Bridge.Log.Info().Int64("local_rev", localRev).Msg("Seeded local revision from getLastOpRevision")
	}

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
			go lc.syncChats(ctx)
			go lc.prefetchMessages(ctx)
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

func (lc *LineClient) handleOperation(ctx context.Context, op line.Operation) {
	// Type 25 = SEND_MESSAGE (Message sent by you from another device)
	// Type 26 = RECEIVE_MESSAGE (Message received from another user)

	if OperationType(op.Type) == OpChatUpdate2 || OperationType(op.Type) == OpChatUpdate {
		lc.UserLogin.Bridge.Log.Info().Str("chat_mid", op.Param1).Int("op_type", op.Type).Msg("Received chat update operation")
		go lc.syncSingleChat(context.Background(), op.Param1)
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
