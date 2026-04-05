package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.mau.fi/util/ptr"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/simplevent"
	"maunium.net/go/mautrix/bridgev2/status"
	"maunium.net/go/mautrix/event"

	"github.com/highesttt/matrix-line-messenger/pkg/line"
)

func (lc *LineClient) syncDMChats(ctx context.Context) {
	opts := line.MessageBoxesOptions{
		ActiveOnly:                     true,
		MessageBoxCountLimit:           100,
		WithUnreadCount:                false,
		LastMessagesPerMessageBoxCount: 0,
	}

	var res *line.MessageBoxesResponse
	_, err := lc.callWithRecovery(ctx, func(c *line.Client) error {
		var e error
		res, e = c.GetMessageBoxes(opts)
		return e
	})
	if err != nil {
		lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to fetch message boxes for DM sync")
		return
	}

	for _, box := range res.MessageBoxes {
		mid := box.ID
		lowerMid := strings.ToLower(mid)
		// Skip group chats — they're handled by syncChats
		if strings.HasPrefix(lowerMid, "c") || strings.HasPrefix(lowerMid, "r") {
			continue
		}

		contact := lc.getContact(ctx, mid)
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
		chatName := contact.EffectiveDisplayName()
		portalKey := networkid.PortalKey{ID: makePortalID(mid), Receiver: lc.UserLogin.ID}
		lc.UserLogin.Bridge.QueueRemoteEvent(lc.UserLogin, &simplevent.ChatResync{
			EventMeta: simplevent.EventMeta{
				Type:      bridgev2.RemoteEventChatResync,
				PortalKey: portalKey,
				Timestamp: time.Now(),
			},
			ChatInfo: &bridgev2.ChatInfo{
				Type:   &dmType,
				Name:   &chatName,
				Avatar: avatar,
				Members: &bridgev2.ChatMemberList{
					IsFull:                     true,
					ExcludeChangesFromTimeline: true,
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
								Sender: makeUserID(mid),
							},
							Membership: event.MembershipJoin,
							PowerLevel: ptr.Ptr(0),
						},
					},
				},
				ExcludeChangesFromTimeline: true,
			},
		})
	}
}

func (lc *LineClient) prefetchMessages(ctx context.Context) {
	opts := line.MessageBoxesOptions{
		ActiveOnly:                     true,
		MessageBoxCountLimit:           100,
		WithUnreadCount:                true,
		LastMessagesPerMessageBoxCount: 0,
	}

	var res *line.MessageBoxesResponse
	client, err := lc.callWithRecovery(ctx, func(c *line.Client) error {
		var e error
		res, e = c.GetMessageBoxes(opts)
		return e
	})
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
	var midsResp *line.GetAllChatMidsResponse
	_, err := lc.callWithRecovery(ctx, func(c *line.Client) error {
		var e error
		midsResp, e = c.GetAllChatMids(true, true)
		return e
	})
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
		var chatsResp *line.GetChatsResponse
		_, err := lc.callWithRecovery(ctx, func(c *line.Client) error {
			var e error
			chatsResp, e = c.GetChats(batch, true, true)
			return e
		})
		if err != nil {
			lc.UserLogin.Bridge.Log.Warn().Err(err).Msg("Failed to fetch batch of chats")
			continue
		}

		for _, chat := range chatsResp.Chats {
			portalKey := networkid.PortalKey{ID: makePortalID(chat.ChatMid), Receiver: lc.UserLogin.ID}

			info := lc.chatToChatInfo(&chat, true)
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

func (lc *LineClient) chatToChatInfo(chat *line.Chat, excludeFromTimeline bool) *bridgev2.ChatInfo {
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
			if m == lc.Mid || m == string(lc.UserLogin.ID) || strings.HasPrefix(m, "c") || strings.HasPrefix(m, "r") {
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
			if m == lc.Mid || m == string(lc.UserLogin.ID) || strings.HasPrefix(m, "c") || strings.HasPrefix(m, "r") {
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
		Type:   &ct,
		Name:   &name,
		Avatar: avatar,
		Members: &bridgev2.ChatMemberList{
			IsFull:                     true,
			Members:                    members,
			ExcludeChangesFromTimeline: excludeFromTimeline,
		},
		ExcludeChangesFromTimeline: excludeFromTimeline,
	}
}

func (lc *LineClient) generateNameFromMembers(members map[string]bool) string {
	var names []string
	count := 0
	for mid := range members {
		if mid == string(lc.UserLogin.ID) || mid == lc.Mid || strings.HasPrefix(mid, "c") || strings.HasPrefix(mid, "r") {
			continue
		}
		if cached, ok := lc.contactCache[mid]; ok && cached.DisplayName != "" {
			names = append(names, cached.DisplayName)
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

	lc.UserLogin.Bridge.Log.Info().Msg("Starting LINE SSE loop...")
	var rev int64
	client, err := lc.callWithRecovery(ctx, func(c *line.Client) error {
		var e error
		rev, e = c.GetLastOpRevision()
		return e
	})
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
			go lc.syncDMChats(ctx)
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

					if lc.isTokenError(err) {
						if errRecover := lc.recoverToken(ctx); errRecover != nil {
							lc.UserLogin.Bridge.Log.Error().Err(errRecover).Msg("Failed to recover session, stopping poll loop")
							lc.UserLogin.BridgeState.Send(status.BridgeState{
								StateEvent: status.StateBadCredentials,
								Error:      "line-logged-out",
								Message:    "LINE session was invalidated (logged out by another client). Please re-authenticate the bridge.",
							})
							return
						}
						client = line.NewClient(lc.AccessToken)
					}
				}
				time.Sleep(3 * time.Second)
			}
		}
	}
}

