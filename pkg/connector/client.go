package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/highesttt/mautrix-line-messenger/pkg/line"
	"github.com/rs/zerolog"
	"go.mau.fi/util/ptr"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/simplevent"
	"maunium.net/go/mautrix/bridgev2/status"
	"maunium.net/go/mautrix/event"
)

type LineClient struct {
	UserLogin   *bridgev2.UserLogin
	AccessToken string
	HTTPClient  *http.Client
}

var _ bridgev2.NetworkAPI = (*LineClient)(nil)

func (lc *LineClient) Connect(ctx context.Context) {
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

	lc.UserLogin.BridgeState.Send(status.BridgeState{
		StateEvent: status.StateConnected,
	})

	go lc.pollLoop(ctx)
}

// Temporary structs to parse the poll response
type PollResponse struct {
	Operations []line.Operation `json:"operations"`
}

func (lc *LineClient) parseOperations(body []byte) ([]line.Operation, int64, error) {
	var resp PollResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, 0, nil
	}

	var maxRev int64
	for _, op := range resp.Operations {
		if rev, err := op.Revision.Int64(); err == nil && rev > maxRev {
			maxRev = rev
		}
	}
	return resp.Operations, maxRev, nil
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
				}
				time.Sleep(3 * time.Second)
			}
		}
	}
}

func (lc *LineClient) handleOperation(ctx context.Context, op line.Operation) {
	// Type 25 = SEND_MESSAGE (Message sent by you from another device)
	// Type 26 = RECEIVE_MESSAGE (Message received from another user)

	// !FIX: My messages from other devices are showing up as seperate, new users
	if (op.Type == 25 || op.Type == 26) && op.Message != nil {
		lc.queueIncomingMessage(op.Message, op.Type)
	}
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
		bodyText = "[Encrypted Message]"
	}

	lc.UserLogin.Bridge.Log.Debug().Str("msg_id", msg.ID).Str("from", msg.From).Str("to", msg.To).Int("opType", opType).Msg("Queueing incoming LINE message")

	lc.UserLogin.Bridge.QueueRemoteEvent(lc.UserLogin, &simplevent.Message[line.Message]{
		EventMeta: simplevent.EventMeta{
			Type:         bridgev2.RemoteEventMessage,
			LogContext:   func(c zerolog.Context) zerolog.Context { return c.Str("msg_id", msg.ID) },
			PortalKey:    portalKey,
			CreatePortal: true,
			Sender:       bridgev2.EventSender{Sender: senderID},
			Timestamp:    time.Now(),
		},
		Data: *msg,
		ID:   networkid.MessageID(msg.ID),
		ConvertMessageFunc: func(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, data line.Message) (*bridgev2.ConvertedMessage, error) {
			return &bridgev2.ConvertedMessage{
				Parts: []*bridgev2.ConvertedMessagePart{
					{
						Type: event.EventMessage,
						Content: &event.MessageEventContent{
							MsgType: event.MsgText,
							Body:    bodyText,
						},
					},
				},
			}, nil
		},
	})
}

func (lc *LineClient) Disconnect() {}

func (lc *LineClient) IsLoggedIn() bool { return lc.AccessToken != "" }

func (lc *LineClient) LogoutRemote(ctx context.Context) {}

func (lc *LineClient) GetCapabilities(ctx context.Context, portal *bridgev2.Portal) *event.RoomFeatures {
	return &event.RoomFeatures{MaxTextLength: 5000}
}

func makeUserID(userID string) networkid.UserID { return networkid.UserID(userID) }

func makePortalID(userID string) networkid.PortalID { return networkid.PortalID(userID) }

func (lc *LineClient) IsThisUser(ctx context.Context, userID networkid.UserID) bool {
	return userID == networkid.UserID(lc.UserLogin.ID)
}

func (lc *LineClient) GetChatInfo(ctx context.Context, portal *bridgev2.Portal) (*bridgev2.ChatInfo, error) {
	return &bridgev2.ChatInfo{
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
	return &bridgev2.UserInfo{Identifiers: []string{string(ghost.ID)}, Name: ptr.Ptr(string(ghost.ID))}, nil
}

type lineWebhook struct {
	Events []lineEvent `json:"events"`
}

type lineEvent struct {
	Type       string       `json:"type"`
	ReplyToken string       `json:"replyToken"`
	Source     lineSource   `json:"source"`
	Timestamp  int64        `json:"timestamp"`
	Message    *lineMessage `json:"message"`
}

type lineSource struct {
	Type   string `json:"type"`
	UserID string `json:"userId"`
}

type lineMessage struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Text string `json:"text"`
}

// !FIX : Temporary function to attempt to validate signature
func (lc *LineClient) ValidateSignature(body []byte, signature string) bool {
	return false

	// mac := hmac.New(sha256.New, []byte(line.ChannelSecret))
	// mac.Write(body)
	// expected := mac.Sum(nil)
	// decoded, err := base64.StdEncoding.DecodeString(signature)
	// if err != nil {
	// 	return false
	// }
	// return hmac.Equal(expected, decoded)
}

func (lc *LineClient) HandleWebhook(ctx context.Context, body []byte) error {
	var payload lineWebhook
	if err := json.Unmarshal(body, &payload); err != nil {
		return err
	}
	for _, ev := range payload.Events {
		if ev.Type != "message" || ev.Message == nil || ev.Message.Type != "text" {
			continue
		}
		lc.queueIncoming(ev)
	}
	return nil
}

func (lc *LineClient) queueIncoming(ev lineEvent) {
	userID := makeUserID(ev.Source.UserID)
	portalID := networkid.PortalKey{ID: makePortalID(ev.Source.UserID), Receiver: lc.UserLogin.ID}
	lc.UserLogin.Bridge.QueueRemoteEvent(lc.UserLogin, &simplevent.Message[lineEvent]{
		EventMeta: simplevent.EventMeta{
			Type: bridgev2.RemoteEventMessage,
			LogContext: func(c zerolog.Context) zerolog.Context {
				return c.Str("from", ev.Source.UserID).Str("message_id", ev.Message.ID)
			},
			PortalKey:    portalID,
			CreatePortal: true,
			Sender:       bridgev2.EventSender{Sender: userID},
			Timestamp:    time.UnixMilli(ev.Timestamp),
		},
		Data:               ev,
		ID:                 networkid.MessageID(ev.Message.ID),
		ConvertMessageFunc: lc.convertMessage,
	})
}

func (lc *LineClient) convertMessage(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, ev lineEvent) (*bridgev2.ConvertedMessage, error) {
	return &bridgev2.ConvertedMessage{Parts: []*bridgev2.ConvertedMessagePart{{Type: event.EventMessage, Content: &event.MessageEventContent{MsgType: event.MsgText, Body: ev.Message.Text}}}}, nil
}

func (lc *LineClient) HandleMatrixMessage(ctx context.Context, msg *bridgev2.MatrixMessage) (*bridgev2.MatrixMessageResponse, error) {
	_ = line.NewClient(lc.AccessToken)
	_ = string(msg.Portal.ID)

	switch msg.Content.MsgType {
	case event.MsgText:
		return nil, fmt.Errorf("failed to send text message: not yet implemented")
	case event.MsgImage, event.MsgVideo, event.MsgAudio, event.MsgFile:
		return nil, fmt.Errorf("media messages are not yet implemented")
	default:
		return nil, fmt.Errorf("unsupported message type: %s", msg.Content.MsgType)
	}

	// return &bridgev2.MatrixMessageResponse{
	// 	DB: &database.Message{
	// 		ID:        networkid.MessageID(fmt.Sprintf("line-%d", time.Now().UnixNano())),
	// 		SenderID:  makeUserID(string(lc.UserLogin.ID)),
	// 		Timestamp: time.Now(),
	// 	},
	// }, nil
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
