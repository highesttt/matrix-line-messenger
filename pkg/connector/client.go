package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/highesttt/mautrix-line-messenger/pkg/e2ee"
	"github.com/highesttt/mautrix-line-messenger/pkg/line"
	"github.com/rs/zerolog"
	"go.mau.fi/util/ptr"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/simplevent"
	"maunium.net/go/mautrix/bridgev2/status"
	"maunium.net/go/mautrix/event"
)

type LineClient struct {
	UserLogin   *bridgev2.UserLogin
	AccessToken string
	Mid         string
	HTTPClient  *http.Client
	E2EE        *e2ee.Manager
	peerKeys    map[string]peerKeyInfo

	reqSeqMu    sync.Mutex
	sentReqSeqs map[int]time.Time
}

var _ bridgev2.NetworkAPI = (*LineClient)(nil)

func (lc *LineClient) Connect(ctx context.Context) {
	if lc.peerKeys == nil {
		lc.peerKeys = make(map[string]peerKeyInfo)
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
		if ei3, err := client.GetEncryptedIdentityV3(); err == nil {
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

	go lc.pollLoop(ctx)
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

func (lc *LineClient) handleOperation(_ context.Context, op line.Operation) {
	// Type 25 = SEND_MESSAGE (Message sent by you from another device)
	// Type 26 = RECEIVE_MESSAGE (Message received from another user)

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
			if pt, err := lc.E2EE.DecryptMessageV2(msg); err == nil && pt != "" {
				bodyText = pt
			} else {
				lc.ensurePeerKeyForMessage(context.Background(), msg)
				if ptRetry, errRetry := lc.E2EE.DecryptMessageV2(msg); errRetry == nil && ptRetry != "" {
					bodyText = ptRetry
				}
			}
		}
	}

	// unwrap JSON payloaad
	if strings.HasPrefix(bodyText, "{") {
		var wrapper map[string]any
		if err := json.Unmarshal([]byte(bodyText), &wrapper); err == nil {
			if t, ok := wrapper["text"].(string); ok {
				bodyText = t
			}
		}
	}

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
	if _, ok := lc.peerKeys[msg.From]; ok {
		return
	}
	if _, _, err := lc.ensurePeerKey(ctx, msg.From); err != nil {
		lc.UserLogin.Bridge.Log.Warn().Err(err).Str("peer", msg.From).Msg("Failed to fetch peer key for decrypt")
	}
}

func (lc *LineClient) HandleMatrixMessage(ctx context.Context, msg *bridgev2.MatrixMessage) (*bridgev2.MatrixMessageResponse, error) {
	if lc.E2EE == nil {
		return nil, fmt.Errorf("E2EE not initialized; cannot send")
	}

	if msg.Content.MsgType != event.MsgText {
		return nil, fmt.Errorf("only text messages are implemented")
	}

	portalMid := string(msg.Portal.ID)
	client := line.NewClient(lc.AccessToken)
	myRaw, myKeyID, err := lc.E2EE.MyKeyIDs()
	if err != nil {
		return nil, fmt.Errorf("missing own E2EE key: %w", err)
	}

	peerRaw, peerPub, err := lc.ensurePeerKey(ctx, portalMid)
	if err != nil {
		return nil, fmt.Errorf("failed to get peer key: %w", err)
	}

	fromMid := lc.midOrFallback()
	chunks, err := lc.E2EE.EncryptMessageV2(portalMid, fromMid, myKeyID, peerPub, myRaw, peerRaw, 0, msg.Content.Body)
	if err != nil {
		return nil, fmt.Errorf("encrypt failed: %w", err)
	}

	now := time.Now().UnixMilli()
	lineMsg := &line.Message{
		ID:          fmt.Sprintf("local-%d", now),
		From:        lc.midOrFallback(),
		To:          portalMid,
		ToType:      guessToType(portalMid),
		SessionID:   0,
		CreatedTime: json.Number(strconv.FormatInt(now, 10)),
		ContentType: 0,
		HasContent:  false,
		ContentMetadata: map[string]string{
			"e2eeVersion": "2",
		},
		Chunks: chunks,
	}

	reqSeq := int(now % 1_000_000_000)
	lc.reqSeqMu.Lock()
	if lc.sentReqSeqs == nil {
		lc.sentReqSeqs = make(map[int]time.Time)
	}
	lc.sentReqSeqs[reqSeq] = time.Now()
	lc.reqSeqMu.Unlock()

	if err := client.SendMessage(int64(reqSeq), lineMsg); err != nil {
		return nil, err
	}

	return &bridgev2.MatrixMessageResponse{
		DB: &database.Message{
			ID:        networkid.MessageID(lineMsg.ID),
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
