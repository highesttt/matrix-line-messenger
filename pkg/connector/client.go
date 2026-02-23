package connector

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/status"

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

type peerKeyInfo struct {
	raw int
	pub string
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
	go lc.prefetchMessages(ctx)
	go lc.pollLoop(ctx)
}

func (lc *LineClient) Disconnect() {}

func (lc *LineClient) IsLoggedIn() bool { return lc.AccessToken != "" }

func (lc *LineClient) LogoutRemote(ctx context.Context) {}

func (lc *LineClient) midOrFallback() string {
	if lc.Mid != "" {
		return lc.Mid
	}
	return string(lc.UserLogin.ID)
}

func makeUserID(userID string) networkid.UserID { return networkid.UserID(userID) }

func makePortalID(userID string) networkid.PortalID { return networkid.PortalID(userID) }

func guessToType(mid string) ToType {
	if strings.HasPrefix(strings.ToLower(mid), "c") {
		return ToGroup
	}
	if strings.HasPrefix(strings.ToLower(mid), "r") {
		return ToRoom
	}
	return ToUser
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
